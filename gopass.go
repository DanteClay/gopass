package gopass

import (
	"io"
	"path/filepath"

	"os"

	"path"

	"sort"

	"bufio"

	"fmt"

	"golang.org/x/crypto/openpgp"
)

// Store represents the password-store
type Store struct {
	p    string
	keys openpgp.EntityList
}

// Open an existing password-store or substore
func Open(path string, keyRing io.Reader) (Store, error) {
	s := Store{p: path}
	el, err := openpgp.ReadKeyRing(keyRing)
	if err != nil {
		return s, err
	}
	ids := GPGIds(path)
	for _, entity := range []*openpgp.Entity(el) {
		for entityid := range entity.Identities {
			if inSlice(ids, entityid) {
				s.keys = append(s.keys, entity)
			}
		}
	}
	return s, err
}

// Create a new password-store or substore, with the given openpgp keys
func Create(path string, el openpgp.EntityList) (Store, error) {
	s := Store{
		p:    path,
		keys: el,
	}
	err := os.Mkdir(path, 0700)
	if err != nil {
		return s, err
	}
	// print each id to
	f, err := os.Create(filepath.Join(path, ".gpg-id"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	for _, entity := range el {
		for id := range entity.Identities {
			fmt.Fprintln(f, id)
		}
	}
	return s, err
}

// List entries in store.
func (s Store) List() ([]string, error) {
	var list []string
	f, err := os.Open(s.p)
	if err != nil {
		return list, err
	}
	names, err := f.Readdirnames(0)
	if err != nil {
		return list, err
	}
	// filter
	for _, name := range names {
		if path.Ext(name) == ".gpg" {
			list = append(list, name)
		}
	}
	sort.Strings(list)
	return list, err
}

// SubStores lists the substores, only goes one level deep.
func (s Store) SubStores() ([]string, error) {
	var list []string
	f, err := os.Open(s.p)
	if err != nil {
		return list, err
	}
	files, err := f.Readdir(0)
	if err != nil {
		return list, err
	}
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(file.Name(), ".gpg-id")); err == nil {
			list = append(list, file.Name())
		}
	}
	return list, err
}

// Write and encrypt entry to password store. Write plaintext to the resulting io.WriteCloser
// Any existing entry will be overwritten.
func (s Store) Write(filename string) (plaintext io.WriteCloser, err error) {
	f, err := os.OpenFile(path.Join(s.p, filename), os.O_CREATE|os.O_WRONLY, 666)
	if err != nil {
		return nil, err
	}
	plaintext, err = openpgp.Encrypt(f, s.keys, nil, nil, nil)
	if err != nil {
		return plaintext, err
	}
	return plaintext, err
}

// Read entity from password store.
func (s Store) Read(filename string, password []byte) (plaintext io.Reader, err error) {
	// Do not Close() it will close the plaintext io.Reader that is returned
	f, err := os.Open(path.Join(s.p, filename))
	if err != nil {
		return plaintext, err
	}
	for _, key := range s.keys {
		key.PrivateKey.Decrypt(password)
		for _, subkey := range key.Subkeys {
			subkey.PrivateKey.Decrypt(password)
		}
	}
	md, err := openpgp.ReadMessage(f, s.keys, nil, nil)
	if err != nil {
		return md.UnverifiedBody, err
	}

	if err != nil {
		return md.UnverifiedBody, err
	}
	return md.UnverifiedBody, err
}

// GPGIds reads the .gpg-id files in a password-store
func GPGIds(p string) []string {
	var ids []string
	f, err := os.Open(path.Join(p, ".gpg-id"))
	if err != nil {
		return ids
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		ids = append(ids, s.Text())
	}
	return ids
}

func inSlice(slice []string, v string) bool {
	for _, b := range slice {
		if b == v {
			return true
		}
	}
	return false
}
