package gopass_test

import (
	"os"
	"path/filepath"
	"testing"

	"reflect"

	"sort"

	"io/ioutil"

	"github.com/danteclay/gopass"
	"golang.org/x/crypto/openpgp"
)

func TestList(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(wd, "testdata")
	keyring, err := os.Open(filepath.Join(prefix, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	safe, err := gopass.Open(prefix, keyring)
	if err != nil {
		t.Fatal(err)
	}
	result, err := safe.List()
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"good.gpg", "hello.gpg"}
	sort.Strings(expected)
	if !reflect.DeepEqual(result, expected) {
		t.Error("Expected: ", expected, "   Got: ", result)
	}
}

func TestRead(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(wd, "testdata")
	keyring, err := os.Open(filepath.Join(prefix, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	safe, err := gopass.Open(prefix, keyring)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("testing")
	r, err := safe.Read("hello.gpg", password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello\n" {
		t.Error("Expected: hello\n Got:", string(b))
	}
}

func TestWrite(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(wd, "testdata")
	keyring, err := os.Open(filepath.Join(prefix, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	safe, err := gopass.Open(prefix, keyring)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := safe.Write("good.gpg")
	if err != nil {
		t.Error(err)
	}
	defer plaintext.Close()
	_, err = plaintext.Write([]byte("good\n"))
	if err != nil {
		t.Error(err)
	}

}

func TestGPGIds(t *testing.T) {
	ids := gopass.GPGIds("testdata")
	gpg := []string{"testing"}
	if !reflect.DeepEqual(ids, gpg) {
		t.Error("Incorrect gpg ids read")
	}
}

func TestCreate(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	el, err := openpgp.ReadKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}
	_, err = gopass.Create(filepath.Join("testdata", "subtest"), el)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(filepath.Join("testdata", "subtest"))
}
