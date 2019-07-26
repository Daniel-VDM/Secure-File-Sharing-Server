package main // Might need to change package to proj2 to pass auto grader

//package proj2

import (
	_ "encoding/hex"
	"encoding/json"
	_ "errors"
	_ "github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

/**
Real tests that should work for all implementations.
*/

// This assumes that each unique username will only call init once.
func TestInitAndGet(t *testing.T) {
	userlib.SetDebugStatus(false)

	/**
	Basic init and get user test.
	*/
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error(err)
		return
	}
	getBob, err := GetUser("bob", "fubar")
	if err != nil {
		t.Error(err)
		return
	}

	bobBytes, _ := json.Marshal(bob)
	getBobBytes, _ := json.Marshal(getBob)
	if !reflect.DeepEqual(bobBytes, getBobBytes) {
		t.Error("Init and Get userdata are not the same.")
		return
	}

	/**
	Corrupted datastore test.
	*/
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore = userlib.DatastoreGetMap()
	keystore = userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = InitUser("alice", "fubar")
	if err != nil {
		t.Error(err)
		return
	}

	var keys []userlib.UUID
	var vals [][]byte
	for k, v := range datastore {
		keys = append(keys, k)
		vals = append(vals, v)
	}
	userlib.DatastoreSet(keys[0], vals[1])
	for i := 1; i < len(keys); i++ {
		userlib.DatastoreSet(keys[i], vals[0])
	}

	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("Datastore was corrupted for alice but still got user.")
		return
	}
	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Datastore was corrupted for alice but still got user.")
		return
	}

	// TODO: more tests to check that stuff is actually encrypted and check PW diffs.
}

func TestStorage(t *testing.T) {
	userlib.SetDebugStatus(true)

	/**
	Basic functionality test with edge cases.
	*/
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	fileNames := []string{"f1", "f2", "f3", "f4", "f5"}
	userNames := []string{"u1", "u2", "u3", "u4", "u5"}
	for i, offset := range []int{-4, -1, 0, 1, 8} {
		user, err := InitUser(userNames[i], "fubar")
		if err != nil {
			t.Error(err)
			return
		}
		file := userlib.RandomBytes(userlib.AESBlockSize*13 - offset)
		user.StoreFile(fileNames[i], file)
		// Get user to check for userdata update.
		user, err = GetUser(userNames[i], "fubar")
		loadedFile, err2 := user.LoadFile(fileNames[i])
		if err2 != nil {
			t.Error("Failed to upload and download", err2)
			return
		}
		if !reflect.DeepEqual(file, loadedFile) {
			t.Error("Downloaded file is not the same", file, loadedFile)
			return
		}
	}

	// TODO: More tests to check for the corruption case.
	// TODO: More tests to check the append function (and respective corruption).
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

/**
Private tests that only work for our implementation.
*/

// It tests the symmetric encryption function that handles padding
// and implements a parallelized decryption
func TestSymEncDec(t *testing.T) {
	userlib.DebugPrint = false
	for _, i := range []int{-4, -1, 0, 1, 5} {
		userlib.DebugMsg("i = %d", i)
		IV := userlib.RandomBytes(userlib.AESBlockSize)
		key := userlib.RandomBytes(userlib.AESBlockSize)
		msg := userlib.RandomBytes(userlib.AESBlockSize*10 + i)
		userlib.DebugMsg("IV: %x", IV)
		userlib.DebugMsg("Msg: %x", msg)

		enc_list_ptr, _ := SymmetricEnc(&key, &IV, &msg)
		userlib.DebugMsg("Enc List: %x", *enc_list_ptr)

		dec_list, _ := SymmetricDec(&key, enc_list_ptr)
		userlib.DebugMsg("Dec List: %x", *dec_list)

		for i := range *dec_list {
			if (*dec_list)[i] != msg[i] {
				t.Error("Encrypted msg doesnt match decrypted msg")
			}
		}

		userlib.DebugMsg("\n")
	}
}

// It tests the Wrap for things being stored on the Datastore.
func TestWrapper(t *testing.T) {
	userlib.DebugPrint = false
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	key := userlib.RandomBytes(userlib.AESBlockSize)
	msg := userlib.RandomBytes(userlib.AESBlockSize * 10000000)
	enc_list_ptr, _ := SymmetricEnc(&key, &IV, &msg)
	wrap_ptr, err := Wrapper(&key, enc_list_ptr)
	if err != nil {
		userlib.DebugMsg("%v", err)
		t.Error("Failed to Wrapper")
	}
	//wrap_ptr.Cyphers[1][0] = wrap_ptr.Cyphers[1][8] // Uncomment to for a fail check.
	//wrap_ptr.Hmac[0] = wrap_ptr.Hmac[8] // Uncomment to for a fail check.
	unwrap_enc_list_ptr, err := Unwrapper(&key, wrap_ptr)
	if err != nil {
		userlib.DebugMsg("%v", err)
		t.Error("Failed to Unwrapper")
		return
	}
	userlib.DebugMsg("Enc List: %x", *enc_list_ptr)
	userlib.DebugMsg("Unwrapped Enc List: %x", *unwrap_enc_list_ptr)
}
