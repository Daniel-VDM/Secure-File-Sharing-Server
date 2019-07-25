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

//###################
//## Private Tests ##
//###################

// This is a private test that only works with out implementation.
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

// This is a private test that only works with our implementation.
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

//################
//## Real Tests ##
//################

// This assumes that each unique username will only call init once.
// TODO: refactor to make this readable.
func TestInitAndGet(t *testing.T) {
	// MAKE SURE TO CLEAR STORES FOR EACH TEST
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	userlib.SetDebugStatus(false)
	datastore := userlib.DatastoreGetMap()
	_ = datastore

	u2, err := InitUser("bob", "fubar")
	_ = u2

	// Basic init and get test
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error(err)
		return
	} else if len(datastore) == 0 {
		t.Error("Datastore is empty when there should be 1 element.")
		return
	}
	userlib.DebugMsg("\n")

	bad, _ := userlib.DatastoreGet(u2.UUID)
	userlib.DatastoreSet(u.UUID, bad)

	ug, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("Datastore was corrupted for alice but still got user.")
		return
	} else if len(datastore) == 0 {
		t.Error("Datastore is empty when there should be 1 element.")
		return
	}

	ug, err = GetUser("bob", "fubar")
	if err != nil {
		t.Error(err)
		return
	} else if len(datastore) == 0 {
		t.Error("Datastore is empty when there should be 1 element.")
		return
	}

	// Make sure the Init struct equal the fetch struct for the same user
	uBytes, _ := json.Marshal(u2)
	ugBytes, _ := json.Marshal(ug)
	for i := range uBytes {
		if uBytes[i] != ugBytes[i] {
			t.Error("Saved and fetched user doesn't match")
			return
		}
	}
}

func TestStorage(t *testing.T) {
	// MAKE SURE TO CLEAR STORES FOR EACH TEST
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	userlib.SetDebugStatus(false)
	datastore := userlib.DatastoreGetMap()
	_ = datastore

	fileNames := []string{"f1", "f2", "f3", "f4", "f5"}
	userNames := []string{"u1", "u2", "u3", "u4", "u5"}

	// Test saving and loading files with edge case block sizes
	// Also implicitly checks loading and saving multiple files & users without reset.
	for i, offset := range []int{-4, -1, 0, 1, 5} {
		user, err := InitUser(userNames[i], "fubar")
		if err != nil {
			t.Error(err)
			return
		}

		file := userlib.RandomBytes(userlib.AESBlockSize*7 - offset)

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
