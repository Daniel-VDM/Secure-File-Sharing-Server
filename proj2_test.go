package proj2

import (
	_ "encoding/hex"
	"encoding/json"
	_ "errors"
	_ "github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	"reflect"
	_ "strconv"
	"strings"
	"testing"
)

/**
Real tests that should work for all implementations.
*/

// This assumes that each unique username will only call init once.
func TestInitAndGetBasic(t *testing.T) {
	userlib.SetDebugStatus(false)
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	bob, err := InitUser("bob", "fubar")
	if bob == nil || err != nil {
		t.Error(err)
		return
	}
	getBob, err := GetUser("bob", "fubar")
	if getBob == nil || err != nil {
		t.Error(err)
		return
	}

	bobBytes, _ := json.Marshal(bob)
	getBobBytes, _ := json.Marshal(getBob)
	if !reflect.DeepEqual(bobBytes, getBobBytes) {
		t.Error("Init and Get userdata are not the same.")
		return
	}

	_, err = GetUser("bob", "wrong")
	if err == nil {
		t.Error("Got a user that is suppose to not exist.")
		return
	}

	_, err = GetUser("wrong", "fubar")
	if err == nil {
		t.Error("Got a user that is suppose to not exist.")
		return
	}

	var keys []userlib.UUID
	var vals [][]byte
	for k, v := range datastore {
		keys = append(keys, k)
		vals = append(vals, v)
	}

	for val := range vals {
		if strings.Contains("bob", string(val)) || strings.Contains("alice", string(val)) {
			t.Error("Username is not obscured.")
			return
		}
	}

}

// This assumes that each unique username will only call init once.
func TestInitAndGetCorruptDatastore(t *testing.T) {
	userlib.SetDebugStatus(false)
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	_, err := InitUser("bob", "fubar")
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
		t.Error("Datastore was corrupted for bob but still got user.")
		return
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()

	_, err = InitUser("bob", "fubar")
	if err != nil {
		t.Error(err)
		return
	}
	userlib.DatastoreClear()
	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Datastore was corrupted for bob but still got user.")
		return
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore = userlib.DatastoreGetMap()

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

	var keys1 []userlib.UUID
	var vals1 [][]byte
	for k, v := range datastore {
		keys1 = append(keys1, k)
		vals1 = append(vals1, v)
	}
	datastore[keys1[0]] = userlib.RandomBytes(len(keys1[0]))

	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Datastore was corrupted for bob but still got user.")
		return
	}
	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error(err)
		return
	}

	// TODO: more tests to check that stuff is actually encrypted and check PW diffs.
	// TODO: Check for username differences,
	// TODO: check or basic UUID/Hash check in dict.
}

func TestStorage(t *testing.T) {
	userlib.SetDebugStatus(true)
	fileNames := []string{"f1", "f2", "f3", "f4", "f5"}
	userNames := []string{"u1", "u2", "u3", "u4", "u5"}

	/**
	Basic functionality test with basic edge cases.
	*/
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	for i, offset := range []int{-4, -1, 0, 1, 7} {
		user, err1 := InitUser(userNames[i], "fubar")
		if err1 != nil {
			t.Error(err1)
			return
		}

		file := userlib.RandomBytes(userlib.AESBlockSize - offset)
		user.StoreFile(fileNames[i], file)

		// Get user to check for userdata update.
		user, err2 := GetUser(userNames[i], "fubar")
		if err2 != nil {
			t.Error(err2)
			return
		}

		loadedFile, err3 := user.LoadFile(fileNames[i])
		if err3 != nil {
			t.Error("Failed to upload and download", err3)
			return
		}
		if !reflect.DeepEqual(file, loadedFile) {
			t.Error("Loaded file is not the same original\n",
				file, loadedFile)
			return
		}
	}

	// Test the file overwrite case in our implementation.
	file := userlib.RandomBytes(userlib.AESBlockSize - 7)
	user, err2 := GetUser(userNames[4], "fubar")
	user.StoreFile(fileNames[4], file)
	if err2 != nil {
		t.Error(err2)
		return
	}
	loadedFile, err3 := user.LoadFile(fileNames[4])
	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}
	if !reflect.DeepEqual(file, loadedFile) {
		t.Log("StoreFile overwrite failed. This is acceptable.")
		// Some implementations don't implement overwrite so this is not a fail.
	}

	/**
	Basic append test with basic edge cases.
	*/
	for i, offset1 := range []int{-4, -1, 0, 1, 7} {
		for _, offset2 := range []int{-4, -1, 0, 1, 7} {
			userlib.DatastoreClear()
			userlib.KeystoreClear()

			user, err0 := InitUser(userNames[i], "fubar")
			if err0 != nil {
				t.Error(err0)
				return
			}

			file := userlib.RandomBytes(userlib.AESBlockSize - offset1)
			toAppend := userlib.RandomBytes(userlib.AESBlockSize - offset2)

			user.StoreFile(fileNames[i], file)
			err1 := user.AppendFile(fileNames[i], toAppend)
			if err1 != nil {
				t.Error(err1)
				return
			}

			// Get user to check for userdata update.
			user, err2 := GetUser(userNames[i], "fubar")
			if err2 != nil {
				t.Error(err2)
				return
			}

			loadedFile, err3 := user.LoadFile(fileNames[i])
			if err3 != nil {
				t.Error(err3)
				return
			}
			refAppend := append(file, toAppend...)
			if !reflect.DeepEqual(refAppend, loadedFile) {
				t.Error("Loaded (appended) file is not the same as reference\n",
					refAppend, "\n", loadedFile)
				return
			}
		}
	}

	/**
	Basic append test with multiple files.
	*/
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore = userlib.DatastoreGetMap()
	keystore = userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	for i, offset1 := range []int{-4, -1, 0, 1, 7} {
		user, err0 := InitUser(userNames[i], "fubar")
		if err0 != nil {
			t.Error(err0)
			return
		}

		file := userlib.RandomBytes(userlib.AESBlockSize - offset1)
		toAppend := userlib.RandomBytes(userlib.AESBlockSize)

		user.StoreFile(fileNames[i], file)
		err1 := user.AppendFile(fileNames[i], toAppend)
		if err1 != nil {
			t.Error(err1)
			return
		}

		// Get user to check for userdata update.
		user, err2 := GetUser(userNames[i], "fubar")
		if err2 != nil {
			t.Error(err2)
			return
		}

		loadedFile, err3 := user.LoadFile(fileNames[i])
		if err3 != nil {
			t.Error(err3)
			return
		}
		refAppend := append(file, toAppend...)
		if !reflect.DeepEqual(refAppend, loadedFile) {
			t.Error("Loaded (appended) file is not the same as reference\n",
				refAppend, "\n", loadedFile)
			return
		}
	}

	// TODO: Tests for nil data on file loads that have wrong file name
	// overall, consider the cases where the data is the things that throws an error.
	// TODO: tests for testing if its global vars.
	// TODO: Stress test to check for the 'efficient' part.
	// TODO: More tests to check for the corruption case.
	// TODO: Write SHARING TESTS that tests for file overwrite AND file appends.

}

func TestShare(t *testing.T) {
	userlib.SetDebugStatus(true)
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	file := userlib.RandomBytes(userlib.AESBlockSize)
	u.StoreFile("file1", file)

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

	// TODO: A LOT MORE SHARE TESTS AS THERE ARE A LOT OF EDGE CASES.
}
