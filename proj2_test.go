package main // Might need to change package to proj2 to pass auto grader

//package proj2

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	_ "github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

// This is a private test that only works with out implementation.
// It tests the symmetric encryption function that handles padding
// and implements a parallelized decryption
//
// Requires the import of Bytes package.
func TestSymEncDec(t *testing.T) {
	userlib.DebugPrint = false
	for _, i := range []int{-4, -1, 0, 1, 5} {
		userlib.DebugMsg("i = %d", i)
		IV := userlib.RandomBytes(userlib.AESBlockSize)
		key := userlib.RandomBytes(userlib.AESBlockSize)
		msg := userlib.RandomBytes(userlib.AESBlockSize*10 + i)
		userlib.DebugMsg("IV: %x", IV)
		userlib.DebugMsg("Msg: %x", msg)

		enc_list_ptr, _ := symEncrypt(&key, &IV, &msg)
		userlib.DebugMsg("Enc List: %x", *enc_list_ptr)

		//if !bytes.Equal((*enc_list_ptr)[0], IV) {
		//	userlib.DebugMsg("IV is not first element of enc list")
		//	t.Error("Failed to encrypt and decrypt", msg)
		//}

		dec_list, _ := symDecrypt(&key, enc_list_ptr)
		userlib.DebugMsg("Dec List: %x", *dec_list)
		//if bytes.Equal(msg, *dec_list) {
		//	userlib.DebugMsg("Msg and Dec equal")
		//} else {
		//	userlib.DebugMsg("Msg and Dec NOT EQUAL!!!!")
		//	t.Error("Failed to encrypt and decrypt", msg)
		//}
		userlib.DebugMsg("\n")
	}
}

// This is a private test that only works with out implementation.
// It tests the wrapper for things being stored on the Datastore.
func TestWrapper(t *testing.T) {
	userlib.DebugPrint = false
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	key := userlib.RandomBytes(userlib.AESBlockSize)
	msg := userlib.RandomBytes(userlib.AESBlockSize * 10000000)
	enc_list_ptr, _ := symEncrypt(&key, &IV, &msg)
	wrap_ptr, err := wrap(&key, enc_list_ptr)
	if err != nil {
		userlib.DebugMsg("%v", err)
		t.Error("Failed to wrap")
	}
	//wrap_ptr.cyphers[1][0] = wrap_ptr.cyphers[1][8] // Uncomment to for a fail check.
	//wrap_ptr.hmacs[0] = wrap_ptr.hmacs[8] // Uncomment to for a fail check.
	unwrap_enc_list_ptr, err := unwrap(&key, wrap_ptr)
	if err != nil {
		userlib.DebugMsg("%v", err)
		t.Error("Failed to unwrap")
		return
	}
	userlib.DebugMsg("Enc List: %x", *enc_list_ptr)
	userlib.DebugMsg("Unwrapped Enc List: %x", *unwrap_enc_list_ptr)
}

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
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
