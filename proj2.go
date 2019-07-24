package main // Might need to change package to proj2 to pass auto grader

//package proj2

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	_ "strconv"
)

// Simple helper function to convert byte slices to UUIDs
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

/**
This function symmetrically encrypts a byte slice and handles the necessary padding.

It takes:
	- A decryption/encryption key byte slice.
	- A IV byte slice. (size has to be equal to userlib.AESBlockSize)
	- A byte slice to be encrypted.
It returns:
	- A slice of byte slice cypher texts s.t. the first element is the IV byte slice.
	- A nil error if successful.
*/
func symmetricEnc(key *[]byte, iv *[]byte, data *[]byte) (cyphers *[][]byte, err error) {
	padCount := userlib.AESBlockSize - (len(*data) % userlib.AESBlockSize)
	if padCount == 0 {
		err = errors.New("padding error during symmetric encryption")
		return
	}
	pad := make([]byte, padCount)
	pad[0] = 1

	encSlice := userlib.SymEnc(*key, *iv, append(*data, pad...))

	cyphersCount := len(encSlice) / userlib.AESBlockSize
	cyphersSlice := make([][]byte, cyphersCount)
	for i := 0; i < cyphersCount; i++ {
		cyphersSlice[i] = encSlice[i*userlib.AESBlockSize : (i+1)*userlib.AESBlockSize]
	}

	cyphers = &cyphersSlice
	return
}

/**
This function symmetrically decrypts slice of byte slice cypher texts and removes the padding.

It takes:
	- A decryption/encryption key byte slice.
	- A slice of byte slice cypher texts s.t. the first element is the IV byte slice.
It returns:
	- A byte slice of the unencrypted data
	- A nil error if successful.
*/
func symmetricDec(key *[]byte, cyphers *[][]byte) (data *[]byte, err error) {
	var cypher []byte
	for _, c := range *cyphers {
		cypher = append(cypher, c...)
	}

	decSlice := userlib.SymDec(*key, cypher)

	var padStart uint
	for padStart = uint(len(decSlice) - 1); padStart >= 0; padStart-- {
		if decSlice[padStart] == 1 {
			break
		}
	}
	decSlice = decSlice[:padStart]

	data = &decSlice
	return
}

// The structure definition for storing things on the Datastore.
type Wrap struct {
	Cyphers [][]byte
	Hmac    []byte
}

/**
This is the main Wrap function that is used to ensure integrity of a slice of
cypher text (C0 .. Cn) when it is stored on the Datastore.

It takes:
	- A HMAC key byte slice.
	- A slice of byte slice cypher texts s.t. the first element is the IV byte slice.
It returns:
	- A 'Wrap' struct following the format described in the design doc.
	- A nil error if successful.
*/
func wrap(key *[]byte, cyphers *[][]byte) (wrap *Wrap, err error) {
	wrap = &Wrap{*cyphers, make([]byte, len(*cyphers))}
	var datHMAC []byte
	for i := range wrap.Cyphers {
		datHMAC = append(datHMAC, wrap.Cyphers[i]...)
	}

	wrap.Hmac, err = userlib.HMACEval(*key, datHMAC)
	return
}

/**
This is the main unwrapping function to read encrypted cypher text from the Datastore
and check for integrity.

It takes:
	- A HMAC key byte slice.
	- A 'Wrap' struct following the format described in the design doc.
It returns:
	- A slice of byte slice cypher texts s.t. the first element is the IV byte slice.
	- A nil error if successful.
*/
func unwrap(key *[]byte, wrap *Wrap) (cyphers *[][]byte, err error) {
	var datHMAC []byte
	for i := range wrap.Cyphers {
		datHMAC = append(datHMAC, wrap.Cyphers[i]...)
	}

	currHMAC, err := userlib.HMACEval(*key, datHMAC)
	if !userlib.HMACEqual(wrap.Hmac, currHMAC) {
		err = errors.New("failed to unwrap")
	} else {
		cyphers = &wrap.Cyphers // Don't return cyphers if hmac is not correct.
	}
	return
}

// The structure definition for a user record
type User struct {
	Username      string
	UPH           []byte
	UUID          uuid.UUID
	PrivateDecKey userlib.PKEDecKey
	PrivateSigKey userlib.DSSignKey
	FilesOwned    map[uuid.UUID]bool
	FileUUIDs     map[string]uuid.UUID
	FileKeys      map[uuid.UUID][]byte
}

/**
This is the main function to create a new user. The function assumes that it will
be called only once per unique username.

It takes:
	- Username String.
	- Password String.
It returns:
	- A pointer to the User struct that was created and stored on the Datastore.
	- A nil error if successful.
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Derive necessary info from password and username
	bytesUn := []byte(username)
	bytesPw := []byte(password)
	strongBytesPw := userlib.Argon2Key(bytesPw, bytesUn, uint32(userlib.AESBlockSize))
	UPH, err := userlib.HMACEval(strongBytesPw, bytesUn) // User Password Hash
	if err != nil {
		return
	}
	UUID, err := uuid.FromBytes(UPH[:16])
	if err != nil {
		return
	}

	// Initialize the user's struct
	userdata.Username = username
	userdata.UPH = UPH
	userdata.UUID = UUID
	userdata.FilesOwned = make(map[uuid.UUID]bool)
	userdata.FileUUIDs = make(map[string]uuid.UUID)
	userdata.FileKeys = make(map[uuid.UUID][]byte)

	// Set-up and save the asymmetric keys
	PKenc, PKdec, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	DSsig, DSvfy, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	err = userlib.KeystoreSet("enc_"+userdata.UUID.String(), PKenc)
	if err != nil {
		return
	}
	err = userlib.KeystoreSet("vfy_"+userdata.UUID.String(), DSvfy)
	if err != nil {
		return
	}
	userdata.PrivateDecKey = PKdec
	userdata.PrivateSigKey = DSsig

	// Encrypt, Mac and Save the userdata on the Datastore
	encKey := userlib.Argon2Key(append([]byte("enc_"), UPH...),
		bytesPw, uint32(userlib.AESBlockSize))
	hmacKey := userlib.Argon2Key(append([]byte("mac_"), UPH...),
		bytesPw, uint32(userlib.AESBlockSize))
	byteUserdata, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	encCyphersPtr, err := symmetricEnc(&encKey, &IV, &byteUserdata)
	if err != nil {
		return
	}
	wrappedCyphersPtr, err := wrap(&hmacKey, encCyphersPtr)
	if err != nil {
		return
	}
	wrappedUserdataBytes, err := json.Marshal(*wrappedCyphersPtr)
	if err != nil {
		return
	}
	userlib.DatastoreSet(UUID, wrappedUserdataBytes)

	// Debugging stuff
	userlib.DebugMsg("UUID: %v", UUID)
	userlib.DebugMsg("UPH: %x", UPH)
	userlib.DebugMsg("encKey: %x", encKey)
	userlib.DebugMsg("hmacKey: %x", hmacKey)
	userlib.DebugMsg("wrapperHmac: %x", wrappedCyphersPtr.Hmac)

	return
}

/**
This is the main function to fetch a user from the Datastore.
It returns a non nil error when:
	* user/password is invalid.
	* user data was corrupted.
	* user can't be found.

It takes:
	- Username String.
	- Password String.
It returns:
	- A pointer to the User struct that was stored on the Datastore.
	- A nil error if successful.
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Derive necessary info from password and username
	bytesUn := []byte(username)
	bytesPw := []byte(password)
	strongBytesPw := userlib.Argon2Key(bytesPw, bytesUn, uint32(userlib.AESBlockSize))
	UPH, err := userlib.HMACEval(strongBytesPw, bytesUn) // User Password Hash
	if err != nil {
		return
	}
	UUID, err := uuid.FromBytes(UPH[:16])
	if err != nil {
		return
	}

	// Fetch encrypted data from Datastore
	wrappedUserdataBytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		err = errors.New("username not found or password is not correct")
		return
	}

	// Verify and unencrypt wrapped userdata
	var wrap Wrap
	encKey := userlib.Argon2Key(append([]byte("enc_"), UPH...),
		bytesPw, uint32(userlib.AESBlockSize))
	hmacKey := userlib.Argon2Key(append([]byte("mac_"), UPH...),
		bytesPw, uint32(userlib.AESBlockSize))
	err = json.Unmarshal(wrappedUserdataBytes, &wrap)
	if err != nil {
		return
	}
	userdataCyphersPtr, err := unwrap(&hmacKey, &wrap)
	if err != nil {
		return
	}
	byteUserdataPtr, err := symmetricDec(&encKey, userdataCyphersPtr)
	if err != nil {
		return
	}
	err = json.Unmarshal(*byteUserdataPtr, userdataptr)
	if err != nil {
		return
	}

	// Debugging stuff
	userlib.DebugMsg("UUID: %v", UUID)
	userlib.DebugMsg("loaded UUID: %v", userdata.UUID)
	userlib.DebugMsg("UPH: %x", UPH)
	userlib.DebugMsg("loaded UPH: %x", userdata.UPH)
	userlib.DebugMsg("encKey: %x", encKey)
	userlib.DebugMsg("hmacKey: %x", hmacKey)
	userlib.DebugMsg("wrapperHmac: %x", wrap.Hmac)

	return
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
