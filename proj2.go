package main // Might need to change package to proj2 to pass auto grader

//package proj2

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	_ "strconv"
	_ "strings"
)

/**
Struct Defs:
*/

// The structure definition for a user record
type User struct {
	Username      string
	UPH           []byte
	symEncKey     []byte
	hmacKey       []byte
	PrivateDecKey userlib.PKEDecKey
	PrivateSigKey userlib.DSSignKey
	FilesOwned    map[uuid.UUID]bool
	FileUUIDs     map[string]uuid.UUID
	FileKeys      map[uuid.UUID][]byte
}

// The structure definition for storing things on the Datastore.
type Wrap struct {
	Cyphers [][]byte
	Hmac    []byte
}

// The structure definition for a file's metadata
type FileMetadata struct {
	CypherUUIDs []uuid.UUID
}

// TODO wrapper save method & get FUNCTION    (Have save method  & function only take UUIDs)
// TODO FileMetadata save method   (Have save method UUIDs and 2 Keys) - Needs to be encrypted btw

/**
Helper Functions:
*/

// Simple helper function to convert byte slices to UUIDs
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// Simple helper to generate a random UUID that is NOT a key in the Datastore
func GenRandUUID() (UUID uuid.UUID) {
	for {
		UUID = uuid.New()
		_, ok := userlib.DatastoreGet(UUID)
		if !ok {
			return
		}
	}
}

/**
This function symmetrically encrypts a byte slice and handles the necessary padding.

It takes:
	- A pointer to a decryption/encryption key byte slice.
	- A pointer to a IV byte slice. (size has to be equal to userlib.AESBlockSize)
	- A pointer to a byte slice to be encrypted.
It returns:
	- A pointer to a slice of byte slice cypher texts s.t. the first
      element is the IV byte slice.
	- A nil error if successful.
*/
func SymmetricEnc(key *[]byte, iv *[]byte, data *[]byte) (cyphers *[][]byte, err error) {
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
	- A pointer to a decryption/encryption key byte slice.
	- A pointer to a slice of byte slice cypher texts s.t. the first element is the IV byte slice.
It returns:
	- A pointer to a byte slice of the unencrypted data
	- A nil error if successful.
*/
func SymmetricDec(key *[]byte, cyphers *[][]byte) (data *[]byte, err error) {
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

/**
This is the main Wrap function that is used to ensure integrity of a slice of
cypher text (C0 .. Cn) when it is stored on the Datastore.

It takes:
	- A pointer HMAC key byte slice.
	- A pointer to a slice of byte slice cypher texts s.t. the first
      element is the IV byte slice.
It returns:
	- A pointer to a Wrap struct following the format described in the design doc.
	- A nil error if successful.
*/
func Wrapper(key *[]byte, cyphers *[][]byte) (wrap *Wrap, err error) {
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
	- A pointer to a HMAC key byte slice.
	- A pointer to a Wrap struct following the format described in the design doc.
It returns:
	- A pointer to a slice of byte slice cypher texts s.t. the first
      element is the IV byte slice.
	- A nil error if successful.
*/
func Unwrapper(key *[]byte, wrap *Wrap) (cyphers *[][]byte, err error) {
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

/**
This is a helper function for the Init and Get user functions.
It derives the keys, hashes and UUID for a user given their username and password
and saves it to the userdata User struct.

It takes:
	- A pointer to username String.
	- A pointer to password String.
    - A pointer to the userdata User struct.
It returns:
	- A nil error if successful.
*/
func DeriveAndSaveUserAttributes(username *string, password *string, userdata *User) (err error) {
	bUsername := []byte(*username)
	bPassword := []byte(*password)

	userdata.UPH = userlib.Argon2Key(bPassword, bUsername, 32) // User Password Hash
	userdata.symEncKey = userlib.Argon2Key(append([]byte("enc_"), userdata.UPH...),
		bPassword, uint32(userlib.AESKeySize))
	userdata.hmacKey = userlib.Argon2Key(append([]byte("mac_"), userdata.UPH...),
		bPassword, uint32(userlib.AESKeySize))

	return
}

/**
This is a helper function to get, validate and unencrypt a file's metadata

It takes:
	- A pointer to a file's metadata UUID
	- A pointer to a file's hmac key
	- A pointer to a file's encryption key
It returns:
	- A pointer to the file's metadata struct
	- A nil error if successful
*/
func GetFileMetadata(fileUUID *uuid.UUID, fileHmacKey *[]byte, fileEncKey *[]byte) (metadata *FileMetadata, err error) {
	var metadataWrap Wrap
	wrappedMetadataBytes, ok := userlib.DatastoreGet(*fileUUID)
	if !ok {
		err = errors.New("file's metadata not found on Datastore")
		return
	}
	err = json.Unmarshal(wrappedMetadataBytes, &metadataWrap)
	if err != nil {
		return
	}
	metadataCypherBytesPtr, err := Unwrapper(fileHmacKey, &metadataWrap)
	if err != nil {
		return
	}
	metadataBytesPtr, err := SymmetricDec(fileEncKey, metadataCypherBytesPtr)
	if err != nil {
		return
	}
	err = json.Unmarshal(*metadataBytesPtr, &metadata)
	if err != nil {
		return
	}
	return
}

// TODO Metadata methods here...

/**
User Init and Get:
*/

/**
This is the main function that creates a new user and saves them to the Datastore.
This function assumes that it will be called only once per unique username.

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

	err = DeriveAndSaveUserAttributes(&username, &password, &userdata)
	if err != nil {
		return
	}
	rehashedUPH, err := userlib.HMACEval(userdata.UPH, []byte(username))
	if err != nil {
		return
	}
	UUID, err := uuid.FromBytes(rehashedUPH[:16])
	if err != nil {
		return
	}

	// Initialize the rest of the userdata.
	userdata.Username = username
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
	err = userlib.KeystoreSet("enc_"+username, PKenc)
	if err != nil {
		return
	}
	err = userlib.KeystoreSet("vfy_"+username, DSvfy)
	if err != nil {
		return
	}
	userdata.PrivateDecKey = PKdec
	userdata.PrivateSigKey = DSsig

	err = userdata.SaveUser(UUID)
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

	err = DeriveAndSaveUserAttributes(&username, &password, &userdata)
	if err != nil {
		return
	}
	rehashedUPH, err := userlib.HMACEval(userdata.UPH, []byte(username))
	if err != nil {
		return
	}
	UUID, err := uuid.FromBytes(rehashedUPH[:16])
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
	err = json.Unmarshal(wrappedUserdataBytes, &wrap)
	if err != nil {
		return
	}
	userdataCyphersPtr, err := Unwrapper(&userdata.hmacKey, &wrap)
	if err != nil {
		return
	}
	byteUserdataPtr, err := SymmetricDec(&userdata.symEncKey, userdataCyphersPtr)
	if err != nil {
		return
	}
	err = json.Unmarshal(*byteUserdataPtr, &userdata) // overwrite the userdata being used.
	if err != nil {
		return
	}

	userdataptr = &userdata
	return
}

/**
User Methods:
*/

/**
This is a helper method to save a User struct to the Datastore.

It takes:
	- A  pointer to the User struct to be saved (contains all the info needed).
It returns:
	- A nil error if successful.
*/
func (userdata *User) SaveUser(UUID uuid.UUID) (err error) {
	byteUserdata, err := json.Marshal(userdata)
	if err != nil || len(byteUserdata) <= 2 {
		err = errors.New("userdata marshal failed")
		return
	}
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	encCyphersPtr, err := SymmetricEnc(&userdata.symEncKey, &IV, &byteUserdata)
	if err != nil {
		return
	}
	wrappedCyphersPtr, err := Wrapper(&userdata.hmacKey, encCyphersPtr)
	if err != nil {
		return
	}
	wrappedUserdataBytes, err := json.Marshal(*wrappedCyphersPtr)
	if err != nil || len(wrappedUserdataBytes) <= 2 {
		err = errors.New("wrapped userdata marshal failed")
		return
	}
	userlib.DatastoreSet(UUID, wrappedUserdataBytes)
	return
}

/**
This method stores a file in the datastore and does not reveal the filename to the Datastore.
Note that only a user (i.e: a User struct) can call this method.

Note that storing a file under a name that already exists for this user is undefined behavior.
But this implementation attempts to remove the underlying file.

It takes:
	- A filename string = the name of the file for THIS particular user.
	- The byte slice of the file.
*/
func (userdata *User) StoreFile(filename string, data []byte) {
	// Generate file keys and UUIDs
	fileUUID := GenRandUUID()
	fileUUIDBytes, err := fileUUID.MarshalBinary()
	if err != nil {
		panic("file UUID binary marshal failed.")
	}
	fileEncKey := userlib.RandomBytes(userlib.AESKeySize)
	fileHmacKey, err := userlib.HMACEval(fileEncKey, fileUUIDBytes)
	if err != nil {
		panic("file hmac failed.")
	}
	fileHmacKey = fileHmacKey[:userlib.AESKeySize]

	// Attempt to delete the filename's underlying file if it is present. (Might have to remove this)
	_, ok := userdata.FileUUIDs[filename]
	if ok {
		_ = userdata.DeleteFile(filename) // It's ok if it fails.
	}

	// Encrypting file data
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	var metadata FileMetadata
	encCyphersPtr, err := SymmetricEnc(&fileEncKey, &IV, &data)
	if err != nil {
		panic("file store encryption failed.")
	}
	// Wrap and store each cypher on the Datastore
	metadata.CypherUUIDs = make([]uuid.UUID, len(*encCyphersPtr)-1)
	for i := range metadata.CypherUUIDs {
		metadata.CypherUUIDs[i] = GenRandUUID()
		tempCyphers := [][]byte{(*encCyphersPtr)[i], (*encCyphersPtr)[i+1]}
		wrappedCypherPtr, err := Wrapper(&fileHmacKey, &tempCyphers)
		if err != nil {
			panic("file cypher wrap failed.")
		}
		wrappedCypherBytes, err := json.Marshal(*wrappedCypherPtr)
		if err != nil || len(wrappedCypherBytes) <= 2 {
			panic("file cypher marshal failed.")
		}
		userlib.DatastoreSet(metadata.CypherUUIDs[i], wrappedCypherBytes)
	}
	// Encrypt, wrap and store the file's metadata on the Datastore
	metadataBytes, err := json.Marshal(metadata)
	if err != nil || len(metadataBytes) <= 2 {
		panic("file metadata marshal failed.")
	}
	metadataEncCyphersPtr, err := SymmetricEnc(&fileEncKey, &IV, &metadataBytes)
	if err != nil {
		panic("file metadata encryption failed.")
	}
	wrappedMetadataCypherPtr, err := Wrapper(&fileHmacKey, metadataEncCyphersPtr)
	if err != nil {
		panic("file metadata wrap failed.")
	}
	wrappedMetadataBytes, err := json.Marshal(*wrappedMetadataCypherPtr)
	if err != nil || len(wrappedMetadataBytes) <= 2 {
		panic("file metadata marshal failed.")
	}
	userlib.DatastoreSet(fileUUID, wrappedMetadataBytes)

	// Adding file's UUID and key to userdata
	userdata.FileUUIDs[filename] = fileUUID
	userdata.FileKeys[fileUUID] = fileEncKey
	userdata.FilesOwned[fileUUID] = true

	// Save the userdata to the Datastore
	rehashedUPH, err := userlib.HMACEval(userdata.UPH, []byte(userdata.Username))
	if err != nil {
		return
	}
	userUUID, err := uuid.FromBytes(rehashedUPH[:16])
	if err != nil {
		return
	}
	err = userdata.SaveUser(userUUID)
	if err != nil {
		panic(err)
	}
}

/**
This method efficiently appends data to the underlying file known as filename the user.
Note that this is very similar to the load file method by design.
Note that this raises an error if the filename is not found.

It takes:
	- A filename string = the name of the file for THIS particular user.
	- A data byte slice to be appended.
It returns:
	- A nil error if successful.
*/
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Setup & derive file attributes
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		err = errors.New("file not found for the append")
		return
	}
	fileUUIDBytes, err := fileUUID.MarshalBinary()
	if err != nil {
		err = errors.New("file UUID binary marshal failed")
		return
	}
	fileEncKey, ok := userdata.FileKeys[fileUUID]
	if !ok {
		err = errors.New("file key not found")
		return
	}
	fileHmacKey, err := userlib.HMACEval(fileEncKey, fileUUIDBytes)
	if err != nil {
		return
	}
	fileHmacKey = fileHmacKey[:userlib.AESKeySize]

	// Fetch, verify and unencrypt file's data
	metadataPtr, err := GetFileMetadata(&fileUUID, &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}
	_ = metadataPtr

	// TODO: finish this up.

	// Save the userdata to the Datastore
	rehashedUPH, err := userlib.HMACEval(userdata.UPH, []byte(userdata.Username))
	if err != nil {
		return
	}
	userUUID, err := uuid.FromBytes(rehashedUPH[:16])
	if err != nil {
		return
	}
	err = userdata.SaveUser(userUUID)
	if err != nil {
		panic(err)
	}
	return
}

/**
This method loads a file in the datastore and does not reveal the filename to the Datastore.
It will error if the file doesn't exist or if the file is corrupted in ANY WAY.
Note that only a user (i.e: a User struct) can call this method.

It takes:
	- A filename string = the name of the file for THIS particular user.
It returns:
	- The file's byte slice.
	- A nil error if successful.
*/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Setup & derive file attributes
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		return // Do NOT raise an error if the file is not found.
	}
	fileUUIDBytes, err := fileUUID.MarshalBinary()
	if err != nil {
		err = errors.New("file UUID binary marshal failed")
		return
	}
	fileEncKey, ok := userdata.FileKeys[fileUUID]
	if !ok {
		err = errors.New("file key not found")
		return
	}
	fileHmacKey, err := userlib.HMACEval(fileEncKey, fileUUIDBytes)
	if err != nil {
		return
	}
	fileHmacKey = fileHmacKey[:userlib.AESKeySize]

	// Fetch, verify and unencrypt file's data
	metadataPtr, err := GetFileMetadata(&fileUUID, &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}
	var encCyphers [][]byte
	for i, CypherUUID := range metadataPtr.CypherUUIDs {
		var wrappedCyphers Wrap
		wrappedCypherBytes, ok := userlib.DatastoreGet(CypherUUID)
		if !ok {
			err = errors.New("file is missing a cypher (probably corrupted)")
			return
		}
		err = json.Unmarshal(wrappedCypherBytes, &wrappedCyphers)
		if err != nil {
			return
		}
		cypherPairPtr, er := Unwrapper(&fileHmacKey, &wrappedCyphers)
		if er != nil {
			err = er // Won't compile if this like everything else.
			return
		}
		if i == 0 {
			encCyphers = *cypherPairPtr
		} else {
			encCyphers = append(encCyphers, (*cypherPairPtr)[1])
		}
	}
	dataPtr, err := SymmetricDec(&fileEncKey, &encCyphers)

	data = *dataPtr
	return
}

/**
This method deletes the underlying file known as filename to the user.
Only the file owner can delete the file.
Note that it deletes ALL related files on the Datastore.

TODO: Implement this function. It is needed for a file revoke.

It takes:
	- A filename string = the name of the file to be deleted
It returns:
	- A nil error if successful.
*/
func (userdata *User) DeleteFile(filename string) (err error) {
	return
}

// TODO: Move things around to have logic flow.

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

func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	DocUuid := userdata.FileUUIDs[filename]
	fileKey := userdata.FileKeys[DocUuid]
	//recipientPubKey, ok := userlib.KeystoreGet(recipient)
	// TODO: Change UUID scheme such that it can be derived from just the username
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
