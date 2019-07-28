package proj2

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
	UUID          uuid.UUID
	UPH           []byte
	symEncKey     []byte
	hmacKey       []byte
	PrivateDecKey userlib.PKEDecKey
	PrivateSigKey userlib.DSSignKey
	FilesOwned    map[uuid.UUID]bool
	FileUUIDs     map[string]uuid.UUID
	FileEncKeys   map[uuid.UUID][]byte
	FileHmacKeys  map[uuid.UUID][]byte
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

// The structure definition for the struct (in byte form) sent when sharing
type sharingRecord struct {
	EncMessage []byte
	Signature  []byte
}

// The structure definition for the struct containing all of the info necessary when sharing
type Record struct {
	EncBFileUUID   []byte
	EncFileEncKey  []byte
	EncFileHmacKey []byte
}

/**
Helper Functions:
*/

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
Note that userlib's symmetric encryption / decryption uses AES-CBC mode.

It takes:
	- A pointer to a decryption/encryption key byte slice.
	- A pointer to a IV byte slice. (size has to be equal to userlib.AESBlockSize)
	- A pointer to a byte slice to be encrypted.
It returns:
	- A pointer to a slice of byte slice cypher texts s.t. the first
      element is the IV byte slice.
*/
func SymmetricEnc(key *[]byte, iv *[]byte, data *[]byte) (cyphers *[][]byte) {
	padCount := userlib.AESBlockSize - (len(*data) % userlib.AESBlockSize)
	paddedData := make([]byte, padCount+len(*data))
	for i := 0; i <= len(*data); i++ {
		if i == len(*data) {
			paddedData[i] = 1
		} else {
			paddedData[i] = (*data)[i]
		}
	}

	encSlice := userlib.SymEnc(*key, *iv, paddedData)

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
Note that userlib's symmetric encryption / decryption uses AES-CBC mode.

It takes:
	- A pointer to a decryption/encryption key byte slice.
	- A pointer to a slice of byte slice cypher texts s.t. the first element is the IV byte slice.
It returns:
	- A pointer to a byte slice of the unencrypted data
*/
func SymmetricDec(key *[]byte, cyphers *[][]byte) (data *[]byte) {
	var cypher []byte
	for _, c := range *cyphers {
		cypher = append(cypher, c...)
	}

	decSlice := userlib.SymDec(*key, cypher)

	var padStart uint
	for padStart = uint(len(decSlice) - 1); padStart >= 0 && decSlice[padStart] == 0; padStart-- {
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
This function securely stores a byte slice on the Datastore.

This takes:
	- A pointer to the datastore UUID key
	- A pointer to a HMAC key byte slice.
	- A pointer to a decryption/encryption key byte slice.
	- A pointer to the byte slice to be stored.
It returns:
	- A nil error if successful.
*/
func SecureDatastoreSet(UUID *uuid.UUID, hmacKey *[]byte, symEncKey *[]byte, data *[]byte) (err error) {
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	encCyphersPtr := SymmetricEnc(symEncKey, &IV, data)
	wrappedCyphersPtr, err := Wrapper(hmacKey, encCyphersPtr)
	if err != nil {
		return
	}
	wrappedCyphersBytes, err := json.Marshal(*wrappedCyphersPtr)
	userlib.DatastoreSet(*UUID, wrappedCyphersBytes)
	return
}

/**
This function securely gets a byte slice from the Datastore.

This takes:
	- A pointer to the datastore UUID key
	- A pointer to a HMAC key byte slice.
	- A pointer to a decryption/encryption key byte slice.
It returns:
	- A pointer to the byte slice given when SecureDatastoreSet was called.
	- A nil error if successful.
*/
func SecureDatastoreGet(UUID *uuid.UUID, hmacKey *[]byte, symEncKey *[]byte) (data *[]byte, err error) {
	wrappedCyphersBytes, ok := userlib.DatastoreGet(*UUID)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}

	var wrap Wrap
	err = json.Unmarshal(wrappedCyphersBytes, &wrap)
	if err != nil {
		return
	}
	userdataCyphersPtr, err := Unwrapper(hmacKey, &wrap)
	if err != nil {
		return
	}
	data = SymmetricDec(symEncKey, userdataCyphersPtr)
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
func DeriveAndSaveUserAttributes(username *string, password *string, userdata *User) {
	bUsername := []byte(*username)
	bPassword := []byte(*password)

	userdata.UPH = userlib.Argon2Key(bPassword, bUsername, 32) // User Password Hash
	rehashedUPH, _ := userlib.HMACEval(userdata.UPH, bUsername)
	userdata.UUID, _ = uuid.FromBytes(rehashedUPH[:16])
	userdata.symEncKey = userlib.Argon2Key(append([]byte("enc_"), userdata.UPH...),
		bPassword, uint32(userlib.AESKeySize))
	userdata.hmacKey = userlib.Argon2Key(append([]byte("mac_"), userdata.UPH...),
		bPassword, uint32(userlib.AESKeySize))
	return
}

/**
User Init and Get:
*/

/**
This is the main function that creates a new user and saves them to the Datastore.
Note that symmetric encryption / decryption uses AES-CBC mode.

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
	DeriveAndSaveUserAttributes(&username, &password, &userdata)

	// Initialize the rest of the userdata.
	userdata.Username = username
	userdata.FilesOwned = make(map[uuid.UUID]bool)
	userdata.FileUUIDs = make(map[string]uuid.UUID)
	userdata.FileEncKeys = make(map[uuid.UUID][]byte)
	userdata.FileHmacKeys = make(map[uuid.UUID][]byte)

	// Set-up and save the asymmetric keys
	PKenc, PKdec, _ := userlib.PKEKeyGen()
	DSsig, DSvfy, _ := userlib.DSKeyGen()
	_ = userlib.KeystoreSet("enc_"+username, PKenc)
	_ = userlib.KeystoreSet("vfy_"+username, DSvfy)
	userdata.PrivateDecKey = PKdec
	userdata.PrivateSigKey = DSsig

	err = userdata.Store()
	return
}

/**
This is the main function to fetch a user from the Datastore.
Note that symmetric encryption / decryption uses AES-CBC mode.

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
func GetUser(username string, password string) (userdataPtr *User, err error) {
	var userdata User
	userdataPtr = &userdata
	DeriveAndSaveUserAttributes(&username, &password, &userdata)

	userdataBytesPtr, err := SecureDatastoreGet(&userdataPtr.UUID,
		&userdataPtr.hmacKey, &userdataPtr.symEncKey)
	if err != nil {
		if err.Error() == "UUID not found in keystore" {
			err = errors.New("username and/or password is not correct")
		}
		return
	}

	err = json.Unmarshal(*userdataBytesPtr, userdataPtr) // overwrite the userdata being used
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
func (userdata *User) Store() (err error) {
	byteUserdata, _ := json.Marshal(userdata)
	err = SecureDatastoreSet(&userdata.UUID, &userdata.hmacKey,
		&userdata.symEncKey, &byteUserdata)
	return
}

/**
This method stores a file in the datastore and does not reveal the filename to the Datastore.
Note that symmetric encryption / decryption uses AES-CBC mode.

This implementation overrides the existing underlying file but keeps the SAME metadata
file (and encryption keys) for file sharing.

It takes:
	- A filename string = the name of the file for THIS particular user.
	- The byte slice of the file.
*/
func (userdata *User) StoreFile(filename string, data []byte) {
	var (
		fileUUID    uuid.UUID
		fileEncKey  []byte
		fileHmacKey []byte
		ok          bool
	)

	fileUUID, overwrite := userdata.FileUUIDs[filename]
	if overwrite {
		// Save file keys for sharing and delete underlying file
		fileEncKey, ok = userdata.FileEncKeys[fileUUID]
		if !ok {
			userlib.DebugMsg("file key not found")
			return
		}
		fileHmacKey, ok = userdata.FileHmacKeys[fileUUID]
		if !ok {
			userlib.DebugMsg("file Hmac key not found")
			return
		}
		_ = userdata.DeleteFile(filename) // It is okay to error here
	} else {
		// Generate file keys and file UUID
		fileUUID = GenRandUUID()
		fileEncKey = userlib.RandomBytes(userlib.AESKeySize)
		fileHmacKey = userlib.RandomBytes(userlib.AESKeySize)
	}

	// Encrypt file data and get cyphers
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	cyphersPtr := SymmetricEnc(&fileEncKey, &IV, &data)

	// Store each cypher on the Datastore
	var metadata FileMetadata
	metadata.CypherUUIDs = make([]uuid.UUID, len(*cyphersPtr))
	for i := range metadata.CypherUUIDs {
		metadata.CypherUUIDs[i] = GenRandUUID()
		err := SecureDatastoreSet(&metadata.CypherUUIDs[i], &fileHmacKey,
			&fileEncKey, &(*cyphersPtr)[i])
		if err != nil {
			userlib.DebugMsg("", err)
			return
		}
	}

	// Encrypt, wrap and store the file's metadata on the Datastore
	metadataBytes, _ := json.Marshal(metadata)
	err := SecureDatastoreSet(&fileUUID, &fileHmacKey, &fileEncKey, &metadataBytes)
	if err != nil {
		userlib.DebugMsg("", err)
		return
	}

	// Adding file's UUID and key to userdata
	userdata.FileUUIDs[filename] = fileUUID
	userdata.FilesOwned[fileUUID] = true
	userdata.FileEncKeys[fileUUID] = fileEncKey
	userdata.FileHmacKeys[fileUUID] = fileHmacKey

	err = userdata.Store()
	if err != nil {
		userlib.DebugMsg("", err)
	}
}

/**
This method efficiently appends data to the underlying file known as filename the user.
Note that this is very similar to the load file method by design.
Note that this raises an error if the filename is not found.
Note that symmetric encryption / decryption uses AES-CBC mode.

It takes:
	- A filename string = the name of the file for THIS particular user.
	- A data byte slice to be appended.
It returns:
	- A nil error if successful.
*/
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Get file UUID and keys.
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok { // This is possibly undefined behavior in the spec.
		err = errors.New("file not found for the append")
		return
	}
	fileEncKey, ok := userdata.FileEncKeys[fileUUID]
	if !ok {
		err = errors.New("file key not found")
		return
	}
	fileHmacKey, ok := userdata.FileHmacKeys[fileUUID]
	if !ok {
		err = errors.New("file Hmac key not found")
		return
	}

	// Fetch, verify and unencrypt file's metadata
	var metadata FileMetadata
	metadataBytesPtr, err := SecureDatastoreGet(&fileUUID, &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}
	_ = json.Unmarshal(*metadataBytesPtr, &metadata)

	// Fetch, verify and unencrypt last 2 cyphers of file's data
	last2CypherUUIDs := metadata.CypherUUIDs[len(metadata.CypherUUIDs)-2:]
	cypher0BytesPtr, err := SecureDatastoreGet(&last2CypherUUIDs[0], &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}
	cypher1BytesPtr, err := SecureDatastoreGet(&last2CypherUUIDs[1], &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}

	// Append to the end of our file and encrypt it
	cyphers := [][]byte{*cypher0BytesPtr, *cypher1BytesPtr}
	oldEndDataPtr := SymmetricDec(&fileEncKey, &cyphers)
	if err != nil {
		return
	}
	endData := append(*oldEndDataPtr, data...)
	cyphersPtr := SymmetricEnc(&fileEncKey, cypher0BytesPtr, &endData)

	// Store the new cyphers in the Datastore and update metadata
	metadata.CypherUUIDs = metadata.CypherUUIDs[:len(metadata.CypherUUIDs)-1]
	for i := 1; i < len(*cyphersPtr); i++ {
		cypherUUID := GenRandUUID()
		metadata.CypherUUIDs = append(metadata.CypherUUIDs, cypherUUID)
		err = SecureDatastoreSet(&cypherUUID, &fileHmacKey, &fileEncKey, &(*cyphersPtr)[i])
		if err != nil {
			return
		}
	}

	// Encrypt, wrap and store the file's metadata on the Datastore
	metadataBytes, _ := json.Marshal(metadata)
	err = SecureDatastoreSet(&fileUUID, &fileHmacKey, &fileEncKey, &metadataBytes)
	return
}

/**
This method loads a file in the datastore and does not reveal the filename to the Datastore.

It will error if the file doesn't exist or if the file is corrupted in any way.
Note that it will NOT raise an error if the file cannot be found.

It takes:
	- A filename string = the name of the file for THIS particular user.
It returns:
	- The file's byte slice.
	- A nil error if successful.
*/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Get file UUID and keys.
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		userlib.DebugMsg("filename not found for user: %s", userdata.Username)
		// Do not raise error
		return
	}
	fileEncKey, ok := userdata.FileEncKeys[fileUUID]
	if !ok {
		err = errors.New("file key not found")
		return
	}
	fileHmacKey, ok := userdata.FileHmacKeys[fileUUID]
	if !ok {
		err = errors.New("file Hmac key not found")
		return
	}

	// Fetch, verify and unencrypt file's metadata
	var metadata FileMetadata
	metadataBytesPtr, err := SecureDatastoreGet(&fileUUID, &fileHmacKey, &fileEncKey)
	if err != nil {
		if err.Error() == "UUID not found in keystore" {
			// Remove file if file is not found for user (do not raise error)
			userlib.DebugMsg("file not found for user: %s", userdata.Username)
			delete(userdata.FilesOwned, fileUUID)
			delete(userdata.FileEncKeys, fileUUID)
			delete(userdata.FileUUIDs, filename)
			err = userdata.Store()
		}
		return
	}
	_ = json.Unmarshal(*metadataBytesPtr, &metadata)

	// Fetch, verify, combine cyphers, and unencrypt file's data
	var cyphers [][]byte
	for _, CypherUUID := range metadata.CypherUUIDs {
		cypherPtr, er := SecureDatastoreGet(&CypherUUID, &fileHmacKey, &fileEncKey)
		if er != nil {
			err = er
			return
		}
		cyphers = append(cyphers, *cypherPtr)
	}
	dataPtr := SymmetricDec(&fileEncKey, &cyphers)
	data = *dataPtr
	return
}

/**
This method deletes the underlying file known as filename to the user.
Note that it deletes ALL related files on the Datastore.

This implementation does NOT check if the user was the original creator
of the underlying file since it is undefined behavior for a non-owner
to delete the file.

It takes:
	- A filename string = the name of the file to be deleted
It returns:
	- A nil error if successful.
*/
func (userdata *User) DeleteFile(filename string) (err error) {
	// Get file UUID and keys.
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		return // Nothing to delete
	}
	fileEncKey, ok := userdata.FileEncKeys[fileUUID]
	if !ok {
		err = errors.New("file key not found")
		return
	}
	fileHmacKey, ok := userdata.FileHmacKeys[fileUUID]
	if !ok {
		err = errors.New("file Hmac key not found")
		return
	}

	// Fetch, verify and unencrypt file's metadata
	var metadata FileMetadata
	metadataBytesPtr, err := SecureDatastoreGet(&fileUUID, &fileHmacKey, &fileEncKey)
	if err != nil {
		return
	}
	_ = json.Unmarshal(*metadataBytesPtr, &metadata)

	// Remove each cypher entry and the metadata entry
	for _, cypherUUID := range metadata.CypherUUIDs {
		userlib.DatastoreDelete(cypherUUID)
	}
	userlib.DatastoreDelete(fileUUID)

	// Update and save user.
	delete(userdata.FilesOwned, fileUUID)
	delete(userdata.FileEncKeys, fileUUID)
	delete(userdata.FileUUIDs, filename)
	err = userdata.Store()
	return
}

/**
This method shares a record to the recipient. The sender's filename will not be known to
the recipient since the underlying file's UUID is the 'file pointer' being sent.

Note that we have to encrypt each key and file UUID separately because RSA will not allow
long strings.

It takes:
	- A filename string = the name of the file to be shared.
	- A recipient string = the username of recipient user.
It returns:
	- A string to be sent to the recipient user.
	- A nil error if successful.
*/
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	// Get file UUID and keys.
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		err = errors.New("user does not have access to this file - missing docUUID")
		return
	}
	bFileUUID, _ := fileUUID.MarshalBinary()
	fileEncKey, ok := userdata.FileEncKeys[fileUUID]
	if !ok {
		err = errors.New("missing file encryption key")
		return
	}
	fileHmacKey, ok := userdata.FileHmacKeys[fileUUID]
	if !ok {
		err = errors.New("missing MAC key")
		return
	}

	// Encrypt each UUID and keys
	recPKE, ok := userlib.KeystoreGet("enc_" + recipient)
	if !ok {
		err = errors.New("invalid recipient - missing public encryption key")
		return

	}
	encBFileUUID, _ := userlib.PKEEnc(recPKE, bFileUUID)
	encFileEncKey, _ := userlib.PKEEnc(recPKE, fileEncKey)
	encFileHmacKey, _ := userlib.PKEEnc(recPKE, fileHmacKey)

	// Create a record, sign it, and package it for the share message
	record := Record{encBFileUUID, encFileEncKey, encFileHmacKey}
	encMessageBytes, _ := json.Marshal(record)
	sig, _ := userlib.DSSign(userdata.PrivateSigKey, encMessageBytes)
	magicStringBytes, _ := json.Marshal(sharingRecord{encMessageBytes, sig})
	magic_string = string(magicStringBytes)
	return
}

/**
This method receives a file share message and updates the userdata accordingly.
Note that it validates the received message before decrypting it to ensure that
the share message has not been tampered with.

Note that this implementation will always override the user's existing filename
data with the received file name data. This is technically an undefined behavior
in the spec.

It takes:
	- A filename string = the name of the file to save the received file as.
	- A sender string = the username of user that sent the file.
	- A string containing the encrypted (and signed) file UUID and keys.
It returns:
	- A nil error if successful.
*/
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) (err error) {
	// Unpack sharingRecord from string and verify it
	var magicRecord sharingRecord
	err = json.Unmarshal([]byte(magic_string), &magicRecord)
	if err != nil {
		return
	}
	senderPubSigKey, ok := userlib.KeystoreGet("vfy_" + sender)
	if !ok {
		return errors.New("invalid sender")
	}
	err = userlib.DSVerify(senderPubSigKey, magicRecord.EncMessage, magicRecord.Signature)
	if err != nil {
		return err
	}

	// Decrypt file UUID and keys
	var record Record
	_ = json.Unmarshal(magicRecord.EncMessage, &record)
	fileUUIDBytes, err := userlib.PKEDec(userdata.PrivateDecKey, record.EncBFileUUID)
	if err != nil {
		return err
	}
	fileUUID, err := uuid.FromBytes(fileUUIDBytes)
	if err != nil {
		return err
	}
	fileEncKey, err := userlib.PKEDec(userdata.PrivateDecKey, record.EncFileEncKey)
	if err != nil {
		return err
	}
	fileHmacKey, err := userlib.PKEDec(userdata.PrivateDecKey, record.EncFileHmacKey)
	if err != nil {
		return err
	}

	// Update userdata and save
	userdata.FileUUIDs[filename] = fileUUID
	userdata.FileEncKeys[fileUUID] = fileEncKey
	userdata.FileHmacKeys[fileUUID] = fileHmacKey
	err = userdata.Store()
	return
}

/**
This method revokes a file that was shared so that only the user has access to it.
Note that this implementation allows anyone to revoke a file (not just the file owner)
since this is technically undefined behavior in the spec.

It takes:
	- A filename string = the name of the file to be revoked
It returns:
	- A nil error if successful.
*/
func (userdata *User) RevokeFile(filename string) (err error) {
	fileUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		return errors.New("missing UUID for this filename")
	}
	own, ok := userdata.FilesOwned[fileUUID]
	if !ok || !own {
		// We allow anyone to revoke a file as stated in the spec
		userlib.DebugMsg("%s is revoking %s, which they do not own",
			userdata.Username, filename)
	}

	file, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	err = userdata.DeleteFile(filename)
	if err != nil {
		return err
	}
	userdata.StoreFile(filename, file)
	return
}
