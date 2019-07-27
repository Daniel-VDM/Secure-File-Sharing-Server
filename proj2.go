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
Note that userlib's symmetric encryption / decryption uses AES-CBC mode.

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
	encCyphersPtr, err := SymmetricEnc(symEncKey, &IV, data)
	if err != nil {
		return
	}
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
	_ = json.Unmarshal(wrappedCyphersBytes, &wrap)
	userdataCyphersPtr, err := Unwrapper(hmacKey, &wrap)
	if err != nil {
		return
	}
	data, err = SymmetricDec(symEncKey, userdataCyphersPtr)
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
This function assumes that it will be called only once per unique username.
Note that symmetric encryption / decryption uses AES-CBC mode.

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
	cyphersPtr, err := SymmetricEnc(&fileEncKey, &IV, &data)
	if err != nil {
		userlib.DebugMsg("file data encryption failed.")
		return
	}

	// Store each cypher on the Datastore
	var metadata FileMetadata
	metadata.CypherUUIDs = make([]uuid.UUID, len(*cyphersPtr))
	for i := range metadata.CypherUUIDs {
		metadata.CypherUUIDs[i] = GenRandUUID()
		err = SecureDatastoreSet(&metadata.CypherUUIDs[i], &fileHmacKey,
			&fileEncKey, &(*cyphersPtr)[i])
		if err != nil {
			userlib.DebugMsg("", err)
			return
		}
	}

	// Encrypt, wrap and store the file's metadata on the Datastore
	metadataBytes, _ := json.Marshal(metadata)
	err = SecureDatastoreSet(&fileUUID, &fileHmacKey, &fileEncKey, &metadataBytes)
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
	oldEndDataPtr, err := SymmetricDec(&fileEncKey, &cyphers)
	if err != nil {
		return
	}
	endData := append(*oldEndDataPtr, data...)
	cyphersPtr, err := SymmetricEnc(&fileEncKey, cypher0BytesPtr, &endData)
	if err != nil {
		return
	}

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
		err = errors.New("filename not found for user")
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
	dataPtr, err := SymmetricDec(&fileEncKey, &cyphers)
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
		// Nothing to delete
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
	DocUuid, ok := userdata.FileUUIDs[filename]
	if !ok {
		err = errors.New("user does not have access to this file - missing docUUID")
		return
	}
	fileEncKey, ok := userdata.FileEncKeys[DocUuid]
	if !ok {
		err = errors.New("missing file encryption key")
		return
	}
	fileHmacKey, ok := userdata.FileHmacKeys[DocUuid]
	if !ok {
		err = errors.New("missing MAC key")
		return
	}
	recPKE, ok := userlib.KeystoreGet("enc_" + recipient)
	if !ok {
		err = errors.New("invalid recipient - missing public encryption key")
		return
	}
	bDocUuid, err := DocUuid.MarshalBinary()
	if err != nil {
		return
	}
	message := append(bDocUuid, fileEncKey...)
	message = append(message, fileHmacKey...)
	ciphertext, err := userlib.PKEEnc(recPKE, message)
	if err != nil {
		return
	}

	sig, err := userlib.DSSign(userdata.PrivateSigKey, ciphertext)
	if err != nil {
		return
	}

	magic_string = string(append(sig, ciphertext...))
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	bMagicString := []byte(magic_string)
	sig := bMagicString[:userlib.HashSize]
	msg := bMagicString[userlib.HashSize:]
	senderPubSigKey, ok := userlib.KeystoreGet("vfy_" + sender)
	if !ok {
		return errors.New("invalid sender")
	}
	err := userlib.DSVerify(senderPubSigKey, msg, sig)
	if err != nil {
		return err
	}

	msg, err = userlib.PKEDec(userdata.PrivateDecKey, msg)
	if err != nil || len(msg) != 16 + userlib.RSAKeySize * 2 {
		return err
	}
	bDocUuid := msg[:16]
	fileEncKey := msg[16:16 + userlib.RSAKeySize]
	fileHmacKey := msg[16+userlib.RSAKeySize:]

	DocUuid, err := uuid.FromBytes(bDocUuid)
	if err != nil {
		return err
	}

	userdata.FileUUIDs[filename] = DocUuid
	userdata.FileEncKeys[DocUuid] = fileEncKey
	userdata.FileHmacKeys[DocUuid] = fileHmacKey
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	docUUID, ok := userdata.FileUUIDs[filename]
	if !ok {
		return errors.New("missing UUID for this filename")
	}
	own, ok := userdata.FilesOwned[docUUID]
	if !ok || !own {
		return errors.New("user is not the file creator")
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
	return nil
}
