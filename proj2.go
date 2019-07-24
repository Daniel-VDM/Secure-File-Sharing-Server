package main // Might need to change package to proj2 to pass auto grader

//package proj2

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
	_ "strconv"
	"strings"
)

func someUsefulThings() {
	// Creates a random UUID
	userlib.DebugPrint = true
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
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
		cyphers = &wrap.Cyphers
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
	- Username String
	- Password String
It returns:
	- A pointer to the User struct that was created and stored on the Datastore.
	- A nil error if successful.
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
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
	var userdata User
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

	userdataptr = &userdata
	return
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	return userdataptr, nil
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
