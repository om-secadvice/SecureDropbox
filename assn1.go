package assn1

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/fenilfadadu/CS628-assn1/userlib"
	"github.com/google/uuid"
)

// someUsefulThings - This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
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
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// GenericFile - All interface{} are first converted to JSON, encrypted and put in Content field of a GenericFile. The GenericFile JSON is then stored in Datastore.
// This gives us many advantages:-
//
// This way by looking at any location in Datastore server can't know whether it is a FileHeader, FileMeta, User or File content.
//
// Member functions of GenericFile provides Encryption, Decryption, HMAC and Signature verification.
type GenericFile struct {
	Content   string
	Hmac      string `json:",omitempty"`
	Signature string `json:",omitempty"`
}

// encryptCFB - Returns a json generic file with encrypted content and its hmac to directly store
//
// Convert interface{} v to JSON.
// Populate 'gen'(generic file object on which encryptCFB() is called).
// gen.Content set to CFBEncrypt of JSON of v.
// gen.Hmac set to HMAC(gen.Content).
// Return JSON marshal of gen.
func (gen *GenericFile) encryptCFB(aesKey []byte, macKey []byte, v interface{}) (jsonFile []byte, err error) {

	data, er := json.Marshal(v)
	if er != nil {
		return nil, er
	}
	aesCipher := make([]byte, len(data)+userlib.BlockSize)
	aesIv := userlib.RandomBytes(userlib.BlockSize)
	encrypter := userlib.CFBEncrypter(aesKey, aesIv)
	encrypter.XORKeyStream(aesCipher[userlib.BlockSize:], data)
	copy(aesCipher[:userlib.BlockSize], aesIv)

	gen.Content = enc(aesCipher)

	hmac := userlib.NewHMAC(macKey)
	hmac.Write(aesCipher)
	gen.Hmac = enc(hmac.Sum(nil))

	jsonFile, err = json.Marshal(gen)
	return

}

// decryptCFB - Returns unencrypted buffer which must be unmarshalled to get required interface{}.
//
// Populate 'gen'(generic file object on which decryptCFB() is called).
// Verify gen.Hmac == HMAC(gen.Content).
// If verified then decrypt gen.Content using CFBDecrypt.
// aesIV is present in gen.Content already.
// Return the decrypted buffer which can be unmarshalled to get desired interface{}
func (gen *GenericFile) decryptCFB(aesKey []byte, macKey []byte, data []byte) (bufferStruct []byte, err error) {

	//Populate gen
	err = json.Unmarshal(data, &gen)
	if err != nil {

		return nil, errors.New("Possible integrity violation. Can't Unmarshal ")
	}
	//Store content in buffer
	aesCipher := dec(gen.Content)

	//HMAC Check
	hmac := userlib.NewHMAC(macKey)
	hmac.Write(aesCipher)
	if gen.Hmac != enc(hmac.Sum(nil)) {
		return nil, errors.New("Integrity Violation")
	}

	aesIv := aesCipher[:userlib.BlockSize]
	aesCipher = aesCipher[userlib.BlockSize:]

	buff := make([]byte, len(aesCipher))
	decrypter := userlib.CFBDecrypter(aesKey, aesIv)
	decrypter.XORKeyStream(buff, aesCipher)

	return buff, err

}

//encryptRSA - Returns a encrypted json file which can be  directly stored.
//
// gen.Content is set to RSA encrypted string of JSON of interface{} v.
// gen.Hmac is set to calculated HMAC of gen.Content field.
// gen.Signature is set to calculated signature on hash of data.
// Sign the data only if prikey!=nil argument is supplied.
// Sign the data as well as macKey if signMacKey=true.
// Returns JSON of generic file.
func (gen *GenericFile) encryptRSA(signMacKey bool, prikey *userlib.PrivateKey, username string, macKey []byte, v interface{}) (jsonFile []byte, err error) {

	pubkey, ok := userlib.KeystoreGet(username)
	if ok != true {
		return nil, errors.New("User Not Found in Keyserver")
	}
	data, er := json.Marshal(v)
	if er != nil {
		return nil, er
	}

	var rsaCipher []byte
	rsaCipher, err = userlib.RSAEncrypt(&pubkey, data, nil)
	if err != nil {
		return nil, err
	}
	gen.Content = enc(rsaCipher)

	hmac := userlib.NewHMAC(macKey)
	hmac.Write(rsaCipher)
	gen.Hmac = enc(hmac.Sum(nil))

	//Sign also if prikey available
	if prikey != nil {
		hash := userlib.NewSHA256()
		hash.Write(rsaCipher)
		//Useful if sharing address of file
		if signMacKey {
			hash.Write(macKey)
		}

		sign, er := userlib.RSASign(prikey, hash.Sum(nil))
		if er != nil {
			return nil, er
		}
		gen.Signature = enc(sign)
	}
	jsonFile, err = json.Marshal(gen)

	return

}

// decryptRSA - Returns unencrypted buffer to Unmarshal to required struct.
//
// Unmarshal the data []byte to 'gen'(generic file object on which decryptRSA is called).
// Verify gen.Hmac == HMAC(gen.Content).
// If sender!="" then verify gen.Signature on Hash(gen.Content,macKey) if signMacKey=true else only on Hash(gen.Content).
// If verified then RSAdecrypt(gen.Content) which gives us JSON bufferStruct []byte to reconstruct appropriate structure.
//
func (gen *GenericFile) decryptRSA(signMacKey bool, sender string, privKey *userlib.PrivateKey, macKey []byte, data []byte) (bufferStruct []byte, err error) {

	//Populate gen
	err = json.Unmarshal(data, &gen)
	if err != nil {
		return nil, errors.New("Can't Unmarshal Structure From Buffer")
	}
	//Store content in buffer
	rsaCipher := dec(gen.Content)

	//HMAC Check
	hmac := userlib.NewHMAC(macKey)
	hmac.Write(rsaCipher)
	if gen.Hmac != enc(hmac.Sum(nil)) {
		return nil, errors.New("Integrity Violation")
	}

	//Verify signature also if sender is available
	if sender != "" {
		hash := userlib.NewSHA256()
		hash.Write(rsaCipher)
		//Useful if sharing address of file
		if signMacKey {
			hash.Write(macKey)
		}
		pubkey, ok := userlib.KeystoreGet(sender)
		if ok != true {
			return nil, errors.New("Can't fetch Publickey from store for sender")
		}
		err = userlib.RSAVerify(&pubkey, hash.Sum(nil), dec(gen.Signature))
		if err != nil {
			return nil, err
		}
	}
	bufferStruct, err = userlib.RSADecrypt(privKey, rsaCipher, nil)

	return

}

//Generic File ends here

//User - The structure definition for a user record
type User struct {
	ArgonKey string
	Username string
	Password string
	PrivKey  string
}

//FileHeader - Structure definition for a File Header
type FileHeader struct {
	Meta       string
	ContentKey string
	MACKey     string
}

//FileMeta - Structure definition for a Metadata block for a file
type FileMeta struct {
	ListOfUUIDs []string
}

//Important Utility Functions Starts Here

//enc - Encode byte to hex string
func enc(data []byte) (hexdata string) {
	return hex.EncodeToString(data)
}

//dec - Decode hex string to byte
func dec(hexdata string) (data []byte) {
	data, _ = hex.DecodeString(hexdata)
	return
}

//getPriKeyFromBuffer - Parse  userlib.PrivateKey structure  from buffer
func getPriKeyFromBuffer(data []byte) (key *userlib.PrivateKey) {
	json.Unmarshal(data, &key)
	return
}

//getBufferFromPriKey - Marshal  userlib.PrivateKey structure to buffer
func getBufferFromPriKey(key userlib.PrivateKey) (byteKey []byte) {
	byteKey, _ = json.Marshal(key)
	return
}

//b - Converts string to byte (Don't Use b() for strings created using enc())
func b(data string) (b []byte) {
	return []byte(data)
}

//Contains tells whether a contains x.
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

//Important Utility Functions Ends Here

//Member functions for User Starts Here

//getHeaderAndLoc - Fetches header from datastore and returns decrypted FileHeader structure with its location.
func (userdata *User) getHeaderAndLoc(filename string) (header FileHeader, headerloc string, err error) {
	//Calculate header location
	hash := userlib.NewSHA256()
	hash.Write(b(userdata.Username + filename))
	headerloc = enc(hash.Sum(nil))

	//Fetch GenericFile from Datastore.
	//FileHeader is actually decrypted genFile.Content
	buff, e := userlib.DatastoreGet(headerloc)
	if e != true {
		err = errors.New("Header Not Found")
		return
	}

	//Decryption
	privKey := getPriKeyFromBuffer(dec(userdata.PrivKey))
	var genFile GenericFile
	buff, err = genFile.decryptRSA(false, "", privKey, b(userdata.Password+filename), buff)
	if err != nil {
		return
	}

	err = json.Unmarshal(buff, &header)
	return

}

//getMeta - Returns decrypted FileMeta structure from Datastore for given FileHeader
func (userdata *User) getMeta(header FileHeader) (metafile FileMeta, err error) {

	var meta, buff []byte
	var e bool

	meta, e = userlib.DatastoreGet(header.Meta)
	if e != true {
		err = errors.New("Meta Not Found")
		return
	}
	genFile := GenericFile{}
	buff, err = genFile.decryptCFB(dec(header.ContentKey), dec(header.MACKey), meta)
	if err != nil {
		return
	}
	err = json.Unmarshal(buff, &metafile)
	return
}

// InitUser You can assume the user has a STRONG password
// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)
//
// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.
//
// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
//
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.
func InitUser(username string, password string) (userdataptr *User, err error) {

	//Calculate location to store
	hash := userlib.Argon2Key(b(username), b(password), 32)
	loc := enc(hash)
	//Generate RSA Keypairs
	prikey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	priKeyBuff := getBufferFromPriKey(*prikey)
	//Prepare User structure to encrypt
	userdata := User{
		ArgonKey: loc,
		Username: username,
		Password: password,
		PrivKey:  enc(priKeyBuff),
	}
	aesKey := make([]byte, userlib.AESKeySize)
	//Ensure AES Key Size by hashing Password
	//This way no restriction on password length
	myhash := userlib.NewSHA256()
	myhash.Write(b(password))
	copy(aesKey, myhash.Sum(nil))

	//Encrypt user structure to file
	file, err := new(GenericFile).encryptCFB(aesKey, b(username+password), userdata)

	if err != nil {
		return nil, err
	}
	//Store File
	userlib.DatastoreSet(loc, file)

	//Register Public Key
	userlib.KeystoreSet(username, prikey.PublicKey)

	return &userdata, err
}

//GetUser This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	//Calculate location to fetch
	hash := userlib.Argon2Key(b(username), b(password), 32)
	loc := enc(hash)

	file, e := userlib.DatastoreGet(loc)
	if e != true {
		return nil, errors.New("User Not Found")
	}

	//Unmarshal File
	var genFile GenericFile
	aesKey := make([]byte, userlib.AESKeySize)
	//This will break if AESKeySize!=HashSize
	hasher := userlib.NewSHA256()
	hasher.Write(b(password))
	copy(aesKey, hasher.Sum(nil))

	//Get Unencrypted Buffer From GenericFile
	buff, er := genFile.decryptCFB(aesKey, b(username+password), file)
	if er != nil {
		return nil, er
	}
	//Unmarshal user data structure
	var userdata User
	err = json.Unmarshal(buff, &userdata)

	return &userdata, err
}

//StoreFile This stores a file in the datastore.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//Calculate storage location
	hash := userlib.NewSHA256()
	hash.Write(b(userdata.Username))
	hash.Write(b(filename))
	loc := enc(hash.Sum(nil))

	//Header Preparation
	prikeyBuff := dec(userdata.PrivKey)
	//Generate ContentKey(aesKey) and MACKey
	aesKey := userlib.RandomBytes(userlib.AESKeySize)
	//MacKey also used as IV for AES
	macKey := userlib.RandomBytes(userlib.BlockSize)
	//FileMeta Location Calculation

	hash = userlib.NewSHA256()
	hash.Write(prikeyBuff)
	hash.Write(macKey)
	metaloc := enc(hash.Sum(nil))
	header := FileHeader{
		Meta:       metaloc,
		MACKey:     enc(macKey),
		ContentKey: enc(aesKey),
	}

	var gen GenericFile
	headerFile, _ := gen.encryptRSA(false, nil, userdata.Username, b(userdata.Password+filename), header)

	//FileMeta Preparation
	//Calculate File Location Using new UUID every time

	//hash.Write(macKey)
	fileloc := uuid.New().String()
	list := []string{enc(b(fileloc))}
	meta := FileMeta{
		ListOfUUIDs: list,
	}

	metaFile, _ := new(GenericFile).encryptCFB(aesKey, macKey, meta)

	//FileContent Preparation
	uuidRand := b(fileloc)
	uuidRand = append(uuidRand, macKey...)
	contentFile, _ := new(GenericFile).encryptCFB(aesKey, uuidRand, data)

	fileloc = enc(b(fileloc))
	//Save all three
	userlib.DatastoreSet(loc, headerFile)
	userlib.DatastoreSet(metaloc, metaFile)
	userlib.DatastoreSet(fileloc, contentFile)

}

// AppendFile This adds on to an existing file.
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var header FileHeader
	var metafile FileMeta
	// var buff []byte

	header, _, err = userdata.getHeaderAndLoc(filename)
	if err != nil {
		return
	}
	metafile, err = userdata.getMeta(header)
	if err != nil {
		return
	}
	contentKey, macKey := dec(header.ContentKey), dec(header.MACKey)

	fileloc := uuid.New().String()
	uuidRand := b(fileloc)
	uuidRand = append(uuidRand, macKey...)
	contentFile, e := new(GenericFile).encryptCFB(contentKey, uuidRand, data)
	if e != nil {
		return e
	}

	fileloc = enc(b(fileloc))

	metafile.ListOfUUIDs = append(metafile.ListOfUUIDs, fileloc)
	metaBuff, er := new(GenericFile).encryptCFB(contentKey, macKey, metafile)
	if er != nil {
		return er
	}
	userlib.DatastoreSet(header.Meta, metaBuff)
	userlib.DatastoreSet(fileloc, contentFile)

	return
}

// LoadFile This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	var header FileHeader
	var metafile FileMeta
	var buff []byte
	var genFile GenericFile

	header, _, err = userdata.getHeaderAndLoc(filename)
	if err != nil {
		return
	}

	metafile, err = userdata.getMeta(header)
	if err != nil {
		return
	}

	for _, loc := range metafile.ListOfUUIDs {
		buff, _ = userlib.DatastoreGet(loc)
		x := dec(loc)
		x = append(x, dec(header.MACKey)...)
		genFile = GenericFile{}
		msgPart, er := genFile.decryptCFB(dec(header.ContentKey), x, buff)
		if err != nil {
			err = er
			return
		}
		var msg []byte
		err = json.Unmarshal(msgPart, &msg)
		if err != nil {
			return
		}
		data = append(data, msg...)
	}

	return
}

//sharingRecord -You may want to define what you actually want to pass as a
// SharingRecord to serialized/deserialize in the data store.
//
//NOTE:- We instead use a FileHeader structure for sharing.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// ShareFile Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
//
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	//Error if sender is recipient
	if recipient == userdata.Username {
		return "", errors.New("Can't Share With Yourself")
	}

	//Get header for filename if exists
	var header FileHeader
	header, _, err = userdata.getHeaderAndLoc(filename)
	if err != nil {
		return "", errors.New("Header Not Found")
	}

	var msg, msgidbuff []byte
	//Generate msgid i.e. address
	address := userlib.RandomBytes(32)

	hash := userlib.NewSHA256()
	hash.Write(address)
	hashaddr := hash.Sum(nil)

	//Ensures encryption and signature. Since signature is being used HMAC won't be computed
	msg, err = new(GenericFile).encryptRSA(true, getPriKeyFromBuffer(dec(userdata.PrivKey)), recipient, hashaddr, header)
	if err != nil {
		return
	}
	userlib.DatastoreSet(enc(address), msg)

	msgidbuff, err = new(GenericFile).encryptRSA(false, getPriKeyFromBuffer(dec(userdata.PrivKey)), recipient, nil, address)

	msgid = enc(msgidbuff)
	return
}

// ReceiveFile Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
//
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	var address, addressbuff []byte

	//Verify HMAC and decrypt the msgid
	//Verify Signature because 'sender' arguement also passed.
	addressbuff, err := new(GenericFile).decryptRSA(false, sender, getPriKeyFromBuffer(dec(userdata.PrivKey)), nil, dec(msgid))
	if err != nil {
		return err
	}
	//Load unencrypted address
	err = json.Unmarshal(addressbuff, &address)
	if err != nil {
		return err
	}

	//Calculate hash(address) to pass as 'macKey' to decryptRSA()
	hash := userlib.NewSHA256()
	hash.Write(address)
	hashaddr := hash.Sum(nil)

	//Find encrypted header at msgid location
	var headerBuff []byte
	var ok bool
	//Get the GenericFile buffer from address
	headerBuff, ok = userlib.DatastoreGet(enc(address))
	if ok != true {
		return errors.New("Sharing Record Not Found")
	}

	//Decrypt to give marshalled FileHeader structure
	headerBuff, err = new(GenericFile).decryptRSA(true, sender, getPriKeyFromBuffer(dec(userdata.PrivKey)), hashaddr, headerBuff)
	if err != nil {
		return err
	}
	var header FileHeader
	err = json.Unmarshal(headerBuff, &header)
	if err != nil {
		return errors.New("Sharing Record Tampered With")
	}
	headerBuff, err = new(GenericFile).encryptRSA(false, nil, userdata.Username, b(userdata.Password+filename), header)
	if err != nil {
		return errors.New("Sharing Record Tampered With")
	}
	//Calculate storage location
	hash = userlib.NewSHA256()
	hash.Write(b(userdata.Username))
	hash.Write(b(filename))
	loc := enc(hash.Sum(nil))
	userlib.DatastoreSet(loc, headerBuff)

	return nil
}

//RevokeFile Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	//Finding the FileHeader for filename
	var header FileHeader
	header, _, err = userdata.getHeaderAndLoc(filename)
	if err != nil {
		return
	}

	//Since Meta location is calculated using PrivKey of owner and MACKey for meta block hence non-owners will fail this check.
	hash := userlib.NewSHA256()
	hash.Write(dec(userdata.PrivKey))
	hash.Write(dec(header.MACKey))
	if !userlib.Equal(dec(header.Meta), hash.Sum(nil)) {
		return errors.New("You Are Not The Owner")
	}

	//Owner will load the file contents
	data, er := userdata.LoadFile(filename)
	if er != nil {
		return er
	}
	//Owner destroys previous meta
	userlib.DatastoreSet(header.Meta, []byte(""))

	//Owner stores the data in same name but generated MacKey will be different every time.
	//Hence location of meta will also be different.
	userdata.StoreFile(filename, data)

	return
}
