package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).
type User struct {
	Username string
	Password string
	EncryptedPassword []byte
	UUID uuid.UUID

	PublicKey userlib.PKEEncKey
	SecretKey userlib.PKEDecKey
	SignKey userlib.DSSignKey 
	VerifyKey userlib.DSVerifyKey

	FileMap map[string]uuid.UUID //or string //Filename Namespace of the User

}

type SymHmacKeyPair struct {
	SymmetricKey []byte
	HMACKey []byte
} 

type EncryptedPair struct {
	DataEncrypted    []byte
	DataSigned []byte
}

type FileInfo struct { // Meta data
	Owner *Node 
	NumAppend int
	FileKeys SymHmacKeyPair
	StartFile []byte
	FileDataUUIDList []uuid.UUID //Where the files are in order
}


type FileData struct{
	Data []byte
	NextFileUUID string
	NumInAppend int
	// Next FileKey ?
}

type Node struct{
	Username string
	Invite uuid.UUID
	Children []*Node
}

type Invite struct{
	FileInfoUUID uuid.UUID 
	AccessToken []byte //real token generated by owner when upon file creation
	isAccepted bool
	// FileInfoKey []byte
	// InviteKeys SymHmacKeyPair
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check Empty Username
	if ((username == "") || (len(username) == 0)) {
		return nil, errors.New("Username is Empty")
	}

	// Start init user
	var userdata User
	userdata.Username = username
	userdata.Password = password

	username_byte := []byte(username)
	password_byte := []byte(password)

	// Encrypt Username Hash(username||uuid||'user')
	username_to_hash := append(username_byte, []byte("uuid")...)
	user_uuid, err := uuid.FromBytes(userlib.Hash(username_to_hash)[:16])
	if (err != nil) {
		userlib.DebugMsg("Issue with creating user UUID")
		return nil, err
	}
	userdata.UUID = user_uuid
	user_uuid_byte := []byte(user_uuid.String())
	username_key := append(username_byte, user_uuid_byte...)
	username_key = append(username_key, []byte("user")...)
	username_hashed := userlib.Hash(username_key)

	// Generate RSA and DSign through username_hashed to put in KeyStore
	user_rsa_key, _ := userlib.HashKDF(username_hashed[:16], []byte("public"))
	user_sign_key, _ := userlib.HashKDF(username_hashed[:16], []byte("sig"))

	// Check if user exist through key store get 
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if has_user {
		return nil, errors.New("User already existed for" + string(username))
	}
	
	//Generate RSA Keys and store with username hbkdf(encrypted username, 'public') in keystore
	userdata.PublicKey, userdata.SecretKey, err = userlib.PKEKeyGen()
	if (err != nil) {
		return
	}
	userlib.KeystoreSet(string(user_rsa_key), userdata.PublicKey)

	//Generate Signatures and store with username hbkdf(encrypted username, 'sig') in keystore
	userdata.SignKey, userdata.VerifyKey, err = userlib.DSKeyGen()
	if (err != nil) {
		return
	}
	userlib.KeystoreSet(string(user_sign_key), userdata.VerifyKey)
	// Encrypt Password 
	password_encrypted := userlib.Argon2Key(password_byte, username_byte, 512)
	userdata.EncryptedPassword = password_encrypted

	// File Map
	userdata.FileMap = make(map[string]uuid.UUID)
	
	// Data Encryption Scheme to put into Datastore 
	sym_key := userlib.Argon2Key(password_encrypted, []byte("symmetric"), 16)
	hmac_key, _ := userlib.HashKDF(password_encrypted[:16], []byte("hmac")) // To Increase Check Effeciency  
	var key_pair SymHmacKeyPair
	key_pair.SymmetricKey = sym_key
	key_pair.HMACKey = hmac_key[:16]

	data_hash, _ := userlib.HashKDF(password_encrypted[:16], []byte("data")) // 64 length
	user_json, _ := json.Marshal(userdata)
	data_to_encrypt := append(user_json, data_hash...)
	data_encrypted_signed, err := DataEncryption(data_to_encrypt, key_pair)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(user_uuid, data_encrypted_signed)

	return &userdata, nil
}

func DataEncryption(data []byte, keys SymHmacKeyPair) (result []byte, err error) {
	sym_key := keys.SymmetricKey
	hmac_key := keys.HMACKey
	if len(sym_key) != 16 {
		return nil, errors.New("Symmetric Key Incorrect Length not 16")
	}
	if len(hmac_key) != 16 {
		return nil, errors.New("HMAC Key Incorrect Length not 16")
	}
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	data_encrypted := userlib.SymEnc(sym_key, iv, data)
	data_signed, err := userlib.HMACEval(hmac_key, data_encrypted)
	if err != nil {
		return nil, err
	}
	data_encrypted_signed := append(data_encrypted, data_signed...) // 64 length for signature
	var data_encrypt_sign_pair EncryptedPair
	data_encrypt_sign_pair.DataEncrypted = data_encrypted_signed
	data_encrypt_sign_pair.DataSigned = data_signed
	data_result, _ := json.Marshal(data_encrypt_sign_pair)
	return data_result, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if ((username == "") || (len(username) == 0)) {
		return nil, errors.New("Username is Empty")
	}
	username_byte := []byte(username)
	password_byte := []byte(password)
	
	// Get Username Hashed
	username_to_hash := append(username_byte, []byte("uuid")...)
	user_uuid, err := uuid.FromBytes(userlib.Hash(username_to_hash)[:16])
	if (err != nil) {
		userlib.DebugMsg("Issue with creating user UUID in Get User")
		return nil, err
	}
	user_uuid_byte := []byte(user_uuid.String())
	username_key := append(username_byte, user_uuid_byte...)
	username_key = append(username_key, []byte("user")...)
	// username_hashed := userlib.Hash(username_key)
	// Get Password Encrypted
	password_encrypted := userlib.Argon2Key(password_byte, username_byte, 512)

	user_data_encrypted, is_ok := userlib.DatastoreGet(user_uuid)
	if (!is_ok) {
		return nil, errors.New("Username generated UUID user data not in Data Store")
	}
	sym_key_check := userlib.Argon2Key(password_encrypted, []byte("symmetric"), 16)
	hmac_key_check, _ := userlib.HashKDF(password_encrypted[:16], []byte("hmac"))
	var key_pair_check SymHmacKeyPair
	key_pair_check.SymmetricKey = sym_key_check
	key_pair_check.HMACKey = hmac_key_check[:16]
	decrypted_user_data, err := DataDecryption(user_data_encrypted, key_pair_check)
	if err != nil {
		return
	}
	data_hash, _ := userlib.HashKDF(password_encrypted[:16], []byte("data")) // 64 length
	if (len(decrypted_user_data) < 64) {
		return nil, errors.New("decrypted_user_data too Short")
	}
	append_data_hash := decrypted_user_data[len(decrypted_user_data)-64:]
	if !(userlib.HMACEqual(append_data_hash, data_hash)) {
		return nil, errors.New("Appended data_hash is not valid, malicious attack")
	}
	decrypted_user := decrypted_user_data[:len(decrypted_user_data)-64]
	
	var userdata User
	userdataptr = &userdata
	json_err := json.Unmarshal(decrypted_user, userdataptr)
	if json_err != nil {
		return nil, json_err
	}
	//Should Never Happens
	if (userdataptr.Password != password) {
		return nil, errors.New("This should never fucking happens since we verfiy everything but password fucks up")
	}
	return userdataptr, nil
}

func DataDecryption(encrypted_data []byte, keys SymHmacKeyPair) (result []byte, err error){
	var data_pair EncryptedPair
	json_err := json.Unmarshal(encrypted_data, &data_pair)
	if json_err != nil {
		return nil, errors.New("Json Unmarhsall for Pair Data Error")
	}
	data_encrypted_signed := data_pair.DataEncrypted
	pair_signature := data_pair.DataSigned
	if (len(data_encrypted_signed) < 64) {
		return nil, errors.New("HMAC Signature too Short")
	}
	data_to_decrypt := data_encrypted_signed[:len(data_encrypted_signed)-64]
	hmac_sig, hmac_err := userlib.HMACEval(keys.HMACKey, data_to_decrypt)
	if hmac_err != nil {
		return nil, errors.New("HMAC Signature Generation Error")
	}
	if (!userlib.HMACEqual(pair_signature, hmac_sig)) {
		return nil, errors.New("HMAC Signature in pair data is not valid")
	}
	append_signature := data_encrypted_signed[len(data_encrypted_signed)-64:]
	if (!userlib.HMACEqual(append_signature, hmac_sig)) {
		return nil, errors.New("HMAC Signature in append data is not valid")
	}
	decrypted_data := userlib.SymDec(keys.SymmetricKey, data_to_decrypt)
	return decrypted_data, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Check if current user exist
	user_uuid, user_name_hashed, user_uh_err := UsernameHash(userdata.Username)
	_ = user_uh_err
	user_rsa_key, _ := userlib.HashKDF(user_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if !has_user {
		return errors.New("Current user does not exist, malicious user, Keystore check")
	}
	_, has_user_2 := userlib.DatastoreGet(user_uuid)
	if !has_user_2 {
		return errors.New("Current user does not exist, malicious user, Datastore check")
	}
	// Reload User Data
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return reload_user_err
	}
	// Call Get User on the username
	// Check if file exist under namespace 
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	invitationUUID, has_file := userdata.FileMap[filename_uuid_str]
	if has_file { //If the user has file, we get invitation and check, then overwrite the file, same access tho 
		// Decrypt Invite
		invite_encrypted, has_invite := userlib.DatastoreGet(invitationUUID)
		if !has_invite {
			return errors.New("Invitation not Founded in Data Store no File exist (Append)")
		}
		invite_json_byte, _, decrypt_invite_err := DecryptInvite(user_name_hashed, userdata.SecretKey, invite_encrypted)
		if decrypt_invite_err != nil {
			return decrypt_invite_err
		}
		var user_invite Invite
		invite_json_err := json.Unmarshal(invite_json_byte, &user_invite)
		if invite_json_err!= nil {
			return errors.New("json unMarshal error for invite")
		}

		// Decrypt FileInfo Metadata
		file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite.FileInfoUUID)
		if !has_file_info {
			return errors.New("File Info struct doesn't exist using invite")
		}
		access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfosym"))
		if access_sym_err != nil {
			return errors.New("File Info sym key gen error")
		}
		access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfohmac"))
		if access_hmac_err != nil {
			return errors.New("File Info hmac key gen error")
		}
		access_token_sym_key = access_token_sym_key[:16]
		access_token_hmac_key = access_token_hmac_key[:16]
		// Get metadata then use access token to unlock metadata
		var access_key_pair SymHmacKeyPair
		access_key_pair.SymmetricKey = access_token_sym_key
		access_key_pair.HMACKey = access_token_hmac_key
		
		decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
		if meta_err != nil {
			return meta_err
		}
		var metadata FileInfo
		meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
		if meta_json_err != nil {
			return errors.New("Json Unmarhsall for Meta File Info in Create Invite")
		}
		// New FileData
		metadata.NumAppend = 0
		file_content_start_loc_byte := userlib.RandomBytes(16)
		metadata.StartFile = file_content_start_loc_byte 
		filefirstUUID, _ := uuid.FromBytes((file_content_start_loc_byte))
		metadata.FileDataUUIDList = []uuid.UUID{filefirstUUID}

		var file_content FileData
		file_content.Data = content
		file_content.NextFileUUID = ""
		file_content.NumInAppend = 0
		file_content_json, file_content_json_err := json.Marshal(file_content)
		if file_content_json_err != nil {
			return file_content_json_err
		}
		file_content_encrypted_signed, file_content_enc_err := DataEncryption(file_content_json, metadata.FileKeys)
		if file_content_enc_err != nil {
			return file_content_enc_err
		}
		file_content_start_loc_byte = metadata.StartFile //metadata.FileDataUUIDList[0]
		file_content_loc_byte, loc_err := FileContentUUIDFromNumAppend(file_content_start_loc_byte, file_content.NumInAppend)
		if loc_err != nil {
			return loc_err
		}
		fileContentUUID, _ := uuid.FromBytes(file_content_loc_byte)
		if filefirstUUID != fileContentUUID {
			return errors.New("Shit! No way the two uuid is different")
		}
		if len(metadata.FileDataUUIDList) != (file_content.NumInAppend + 1) {
			return errors.New("FileUUIDList Mismatch Length in Append")
		}
		userlib.DatastoreSet(fileContentUUID, file_content_encrypted_signed)

		file_info_json, _ := json.Marshal(metadata)
		file_info_encrypted_signed, fi_enc_err := DataEncryption(file_info_json, access_key_pair)
		if fi_enc_err != nil {
			return fi_enc_err
		}
		userlib.DatastoreSet(user_invite.FileInfoUUID, file_info_encrypted_signed)
		return nil

	} else { // Create the fileinfo, ecnrypt content, and create invite for itself 
		// Create FileInfo
		var file_info_meta FileInfo
		selfInviteUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
		file_owner := &Node{userdata.Username, selfInviteUUID, make([]*Node, 0)}

		file_content_start_loc_byte := userlib.RandomBytes(16)
		file_info_meta.StartFile = file_content_start_loc_byte 
		//file_content_start_loc_str := string(file_content_start_loc_byte) //Convert to byte in future and generate UUID

		source_key := userlib.RandomBytes(16)
		file_sym_key, _ := userlib.HashKDF(source_key, []byte("file-content-sym"))
		file_sym_key = file_sym_key[:16]
		file_hmac_key, _ := userlib.HashKDF(source_key, []byte("file-content-hmac"))
		file_hmac_key = file_hmac_key[:16]
		file_keys := SymHmacKeyPair{file_sym_key, file_hmac_key}
		
		file_info_meta.Owner = file_owner
		file_info_meta.FileKeys = file_keys
		file_info_meta.NumAppend = 0
		filefirstUUID, _ := uuid.FromBytes((file_content_start_loc_byte))
		file_info_meta.FileDataUUIDList = []uuid.UUID{filefirstUUID}

		file_info_json, _ := json.Marshal(file_info_meta)

		// Encrypt FileInfo: Create sym and hmac
		invite_access_token := userlib.RandomBytes(16) // Generate the Access Token stored in Invitation 
		access_token_sym_key, access_sym_err := userlib.HashKDF(invite_access_token, []byte("fileinfosym"))
		if access_sym_err != nil {
			return errors.New("File Info sym key gen error")
		}
		access_token_hmac_key, access_hmac_err := userlib.HashKDF(invite_access_token, []byte("fileinfohmac"))
		if access_hmac_err != nil {
			return errors.New(strings.ToTitle("File Info hmac key gen error"))
		}
		access_token_sym_key = access_token_sym_key[:16]
		access_token_hmac_key = access_token_hmac_key[:16]
		var access_key_pair SymHmacKeyPair
		access_key_pair.SymmetricKey = access_token_sym_key
		access_key_pair.HMACKey = access_token_hmac_key
		file_info_encrypted_signed, fi_enc_err := DataEncryption(file_info_json, access_key_pair)
		if fi_enc_err != nil {
			return fi_enc_err
		}
		file_info_loc, file_info_loc_err := userlib.HashKDF(user_name_hashed[:16], []byte(filename))
		if file_info_loc_err != nil {
			return file_info_loc_err
		}
		file_info_loc_uuid, _ := uuid.FromBytes(file_info_loc[:16])
		userlib.DatastoreSet(file_info_loc_uuid, file_info_encrypted_signed)
		// Create and store invite
		var self_invite Invite
		self_invite.FileInfoUUID = file_info_loc_uuid
		self_invite.AccessToken = invite_access_token
		self_invite.isAccepted = true
		self_invite_byte, json_err := json.Marshal(self_invite)
		if json_err != nil {
			return json_err
		}
		self_invite_to_encrypt := append(self_invite_byte, user_name_hashed[:16]...)
		
		self_invite_encrypted, public_enc_err := userlib.PKEEnc(userdata.PublicKey, self_invite_to_encrypt)
		if public_enc_err != nil {
			//userlib.DebugMsg("There is an error in public encryption for creating self invitation: len %v", strconv.Itoa(len(self_invite_to_encrypt)))
			return public_enc_err
		}
		self_invite_encrypted_len := len(self_invite_encrypted) // Byte Length in int
		self_invite_hmac_key := userlib.Hash(append(user_name_hashed, []byte("invite")...))[:16] // To Increase Check Effeciency  
		self_invite_hmac_signature, hmac_err := userlib.HMACEval(self_invite_hmac_key, self_invite_encrypted)
		if hmac_err != nil {
			return hmac_err
		}
		self_invite_hmac_signed := append(self_invite_encrypted, self_invite_hmac_signature...) // new_invite_encrypted_len + 64
		self_user_len := len([]byte(userdata.Username)) // byte length in int
	
		self_invite_to_dssign := append(self_invite_hmac_signed, []byte(userdata.Username)...)
		self_invite_to_dssign = append(self_invite_to_dssign, []byte("e")...)
		self_invite_to_dssign = append(self_invite_to_dssign, []byte(strconv.Itoa(self_invite_encrypted_len))...)
		self_invite_to_dssign = append(self_invite_to_dssign, []byte("s")...)
		self_invite_to_dssign = append(self_invite_to_dssign, []byte(strconv.Itoa(self_user_len))...)	
		self_invite_dssigned, ds_err := userlib.DSSign(userdata.SignKey, self_invite_to_dssign) //the signature
		if ds_err != nil {
			return ds_err
		}
		self_invite_encrypted_signed := append(self_invite_to_dssign, self_invite_dssigned...)
		userlib.DatastoreSet(selfInviteUUID, self_invite_encrypted_signed)
		
		// Encrypt Content 
		var file_content FileData
		file_content.Data = content
		file_content.NextFileUUID = ""
		file_content.NumInAppend = 0
		file_content_json, file_content_json_err := json.Marshal(file_content)
		if file_content_json_err != nil {
			return file_content_json_err
		}
		file_content_encrypted_signed, file_content_enc_err := DataEncryption(file_content_json, file_keys)
		if file_content_enc_err != nil {
			return file_content_enc_err
		}
		file_content_loc_byte, _ := FileContentUUIDFromNumAppend(file_content_start_loc_byte, file_content.NumInAppend)
		fileContentUUID, _ := uuid.FromBytes((file_content_loc_byte))
		userlib.DatastoreSet(fileContentUUID, file_content_encrypted_signed)

		userdata.FileMap[filename_uuid_str] = selfInviteUUID
		// bs, _ := json.Marshal(userdata.FileMap)
    	// fmt.Println(string(bs))
		// Encrypt the user
		password_encrypted := userdata.EncryptedPassword
		sym_key := userlib.Argon2Key(password_encrypted, []byte("symmetric"), 16)
		hmac_key, _ := userlib.HashKDF(password_encrypted[:16], []byte("hmac")) // To Increase Check Effeciency  
		var key_pair SymHmacKeyPair
		key_pair.SymmetricKey = sym_key
		key_pair.HMACKey = hmac_key[:16]
		data_hash, _ := userlib.HashKDF(password_encrypted[:16], []byte("data")) // 64 length
		user_json, _ := json.Marshal(userdata)
		data_to_encrypt := append(user_json, data_hash...)
		data_encrypted_signed, err := DataEncryption(data_to_encrypt, key_pair)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(user_uuid, data_encrypted_signed)
		
		return nil
	}


}

func FileContentUUIDFromNumAppend(file_content_start_loc []byte, num_append int) (file_content_loc []byte, err error) {
	if len((file_content_start_loc)) != 16 {
		return nil, errors.New("Wrong start file loc string")
	}
	if num_append == 0 {
		return file_content_start_loc, nil
	}
	if num_append > 0 {
		new_file_content_loc, hash_err := userlib.HashKDF(file_content_start_loc, []byte(strconv.Itoa(num_append)))
		if hash_err != nil {
			return nil, hash_err
		}
		return (new_file_content_loc[20:36]), nil
	} else {
		return nil, errors.New("Invalid Num Append")
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Check User then Get User Data
	// Check if current user exist
	user_uuid, user_name_hashed, user_uh_err := UsernameHash(userdata.Username)
	_ = user_uh_err
	user_rsa_key, _ := userlib.HashKDF(user_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if !has_user {
		return errors.New("Current user does not exist, malicious user, Keystore check")
	}
	_, has_user_2 := userlib.DatastoreGet(user_uuid)
	if !has_user_2 {
		return errors.New("Current user does not exist, malicious user, Datastore check")
	}
	// Reload User Data
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return reload_user_err
	}
	// Valid filename
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	inviteUUID, has_file := userdata.FileMap[filename_uuid_str]
	if !has_file {
		return errors.New("Invitation not Founded in User File list for this filename in Append")
	}
	// Decrypt Invite
	invite_encrypted, has_invite := userlib.DatastoreGet(inviteUUID)
	if !has_invite {
		return errors.New("Invitation not Founded in Data Store no File exist (Append)")
	}
	invite_json_byte, _, decrypt_invite_err := DecryptInvite(user_name_hashed, userdata.SecretKey, invite_encrypted)
	if decrypt_invite_err != nil {
		return decrypt_invite_err
	}
	var user_invite Invite
	invite_json_err := json.Unmarshal(invite_json_byte, &user_invite)
	if invite_json_err!= nil {
		return errors.New("json unMarshal error for invite")
	}
	// Decrypt FileInfo Metadata
	file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite.FileInfoUUID)
	if !has_file_info {
		return errors.New("File Info struct doesn't exist using invite")
	}
	access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfosym"))
	if access_sym_err != nil {
		return errors.New("File Info sym key gen error")
	}
	access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfohmac"))
	if access_hmac_err != nil {
		return errors.New("File Info hmac key gen error")
	}
	access_token_sym_key = access_token_sym_key[:16]
	access_token_hmac_key = access_token_hmac_key[:16]
	// Get metadata then use access token to unlock metadata
	var access_key_pair SymHmacKeyPair
	access_key_pair.SymmetricKey = access_token_sym_key
	access_key_pair.HMACKey = access_token_hmac_key
	
	decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
	if meta_err != nil {
		return meta_err
	}
	var metadata FileInfo
	meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
	if meta_json_err != nil {
		return errors.New("Json Unmarhsall for Meta File Info in Create Invite")
	}
	// Finally Ready to Append File
	// Encrypt New Content
	var file_content FileData
	file_content.Data = content
	file_content.NextFileUUID = ""
	file_content.NumInAppend = metadata.NumAppend + 1
	file_content_json, file_content_json_err := json.Marshal(file_content)
	if file_content_json_err != nil {
		return file_content_json_err
	}
	file_content_encrypted_signed, file_content_enc_err := DataEncryption(file_content_json, metadata.FileKeys)
	if file_content_enc_err != nil {
		return file_content_enc_err
	}
	file_content_start_loc_byte := metadata.StartFile //metadata.FileDataUUIDList[0]
	file_content_loc_byte, loc_err := FileContentUUIDFromNumAppend(file_content_start_loc_byte, file_content.NumInAppend)
	if loc_err != nil {
		return loc_err
	}
	fileContentUUID, _ := uuid.FromBytes(file_content_loc_byte)
	metadata.FileDataUUIDList = append(metadata.FileDataUUIDList, fileContentUUID)
	if len(metadata.FileDataUUIDList) != (file_content.NumInAppend + 1) {
		return errors.New("FileUUIDList Mismatch Length in Append")
	}
	userlib.DatastoreSet(fileContentUUID, file_content_encrypted_signed)
	metadata.NumAppend = metadata.NumAppend + 1

	// Re-encrypt MetaData
	// invite_access_token := user_invite.AccessToken
	// access_token_sym_key, access_sym_err := userlib.HashKDF(invite_access_token, []byte("fileinfosym"))
	// if access_sym_err != nil {
	// 	return errors.New("File Info sym key gen error")
	// }
	// access_token_hmac_key, access_hmac_err := userlib.HashKDF(invite_access_token, []byte("fileinfohmac"))
	// if access_hmac_err != nil {
	// 	return errors.New("File Info hmac key gen error")
	// }
	// access_token_sym_key = access_token_sym_key[:16]
	// access_token_hmac_key = access_token_hmac_key[:16]
	// var access_key_pair SymHmacKeyPair
	// access_key_pair.SymmetricKey = access_token_sym_key
	// access_key_pair.HMACKey = access_token_hmac_key
	file_info_json, _ := json.Marshal(metadata)
	file_info_encrypted_signed, fi_enc_err := DataEncryption(file_info_json, access_key_pair)
	if fi_enc_err != nil {
		return fi_enc_err
	}
	userlib.DatastoreSet(user_invite.FileInfoUUID, file_info_encrypted_signed)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	user_uuid, user_name_hashed, user_uh_err := UsernameHash(userdata.Username)
	_ = user_uh_err
	user_rsa_key, _ := userlib.HashKDF(user_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if !has_user {
		return nil, errors.New("Current user does not exist, malicious user, Keystore check")
	}
	_, has_user_2 := userlib.DatastoreGet(user_uuid)
	if !has_user_2 {
		return nil, errors.New("Current user does not exist, malicious user, Datastore check")
	}
	// Reload User Data
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return nil, reload_user_err
	}
	// Valid filename
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	inviteUUID, has_file := userdata.FileMap[filename_uuid_str]
	if !has_file {
		return nil, errors.New("Invitation not Founded in User File list for this filename in Append")
	}
	// Decrypt Invite
	invite_encrypted, has_invite := userlib.DatastoreGet(inviteUUID)
	if !has_invite {
		return nil, errors.New("Invitation not Founded in Data Store no File exist (Append)")
	}
	invite_json_byte, _, decrypt_invite_err := DecryptInvite(user_name_hashed, userdata.SecretKey, invite_encrypted)
	if decrypt_invite_err != nil {
		return nil, decrypt_invite_err
	}
	var user_invite Invite
	invite_json_err := json.Unmarshal(invite_json_byte, &user_invite)
	if invite_json_err!= nil {
		return nil, errors.New("json unMarshal error for invite")
	}
	// Decrypt FileInfo Metadata
	file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite.FileInfoUUID)
	if !has_file_info {
		return nil, errors.New("File Info struct doesn't exist using invite")
	}
	access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfosym"))
	if access_sym_err != nil {
		return nil, errors.New("File Info sym key gen error")
	}
	access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfohmac"))
	if access_hmac_err != nil {
		return nil, errors.New("File Info hmac key gen error")
	}
	access_token_sym_key = access_token_sym_key[:16]
	access_token_hmac_key = access_token_hmac_key[:16]
	// Get metadata then use access token to unlock metadata
	var access_key_pair SymHmacKeyPair
	access_key_pair.SymmetricKey = access_token_sym_key
	access_key_pair.HMACKey = access_token_hmac_key
	
	decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
	if meta_err != nil {
		return nil, meta_err
	}
	var metadata FileInfo
	meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
	if meta_json_err != nil {
		return nil, errors.New("Json Unmarhsall for Meta File Info in Create Invite")
	}
	// Generate Result content
	var result_content []byte
	if metadata.NumAppend + 1 != len(metadata.FileDataUUIDList) {
		return nil, errors.New("Possible malicious struct data length mismatch")
	}
	result_content = make([]byte, 0)
	for i := 0; i <= metadata.NumAppend; i++ {
		file_content_loc_byte, uuid_from_append_err := FileContentUUIDFromNumAppend(metadata.StartFile, i)
		file_content_UUID, _ := uuid.FromBytes(file_content_loc_byte)
		if uuid_from_append_err != nil {
			return nil, uuid_from_append_err
		}
		if metadata.FileDataUUIDList[i] != file_content_UUID {
			return nil, errors.New("Wtf how is UUID Mismatch, mal attack?")
		}
		file_content_encrypted_signed, has_file_content := userlib.DatastoreGet(file_content_UUID)
		if !has_file_content {
			return nil, errors.New("Datastoreunder attack?, has not file content")
		}
		decrypted_file_content_data, file_content_err := DataDecryption(file_content_encrypted_signed, metadata.FileKeys)
		if file_content_err != nil {
			return nil, file_content_err
		}
		var current_file_content_decrypted FileData
		file_content_json_err := json.Unmarshal(decrypted_file_content_data, &current_file_content_decrypted)
		if file_content_json_err != nil {
			return nil, errors.New("Json Unmarshall error for decrypted file content")
		}
		if (current_file_content_decrypted.NumInAppend != i) {
			return nil, errors.New("Datastore under attack?, decrypted file content append num is diff")
		}
		result_content = append(result_content, current_file_content_decrypted.Data...)
	}
	return result_content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	nil_UUID, _ := uuid.FromBytes(userlib.Hash([]byte("Nil UUID"))[:16])
	// Check if the current user is malicious  by using it's username to get keystore public key and verify it exist
	sender_uuid, sender_name_hashed, send_uh_err := UsernameHash(userdata.Username)
	_ = send_uh_err 
	sender_rsa_key, _ := userlib.HashKDF(sender_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(sender_rsa_key))
	if !has_user {
		return nil_UUID, errors.New("Sender user does not exist, malicious user")
	}
	_, has_user_2 := userlib.DatastoreGet(sender_uuid)
	if !has_user_2 {
		return nil_UUID, errors.New("Current sender user does not exist, malicious user, Datastore check")
	}
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return nil_UUID, reload_user_err
	}
	// Generate File UUID by Sender sender's namespace filename -> it's own fileuuid
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	// Retreive if user has this file
	// bs, _ := json.Marshal(userdata.FileMap)
    // fmt.Println(string(bs))
	inviteUUID, has_file := userdata.FileMap[filename_uuid_str]
	if !has_file {
		return nil_UUID, errors.New("Invitation not Founded in User File list from this filename")
	}
	// Check the invitation is valid by undecrypting its invite and check isAccepted
	invite_encrypted, has_invite := userlib.DatastoreGet(inviteUUID)
	if !has_invite {
		return nil_UUID, errors.New("Invitation not Founded in Data Store no File exist")
	}
	// Decrypt invite: (RSAEncrypt(json(invite)||reciever_username_hash)|| HMACSignature)|| sender_username || 'sender'
	invite_json_byte, _, decrypt_invite_err := DecryptInvite(sender_name_hashed, userdata.SecretKey, invite_encrypted)
	if decrypt_invite_err != nil {
		return nil_UUID, decrypt_invite_err
	}
	var user_invite_check Invite
	invite_json_err := json.Unmarshal(invite_json_byte, &user_invite_check)
	if invite_json_err!= nil {
		return nil_UUID, errors.New("json unMarshal error for invite")
	}
	// check if the invitedata is also correct to see if it can decrpyt meta data
	// if !user_invite_check.isAccepted {
	// 	return nil_UUID, errors.New("How is is Accepted not true, invitation scheme has error")
	// }
	// Generate Keys to decrypt FileInfo
	file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite_check.FileInfoUUID)
	if !has_file_info {
		return nil_UUID, errors.New("File Info struct doesn't exist using invite")
	}

	access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite_check.AccessToken, []byte("fileinfosym"))
	if access_sym_err != nil {
		return nil_UUID, errors.New("File Info sym key gen error")
	}
	access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite_check.AccessToken, []byte("fileinfohmac"))
	if access_hmac_err != nil {
		return nil_UUID, errors.New("File Info hmac key gen error")
	}
	access_token_sym_key = access_token_sym_key[:16]
	access_token_hmac_key = access_token_hmac_key[:16]
	// Get metadata then use access token to unlock metadata
	var access_key_pair SymHmacKeyPair
	access_key_pair.SymmetricKey = access_token_sym_key
	access_key_pair.HMACKey = access_token_hmac_key
	
	decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
	if meta_err != nil {
		return nil_UUID, meta_err
	}
	var metadata FileInfo
	meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
	if meta_json_err != nil {
		return nil_UUID, errors.New("Json Unmarhsall for Meta File Info in Create Invite")
	}
	// Recipient Info
	recipient_uuid, recipient_name_hashed, rec_uh_err :=  UsernameHash(recipientUsername)
	_= rec_uh_err
	recipient_rsa_key, _ := userlib.HashKDF(recipient_name_hashed[:16], []byte("public"))
	// Check recipient and Get Recipient Public Encryption Key
	recipient_public_key, has_recipient := userlib.KeystoreGet(string(recipient_rsa_key))
	if !has_recipient {
		return nil_UUID, errors.New("User does not exist in key store to create invite")
	}
	_, has_recipient_2 := userlib.DatastoreGet(recipient_uuid)
	if !has_recipient_2 {
		return nil_UUID, errors.New("Current receive user does not exist, malicious user, Datastore check")
	}

	// Start Invite Creation
	var new_invite Invite
	new_invite.FileInfoUUID = user_invite_check.FileInfoUUID
	new_invite.AccessToken = user_invite_check.AccessToken
	new_invite.isAccepted = false
	// above is data from invite struct
	new_invite_byte, json_err := json.Marshal(new_invite)
	if json_err != nil {
		return nil_UUID, json_err
	}
	new_invite_to_encrypt := append(new_invite_byte, recipient_name_hashed[:16]...)
	new_invite_encrypted, public_enc_err := userlib.PKEEnc(recipient_public_key, new_invite_to_encrypt)
	if public_enc_err != nil {
		userlib.DebugMsg("There is an error in public encryption for creating new invitation")
		return nil_UUID, public_enc_err
	}
	new_invite_encrypted_len := len(new_invite_encrypted) // Byte Length in int
	recipient_invite_hmac_key := userlib.Hash(append(recipient_name_hashed, []byte("invite")...))[:16] // To Increase Check Effeciency  
	new_invite_hmac_signature, hmac_err := userlib.HMACEval(recipient_invite_hmac_key, new_invite_encrypted)
	if hmac_err != nil {
		return nil_UUID, hmac_err
	}
	new_invite_hmac_signed := append(new_invite_encrypted, new_invite_hmac_signature...) // new_invite_encrypted_len + 64
	sender_user_len := len([]byte(userdata.Username)) // byte length in int

	new_invite_to_dssign := append(new_invite_hmac_signed, []byte(userdata.Username)...)
	new_invite_to_dssign = append(new_invite_to_dssign, []byte("e")...)
	new_invite_to_dssign = append(new_invite_to_dssign, []byte(strconv.Itoa(new_invite_encrypted_len))...)
	new_invite_to_dssign = append(new_invite_to_dssign, []byte("s")...)
	new_invite_to_dssign = append(new_invite_to_dssign, []byte(strconv.Itoa(sender_user_len))...)	
	new_invite_dssigned, ds_err := userlib.DSSign(userdata.SignKey, new_invite_to_dssign) //the signature
	if ds_err != nil {
		return nil_UUID, ds_err
	}
	new_invite_encrypted_signed := append(new_invite_to_dssign, new_invite_dssigned...)
	newInviteUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
	userlib.DatastoreSet(newInviteUUID, new_invite_encrypted_signed)

	// Change Tree
	child_node := &Node{recipientUsername, invitationPtr, make([]*Node, 0)}
	var tree_child_err error
	metadata.Owner, tree_child_err = TreeAddChild(metadata.Owner, child_node, userdata.Username)
	if tree_child_err != nil {
		return nil_UUID, errors.New("Error when Adding Node to Tree")
	}
	// Encrypt File Info
	file_info_json, _ := json.Marshal(metadata)
	file_info_encrypted_signed, fi_enc_err := DataEncryption(file_info_json, access_key_pair)
	if fi_enc_err != nil {
		return nil_UUID, fi_enc_err
	}
	userlib.DatastoreSet(user_invite_check.FileInfoUUID, file_info_encrypted_signed)
	
	// End Invite Creation
	// Change Sharing Tree Structure When they accept invite 
	return newInviteUUID, nil
}

func DecryptInvite(receiver_username_hashed []byte, recipient_private_key userlib.PKEDecKey, invite []byte) (result []byte, sender_un_hash []byte, err error) {
	if len(invite) < 256 {
		return nil, nil, errors.New("Digital Signature not long enough")
	}
	ds_sig := invite[(len(invite)-256):]
	invite_without_ds := invite[:(len(invite)-256)]
	sender_user_len := 0 
	sender_username := ""
	encrypted_data_len := 0
	s_index := 0
	e_index := 0
	var s_err, e_err error
	for i := len(invite_without_ds) - 1; i >= 0; i-- {
		if string(invite_without_ds[i]) == "s" {
			sender_user_len, s_err = strconv.Atoi(string(invite_without_ds[i+1:]))
			if s_err != nil {
				return nil, nil, errors.New("Error Obtaining sender length")
			}
			s_index = i
		}
		if string(invite_without_ds[i]) == "e" {
			if i < s_index {
				encrypted_data_len, e_err = strconv.Atoi(string(invite_without_ds[i+1 : s_index]))
				if e_err != nil {
					return nil, nil, errors.New("Error Obtaining encrypted length, first error")
				}
				e_index = i
				break
			} else {
				return nil, nil, errors.New("Error Obtaining encrypted length, second error")
			}
		}
	}
	if (sender_user_len == 0 || encrypted_data_len == 0) {
		return nil, nil, errors.New("Error Obtaining encrypted length, for loop")
	}
	invite_encrypted_rsa := invite_without_ds[:encrypted_data_len]
	invite_hmac_sig := invite_without_ds[encrypted_data_len:encrypted_data_len+64]
	sender_username_byte := invite_without_ds[encrypted_data_len+64:e_index]
	if (e_index - (encrypted_data_len+64)) != sender_user_len {
		return nil, nil, errors.New("Error Obtaining encrypted length, for loop")
	}
	sender_username = string(sender_username_byte)
	sender_uuid, sender_name_hashed, send_uh_err := UsernameHash(sender_username)
	_ = send_uh_err
	sender_ds_key, _ := userlib.HashKDF(sender_name_hashed[:16], []byte("sig"))
	sender_verify_key, has_user := userlib.KeystoreGet(string(sender_ds_key))
	if !has_user {
		return nil, nil, errors.New("Sender user does not exist, malicious user")
	}
	_, has_user_2 := userlib.DatastoreGet(sender_uuid)
	if !has_user_2 {
		return nil, nil, errors.New("Current sending user does not exist, malicious user, Datastore check")
	}
	// Verify DS Signature 
	ds_sig_err := userlib.DSVerify(sender_verify_key, invite_without_ds, ds_sig)
	if ds_sig_err != nil {
		return nil, nil, ds_sig_err
	}
	// Verfiy HMAC
	recipient_invite_hmac_key := userlib.Hash(append(receiver_username_hashed, []byte("invite")...))[:16] 
	recipient_hmac_signature, hmac_err := userlib.HMACEval(recipient_invite_hmac_key, invite_encrypted_rsa)
	if hmac_err != nil {
		return nil, nil, hmac_err
	}
	is_hmac_equal := userlib.HMACEqual(recipient_hmac_signature, invite_hmac_sig)
	if !is_hmac_equal {
		return nil, nil, errors.New("hmac signature not equal when decrypt invite")
	}
	// Decrypt RSA
	invitation_decrypted, rsa_err := userlib.PKEDec(recipient_private_key, invite_encrypted_rsa)
	if rsa_err != nil {
		return nil, nil, errors.New("rsa decryption error in invite decryption")
	}
	// Final check of username hash
	receiver_hash_appended := invitation_decrypted[len(invitation_decrypted)-16:]
	is_receiver := userlib.HMACEqual(receiver_username_hashed[:16], receiver_hash_appended)	
	if !is_receiver {
		return nil, nil, errors.New("Final usernamehash not equal, like wtf?!")
	}
	result = invitation_decrypted[:len(invitation_decrypted)-16]
	return result, sender_name_hashed, nil
}



// Decrypt Invite
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// Check if current user is malicious 
	user_uuid, user_name_hashed, user_uh_err := UsernameHash(userdata.Username)
	_, _ = user_uuid, user_uh_err
	user_rsa_key, _ := userlib.HashKDF(user_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if !has_user {
		return errors.New("Current user does not exist, malicious user")
	}
	_, has_user_2 := userlib.DatastoreGet(user_uuid)
	if !has_user_2 {
		return errors.New("Current receive user does not exist, malicious user, Datastore check")
	}
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return reload_user_err
	}
	// Valid filename
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	_, has_file := userdata.FileMap[filename_uuid_str]
	if has_file {
		return errors.New("This filename already exist in the name space")
	}
	// Check if sender user exist and if it's malicious
	sender_uuid, sender_name_hashed, send_uh_err := UsernameHash(senderUsername)
	_ = send_uh_err 
	sender_rsa_key, _ := userlib.HashKDF(sender_name_hashed[:16], []byte("public"))
	_, has_sender := userlib.KeystoreGet(string(sender_rsa_key))
	if !has_sender {
		return errors.New("Sender user does not exist, malicious user, cannot accept invite")
	}
	_, has_sender_2 := userlib.DatastoreGet(sender_uuid)
	if !has_sender_2 {
		return errors.New("Current receive user does not exist, malicious user, Datastore check")
	}
	// Get the invitation and verfy to see if it's actually from sender
	invite_encrypted, has_invite := userlib.DatastoreGet(invitationPtr)
	if !has_invite {
		return errors.New("Invitation not Founded in Data Store no File exist")
	}
	invite_json_byte, sender_hashed_from_invite, decrypt_invite_err := DecryptInvite(user_name_hashed, userdata.SecretKey, invite_encrypted)
	if decrypt_invite_err != nil {
		return decrypt_invite_err
	}
	is_sender_equal := userlib.HMACEqual(sender_name_hashed, sender_hashed_from_invite)
	if !is_sender_equal {
		return errors.New("Sender Mismatch from the given sender vs in invitation")
	}
	var user_invite Invite
	invite_json_err := json.Unmarshal(invite_json_byte, &user_invite)
	if invite_json_err != nil {
		return errors.New("Json Unmarshall error for Invite, despite we don't need to decrypt it, and error shouldn't happen")
	}
	
	file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite.FileInfoUUID)
	if !has_file_info {
		return errors.New("File Info struct doesn't exist using invite")
	}

	access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfosym"))
	if access_sym_err != nil {
		return errors.New("File Info sym key gen error")
	}
	access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfohmac"))
	if access_hmac_err != nil {
		return errors.New("File Info hmac key gen error")
	}
	access_token_sym_key = access_token_sym_key[:16]
	access_token_hmac_key = access_token_hmac_key[:16]
	// Get metadata then use access token to unlock metadata
	var access_key_pair SymHmacKeyPair
	access_key_pair.SymmetricKey = access_token_sym_key
	access_key_pair.HMACKey = access_token_hmac_key
	
	decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
	if meta_err != nil {
		return meta_err
	}
	var metadata FileInfo
	meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
	if meta_json_err != nil {
		return errors.New("Json Unmarhsall for Meta File Info in Create Invite")
	}

	// Give the user the file in itself
	userdata.FileMap[filename_uuid_str] = invitationPtr
	// Encrypt the user
	password_encrypted := userdata.EncryptedPassword
	sym_key := userlib.Argon2Key(password_encrypted, []byte("symmetric"), 16)
	hmac_key, _ := userlib.HashKDF(password_encrypted[:16], []byte("hmac")) // To Increase Check Effeciency  
	var key_pair SymHmacKeyPair
	key_pair.SymmetricKey = sym_key
	key_pair.HMACKey = hmac_key[:16]
	data_hash, _ := userlib.HashKDF(password_encrypted[:16], []byte("data")) // 64 length
	user_json, _ := json.Marshal(userdata)
	data_to_encrypt := append(user_json, data_hash...)
	data_encrypted_signed, err := DataEncryption(data_to_encrypt, key_pair)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(user_uuid, data_encrypted_signed)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Check if current user is malicious 
	user_uuid, user_name_hashed, user_uh_err := UsernameHash(userdata.Username)
	_, _ = user_uuid, user_uh_err
	user_rsa_key, _ := userlib.HashKDF(user_name_hashed[:16], []byte("public"))
	_, has_user := userlib.KeystoreGet(string(user_rsa_key))
	if !has_user {
		return errors.New("Current user does not exist, malicious user")
	}
	_, has_user_2 := userlib.DatastoreGet(user_uuid)
	if !has_user_2 {
		return errors.New("Current receive user does not exist, malicious user, Datastore check")
	}
	var reload_user_err error
	userdata, reload_user_err = GetUser(userdata.Username, userdata.Password)
	if reload_user_err != nil {
		return reload_user_err
	}
	// Check if user has file
	// Recipient Info
	recipient_uuid, recipient_name_hashed, rec_uh_err :=  UsernameHash(recipientUsername)
	_= rec_uh_err
	recipient_rsa_key, _ := userlib.HashKDF(recipient_name_hashed[:16], []byte("public"))
	// Check recipient and Get Recipient Public Encryption Key
	recipient_public_key, has_recipient := userlib.KeystoreGet(string(recipient_rsa_key))
	_ = recipient_public_key
	if !has_recipient {
		return errors.New("User does not exist in key store to create invite")
	}
	_, has_recipient_2 := userlib.DatastoreGet(recipient_uuid)
	if !has_recipient_2 {
		return errors.New("Current receive user does not exist, malicious user, Datastore check")
	}
	// Valid filename
	filename_byte := []byte(filename)
	filename_to_hash := append(filename_byte, []byte("uuid")...)
	filename_uuid, _ := (uuid.FromBytes(userlib.Hash(filename_to_hash)[:16]))
	filename_uuid_str := filename_uuid.String()
	inviteUUID, has_file := userdata.FileMap[filename_uuid_str]
	if !has_file {
		return errors.New("Invitation not Founded in User File list for this filename in Append")
	}
	// Decrpyt Invite and Meta
	invite_encrypted, has_invite := userlib.DatastoreGet(inviteUUID)
	if !has_invite {
		return errors.New("Invitation not Founded in Data Store no File exist (Append)")
	}
	invite_json_byte, _, decrypt_invite_err := DecryptInvite(user_name_hashed, userdata.SecretKey, invite_encrypted)
	if decrypt_invite_err != nil {
		return decrypt_invite_err
	}
	var user_invite Invite
	invite_json_err := json.Unmarshal(invite_json_byte, &user_invite)
	if invite_json_err!= nil {
		return errors.New("json unMarshal error for invite")
	}
	// Decrypt FileInfo Metadata
	old_file_info_loc := user_invite.FileInfoUUID
	file_info_encrypted, has_file_info := userlib.DatastoreGet(user_invite.FileInfoUUID)
	if !has_file_info {
		return errors.New("File Info struct doesn't exist using invite")
	}
	access_token_sym_key, access_sym_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfosym"))
	if access_sym_err != nil {
		return errors.New("File Info sym key gen error")
	}
	access_token_hmac_key, access_hmac_err := userlib.HashKDF(user_invite.AccessToken, []byte("fileinfohmac"))
	if access_hmac_err != nil {
		return errors.New("File Info hmac key gen error")
	}
	access_token_sym_key = access_token_sym_key[:16]
	access_token_hmac_key = access_token_hmac_key[:16]
	// Get metadata then use access token to unlock metadata
	var access_key_pair SymHmacKeyPair
	access_key_pair.SymmetricKey = access_token_sym_key
	access_key_pair.HMACKey = access_token_hmac_key
	
	decrypted_fileinfo_data, meta_err := DataDecryption(file_info_encrypted, access_key_pair)
	if meta_err != nil {
		return meta_err
	}
	var metadata FileInfo
	meta_json_err := json.Unmarshal(decrypted_fileinfo_data, &metadata)
	if meta_json_err != nil {
		return errors.New("Json Unmarhsall for Meta File Info in Create Invite")
	}
	if (userdata.Username != metadata.Owner.Username) {
		return errors.New("You are not the owner of the file, cannot revoke")
	}
	has_direct_child := ChildLocation(metadata.Owner.Children, recipientUsername)
	if has_direct_child == -1 {
		return errors.New("The recipient is not you direct child, cannot revoke, making life easier")
	}
	var remove_err error
	metadata.Owner, remove_err = RemoveDirectChild(metadata.Owner, recipientUsername)
	if remove_err != nil {
		return errors.New("Erro removing child, should not happen")
	}
	// Re-encrypt all file content
	old_start_file := metadata.StartFile
	old_file_keys := metadata.FileKeys
	file_content_start_loc_byte := userlib.RandomBytes(16)
	metadata.StartFile = file_content_start_loc_byte

	new_source_key := userlib.RandomBytes(16)
	new_file_sym_key, _ := userlib.HashKDF(new_source_key, []byte("file-content-sym"))
	new_file_sym_key = new_file_sym_key[:16]
	new_file_hmac_key, _ := userlib.HashKDF(new_source_key, []byte("file-content-hmac"))
	new_file_hmac_key = new_file_hmac_key[:16]
	new_file_keys := SymHmacKeyPair{new_file_sym_key, new_file_hmac_key}
	metadata.FileKeys = new_file_keys
	filefirstUUID, _ := uuid.FromBytes((file_content_start_loc_byte))
	_ = filefirstUUID
	for i:=0; i <= metadata.NumAppend; i++ {
		file_content_loc_byte, uuid_from_append_err := FileContentUUIDFromNumAppend(old_start_file, i)
		file_content_UUID, _ := uuid.FromBytes(file_content_loc_byte)
		if uuid_from_append_err != nil {
			return uuid_from_append_err
		}
		file_content_encrypted_signed, has_file_content := userlib.DatastoreGet(file_content_UUID)
		if !has_file_content {
			return errors.New("Datastoreunder attack?, has not file content")
		}
		decrypted_file_content_data, file_content_err := DataDecryption(file_content_encrypted_signed, old_file_keys)
		if file_content_err != nil {
			return file_content_err
		}
		var current_file_content_decrypted FileData
		file_content_json_err := json.Unmarshal(decrypted_file_content_data, &current_file_content_decrypted)
		if file_content_json_err != nil {
			return errors.New("Json Unmarshall error for decrypted file content")
		}
		if (current_file_content_decrypted.NumInAppend != i) {
			return errors.New("Datastore under attack?, decrypted file content append num is diff")
		}
		file_content_json, file_content_json_err_2 := json.Marshal(current_file_content_decrypted)
		if file_content_json_err_2 != nil {
			return file_content_json_err_2
		}
		file_content_encrypted_signed, file_content_enc_err := DataEncryption(file_content_json, metadata.FileKeys)
		if file_content_enc_err != nil {
			return file_content_enc_err
		}
		file_content_start_loc_byte := metadata.StartFile //metadata.FileDataUUIDList[0]
		file_content_loc_byte, loc_err := FileContentUUIDFromNumAppend(file_content_start_loc_byte, current_file_content_decrypted.NumInAppend)
		if loc_err != nil {
			return loc_err
		}
		fileContentUUID, _ := uuid.FromBytes(file_content_loc_byte)
		metadata.FileDataUUIDList[i] = fileContentUUID
		userlib.DatastoreSet(fileContentUUID, file_content_encrypted_signed)
	}
	// Re-create all invites 
	// Create a new self invite to the same FileInfo
	file_info_json, _ := json.Marshal(metadata)
	new_invite_access_token := userlib.RandomBytes(16) // Generate the Access Token stored in Invitation 
	
	new_access_token_sym_key, new_access_sym_err := userlib.HashKDF(new_invite_access_token, []byte("fileinfosym"))
	if new_access_sym_err != nil {
		return errors.New("File Info sym key gen error")
	}
	new_access_token_hmac_key, new_access_hmac_err := userlib.HashKDF(new_invite_access_token, []byte("fileinfohmac"))
	if new_access_hmac_err != nil {
		return errors.New(strings.ToTitle("File Info hmac key gen error"))
	}
	new_access_token_sym_key = new_access_token_sym_key[:16]
	new_access_token_hmac_key = new_access_token_hmac_key[:16]
	var new_access_key_pair SymHmacKeyPair
	new_access_key_pair.SymmetricKey = new_access_token_sym_key
	new_access_key_pair.HMACKey = new_access_token_hmac_key
	new_file_info_encrypted_signed, new_fi_enc_err := DataEncryption(file_info_json, new_access_key_pair)
	if new_fi_enc_err != nil {
		return new_fi_enc_err
	}
	new_file_info_loc, new_file_info_loc_err := userlib.HashKDF(user_name_hashed[:16], append([]byte(filename), userlib.RandomBytes(10)...))
	if new_file_info_loc_err != nil {
		return new_file_info_loc_err
	}
	new_file_info_loc_uuid, _ := uuid.FromBytes(new_file_info_loc[:16])
	userlib.DatastoreSet(new_file_info_loc_uuid, new_file_info_encrypted_signed)
	userlib.DatastoreDelete(old_file_info_loc)
	// user has to update thos invite locations
	new_invite := Invite{new_file_info_loc_uuid, new_invite_access_token, true}
	new_invite_json, new_invite_json_err := json.Marshal(new_invite)
	if new_invite_json_err != nil {
		return errors.New("Error when creating json for new invite")
	}

	recreating_err := userdata.RecreateInvites(metadata.Owner, new_invite_json)
	if recreating_err != nil {
		return recreating_err
	}
	return nil
}


func (userdata *User) RecreateInvites(tree *Node, newInvite []byte) (err error) {
	var bfs_queue []*Node
	owner_username := tree.Username
    bfs_queue = append(bfs_queue, tree)
    for len(bfs_queue) > 0 {
        node := bfs_queue[0]
		// Encrypt invites and put them
		recipient_uuid, recipient_name_hashed, rec_uh_err :=  UsernameHash(node.Username)
		_, _ = recipient_uuid, rec_uh_err
		recipient_rsa_key, _ := userlib.HashKDF(recipient_name_hashed[:16], []byte("public"))
		recipient_public_key, has_recipient := userlib.KeystoreGet(string(recipient_rsa_key))
		if !has_recipient {
			return errors.New("User does not exist in key store to recreate invite")
		}
		new_invite_to_encrypt := append(newInvite, recipient_name_hashed[:16]...)
		new_invite_encrypted, public_enc_err := userlib.PKEEnc(recipient_public_key, new_invite_to_encrypt)
		if public_enc_err != nil {
			userlib.DebugMsg("There is an error in public encryption for creating new invitation")
			return public_enc_err
		}
		new_invite_encrypted_len := len(new_invite_encrypted) // Byte Length in int
		recipient_invite_hmac_key := userlib.Hash(append(recipient_name_hashed, []byte("invite")...))[:16] // To Increase Check Effeciency  
		new_invite_hmac_signature, hmac_err := userlib.HMACEval(recipient_invite_hmac_key, new_invite_encrypted)
		if hmac_err != nil {
			return hmac_err
		}
		new_invite_hmac_signed := append(new_invite_encrypted, new_invite_hmac_signature...) // new_invite_encrypted_len + 64
		sender_user_len := len([]byte(owner_username)) // byte length in int
		
		new_invite_to_dssign := append(new_invite_hmac_signed, []byte(owner_username)...)
		new_invite_to_dssign = append(new_invite_to_dssign, []byte("e")...)
		new_invite_to_dssign = append(new_invite_to_dssign, []byte(strconv.Itoa(new_invite_encrypted_len))...)
		new_invite_to_dssign = append(new_invite_to_dssign, []byte("s")...)
		new_invite_to_dssign = append(new_invite_to_dssign, []byte(strconv.Itoa(sender_user_len))...)

		new_invite_dssigned, ds_err := userlib.DSSign(userdata.SignKey, new_invite_to_dssign) //the signature
		if ds_err != nil {
			return ds_err
		}
		new_invite_encrypted_signed := append(new_invite_to_dssign, new_invite_dssigned...)
		userlib.DatastoreSet(node.Invite, new_invite_encrypted_signed)
        

		// Visiting Rest of the tree
        for i := 0; i < len(node.Children); i++ {
            bfs_queue = append(bfs_queue, node.Children[i])
        }
        bfs_queue = bfs_queue[1:]
    }
	return nil
}

func UsernameHash(username string) (uuid_user uuid.UUID, hashed_user []byte,  err error) {
	nil_UUID, _ := uuid.FromBytes(userlib.Hash([]byte("Nil UUID"))[:16])
	username_byte := []byte(username)
	username_to_hash := append(username_byte, []byte("uuid")...)
	user_uuid, err := uuid.FromBytes(userlib.Hash(username_to_hash)[:16])
	if (err != nil) {
		userlib.DebugMsg("Issue with creating user UUID")
		return nil_UUID, nil, err
	}
	user_uuid_byte := []byte(user_uuid.String())
	username_key := append(username_byte, user_uuid_byte...)
	username_key = append(username_key, []byte("user")...)
	username_hashed := userlib.Hash(username_key)
	
	return user_uuid, username_hashed, nil
}


// Tree Data Structures
func  TreeAddChild(tree *Node, child *Node, parent string) (new_tree *Node, err error) {
	// if tree.Username == parent {
	// 	tree.Children = append(tree.Children, child)
	// 	return tree, nil
	// } else if len(tree.Children) > 0 {
    //     var result *Node = nil
	// 	for i:=0; (result == nil && i < len(tree.Children)); i++ {
	// 		result, err = TreeAddChild(tree.Children[i], child, parent)
	// 		if err == nil {
	// 			tree.Children[i] = result
	// 			return tree, nil
	// 		}
	// 	} 
	// 	return tree, errors.New("not found")
	// } else {
	// 	return tree, errors.New("not found")
	// }
	var bfs_queue []*Node
    bfs_queue = append(bfs_queue, tree)
    for len(bfs_queue) > 0 {
        node := bfs_queue[0]
        if node.Username == parent {
            node.Children = append(node.Children, child)
            return tree, nil
        }
        for i := 0; i < len(node.Children); i++ {
            bfs_queue = append(bfs_queue, node.Children[i])
        }
        bfs_queue = bfs_queue[1:]
    }
	return tree, nil
}
func RemoveDirectChild(tree *Node, target_username string) (new_tree *Node, err error) {
	loc := ChildLocation(tree.Children, target_username)
	if loc == -1 {
		return nil, errors.New("Username not in the tree or Username is not a direct child")
	} 
	tree.Children[loc] = tree.Children[len(tree.Children)-1]
	tree.Children = tree.Children[:len(tree.Children)-1]
	return tree, nil
}

func ChildLocation(children []*Node, tag string) int {
	for i := 0; i < len(children); i++ {
		if children[i].Username == tag {
			return i
		}
	}
	return -1
}



