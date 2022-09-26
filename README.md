To test the implementation, run `go test -v` inside of the `client_test` directory.

This is a project creating a secure file storage and file sharing system. It is IND-CPA secure, and ensures integrity and authenticity of file sharing actions. 

- Data Structures

* Struct User: the user struct should contain the username(string), the hash(password) (string), a unique salt value and a private key used for user authentication. A map invitation of files that they have been shared with, with the key being original owner of the file appended by the file name, and the value an uuid for the particular share. A similar shared_file map of files they shared (key file_name, value users that the file is shared with).(encrypt hashed )

* Struct File: the file struct should contain the metadata of a file: a file’s owner(string), and its shared users(string[]), the number of times the file has been appended to num_append, and an array of symmetric keys sym_keys corresponding to each append.

* Map all_users: we also need to keep track of a set of all users, so that when a new user signs up the service, we can ensure they have a different username. 

* Map online_users: this set is to ensure proper sessions from the same users across multiple devices. 

* Struct Invitation: this struct is used for file sharing. It should contain the name of the root_owner of a file and the name of the inviter owner and the name of the user invited and the filename and the symmetric key of the file shared //// hmac key///. Also, a boolean accepted indicating whether the invitation has been accepted or not. When the invitation is accepted, the invitee can access the metadata of the file owned by the root_user and use the symmetric key of the file to perform store/load/append. 

- User Authentication
Relevant Client API Methods: InitUser, GetUser
When a user signs up, we will assign the user a unique salt value and a randomly generated private key. We will use a secure hash function to compute h(pwd||salt).
For each user, we will store username, salt, H(password || salt) in the Datastore.
To verify a user, we look up their salt in the Datastore, compute H(password || salt), and check it matches the hash in the file.

* InitUser: this function will create a new user, and when creating the user, we will check the username against usernames that are already registered in the Datastore. If the username entered exists or is empty, we will error.

* GetUser: in this method, we will authenticate the user using the method mentioned above. If the verification fails, we will error; otherwise, we will return the user’s pointer stored in the all_user map. If the user is already online and now logged in with a different device, different pointers produced by this method will point to the same user object, and the session will be appended under this user in the online_users map.


- File Storage and Retrieval

* StoreFile: A user will store their files using a symmetric encryption scheme along with a MAC to ensure integrity and authenticity. The (key from user’s pwd; hash-kdf, symmetric key function, make it clear) symmetric key will be re-generated for each operation. They will be stored onto the Datastore along with a hashed file name (h(username||filename)). This will ensure that different users have their own namespace, and can have files of the same name. If a file is newly created, we will create its metadata at that location (i.e. the File struct), and its contents will be at h(username|filename|0th-append).

* LoadFile: When a user requests their files, we perform a similar authentication process. If the authentication succeeds, we will fetch the file with a matching hash and give it to the user.

* AppendToFile:the authentication process is similar, after we locate the file, we will just append the ciphertext and record the IV used. This way, we won’t need to recompute or reencrypt the messages that already exist, and the complexity would only pertain to the appended message. We perform a similar authentication process, and when we append to a file we store the appended text with a new symmetric key in a different location in the Datastore. These appended files will be in the format (h(username|filename|ith-append). We store the number of appends done in the File struct of a file; when we issue a new append, we will simply increment “file.num_appends” by 1, and dump the new data onto the new location. 
In the case where the file is shared (i.e. the caller is not the root owner of the file), we will check the file in the user’s invitation map and obtain the uuid to the corresponding invitation. Then we will go to the Datastore and find the invitation struct; there we can find the root_owner of a file, and we will do “store/load/append” directly on the file in the root owner’s namespace.

- File Sharing and Revocation
* CreateInvitation:we first authenticate the user and fetch the file object denoted by the function arguments; then we generate a uuid and store an invitation object onto the Datastore. Also, we will append this uuid to the user’s invitation map, denoting that they have created this invitation. 
AcceptInvitation:we first authenticate the user. the user accepts a file share. We will then insert the uuid of this invitation and the file name into the user’s shared file map. 

* RevokeAccess:we first authenticate the user. Then we will revoke the access of the other user by removing the file name and its uuid from the other user’s shared file map. We will also recursively revoke the access by looking at the other user’s invitation map, and revoke the access of people the other user invited. The key value pair of related invitation struct will be deleted along the way from the Datastore. After this, we will update the symmetric key mac of the file and migrate the file to a new location in the Datastore to prevent the revoked user from accessing the file. The invitation of other users with legitimate access will also be updated to reflect this change.

- Helper Methods
Authenticate: this method takes in a user, a message, and the purpose of authentication. It will authenticate the user’s identity according to the purpose.
 





























































































