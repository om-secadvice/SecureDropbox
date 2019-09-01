package assn1

import (
	"cs628a-assn1/userlib"
	"reflect"
	"testing"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}

	userlib.DebugPrint = true
	t.Logf("User Init %s", u.Username)
	userlib.DebugPrint = false
	u.StoreFile("abc", []byte("My file"))
	u1, err1 := InitUser("alice", "fubar")
	if err1 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	if reflect.DeepEqual(u, u1) {
		t.Error("User ReInited. Test Failed")
	}
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {

	// t.Log("Getuser test")
	// userlib.DebugPrint = true

	// u1, err1 := InitUser("alice", "fubar")
	// if err1 != nil {
	// 	// t.Error says the test fails
	// 	t.Error("Failed to initialize user", err1)
	// }
	// t.Log("User 1 Initialised")

	// u2, err2 := InitUser("bob", "fobar")
	// if err2 != nil {
	// 	// t.Error says the test fails
	// 	t.Error("Failed to initialize user", err2)
	// }
	// t.Log("User 2 Initialised")

	// //Swap Key attacks on userfile. Change GetUser password to 'fobar' to see effect.
	// u2f, _ := userlib.DatastoreGet(u2.ArgonKey)
	// userlib.DatastoreSet(u1.ArgonKey, u2f)

	u3, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	t.Logf("User Got %s", u3.Username)
	// userlib.DatastoreClear()
	// u3, err = GetUser("alice", "fubar")
	// if err != nil {
	// 	t.Error("Failed to get user", err)
	// }

}

//TestStorage - Tests StoreFile, AppendFile and LoadFile
func TestStorage(t *testing.T) {
	InitUser("alice", "fubar")
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("This is a test ")
	u.StoreFile("file1", v)
	v2, err2 := u.LoadFile("file1")
	t.Log(string(v2))

	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
	u.AppendFile("file1", []byte("by Alice"))
	v3, err3 := u.LoadFile("file1")

	if err3 != nil {
		t.Error("Failed to download", err3)
	}
	v = append(v, []byte("by Alice")...)
	if !reflect.DeepEqual(v, v3) {
		t.Error("Downloaded file is not the same", v, v3)
	}
	t.Log(string(v3))

}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}

	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	// t.Logf("User %s Files are %s", u2.Username, u2.ListOfFiles)
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}
func TestRevoke(t *testing.T) {
	u1, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("bob", "foobar")
	u1.RevokeFile("file1")
	u1.AppendFile("file1", []byte(" that too successful."))
	ms, _ := u1.LoadFile("file1")

	t.Log(string(ms))

	msg, _ := u2.LoadFile("file2")
	t.Log(string(msg))
	if userlib.Equal(ms, msg) {
		t.Error("Revoke Error")
	}

}
func TestStoreAfterClear(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	u, err := InitUser("alice", "fubar")
	u, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error(err)
	}
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	u.StoreFile("abc", []byte("New File"))
	err = u.AppendFile("abc", []byte(" created"))
	if err != nil {
		t.Error(err)
	}
	m := userlib.DatastoreGetMap()
	if len(m) > 0 {
		t.Error("Store without user session")
	}
	t.Log(m)
}

func TestSingleUserMultipleInstances(t *testing.T) {

	u1, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("alice", "fubar")
	v := []byte("first file")
	u1.StoreFile("first", v)
	msg, err := u2.LoadFile("first")
	if err != nil {
		t.Error(err)
	}
	if !userlib.Equal(v, msg) {
		t.Error("File Not Same")
	}

}

func TestMutateShare(t *testing.T) {
	u1, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("bob", "foobar")
	u1.StoreFile("first", []byte("google"))
	msgid, err := u1.ShareFile("first", "bob")
	u2.ReceiveFile("bobfirst", "alice", msgid)
	msg, _ := u2.LoadFile("bobfirst")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(msg))
	// InitUser("mike", "peyton")
	// u3, _ := GetUser("mike", "peyton")
	// u3.ReceiveFile("myfirst", "alice", msgid)
	// msg, err = u3.LoadFile("myfirst")
	// if err != nil {
	// 	t.Log(err)
	// }
	// t.Log(msg)
}
