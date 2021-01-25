package warcindexer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Encryption Constants
	AuthKeySize     = 256
	AuthKeyIdSize   = 8
	KdfIterations   = 4096
	ExtendedKeySize = 32
)

// generateRandomBytes returns n number of random bytes
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// generateRandomString returns a random string of n length
func generateRandomString(n int) (string, error) {
	b, err := generateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:n], nil
}

// newNonce returns a new nonce for the given size
func newNonce(sz int) ([]byte, error) {
	now := time.Now().Unix()
	h := sha256.New()
	str, err := generateRandomString(h.Size())
	if err != nil {
		return nil, err
	}
	io.WriteString(h, strconv.FormatInt(now, 10))
	io.WriteString(h, str)
	return h.Sum(nil)[:sz], nil
}

// newExtendedKey returns an extended key using the PBKDF2 function
func newExtendedKey(key, salt []byte) []byte {
	return pbkdf2.Key(
		key,             // password
		salt,            // salt
		KdfIterations,   // iterations
		ExtendedKeySize, // key size
		sha256.New,      // hash function
	)
}

// newAesGcmKey returns a new GCM wrapped AES cipher block; keys should be 16,
// 24, or 32 bytes in length to select AES-128, AES-192, or AES-256 respectively
func newAesGcmKey(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	// check key length
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf(
			"invalid key length (%d); %s",
			len(key),
			"accepted lengths are 16, 24, or 32 bytes",
		)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// newKey returns a new GCM wrapped AES cipher block of a PBKDF2 extended key
func newKey(key, salt []byte) (cipher.AEAD, []byte, error) {
	aead, err := newAesGcmKey(newExtendedKey(key, salt))
	if err != nil {
		return nil, nil, err
	}
	nonce, err := newNonce(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return aead, nonce, nil
}

// getKeyId returns a AuthKeyIdSize long ID for the given key
func getKeyId(key []byte) []byte {
	sum := sha256.Sum256(key)
	return sum[:AuthKeyIdSize]
}

// sha1Sum returns the sha1 sum for the contents of the given reader
func sha1Sum(r io.Reader) (string, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(b)
	return string(sum[:]), nil
}
