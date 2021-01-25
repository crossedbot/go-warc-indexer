package warcindexer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRandomBytes(t *testing.T) {
	length := 12
	b1, err := generateRandomBytes(length)
	require.Nil(t, err)
	require.Equal(t, length, len(b1))
	b2, err := generateRandomBytes(length)
	require.Nil(t, err)
	require.NotEqual(t, b1, b2)
}

func TestGenerateRandomString(t *testing.T) {
	length := 12
	b1, err := generateRandomString(length)
	require.Nil(t, err)
	require.Equal(t, length, len(b1))
	b2, err := generateRandomString(length)
	require.Nil(t, err)
	require.NotEqual(t, b1, b2)
}

func TestNewNonce(t *testing.T) {
	length := 12
	n1, err := newNonce(length)
	require.Nil(t, err)
	require.Equal(t, length, len(n1))
	n2, err := newNonce(length)
	require.Nil(t, err)
	require.NotEqual(t, n1, n2)
}

func TestNewExtendedKey(t *testing.T) {
	key, salt := []byte("helloworld"), []byte("saltsalt")
	b := newExtendedKey(key, salt)
	require.Equal(t, ExtendedKeySize, len(b))
	require.Equal(t, b, newExtendedKey(key, salt))
}

func TestNewAesGcmKey(t *testing.T) {
	key, salt := []byte("helloworld"), []byte("saltsalt")
	extKey := newExtendedKey(key, salt)
	aead, err := newAesGcmKey(extKey)
	require.Nil(t, err)
	require.NotNil(t, aead)
	require.NotZero(t, aead.NonceSize())
}

func TestNewKey(t *testing.T) {
	key, salt := []byte("helloworld"), []byte("saltsalt")
	aead, nonce, err := newKey(key, salt)
	require.Nil(t, err)
	require.NotNil(t, aead)
	require.NotZero(t, aead.NonceSize())
	require.Equal(t, aead.NonceSize(), len(nonce))
}

func TestGetKeyId(t *testing.T) {
	key := []byte("helloworld")
	expected := []byte{0x93, 0x6a, 0x18, 0x5c, 0xaa, 0xa2, 0x66, 0xbb}
	require.Equal(t, expected, getKeyId(key))
}

func TestSha1Sum(t *testing.T) {
	r := bytes.NewReader([]byte("helloworld"))
	expected := string([]byte{
		0x6a, 0xdf, 0xb1, 0x83,
		0xa4, 0xa2, 0xc9, 0x4a,
		0x2f, 0x92, 0xda, 0xb5,
		0xad, 0xe7, 0x62, 0xa4,
		0x78, 0x89, 0xa5, 0xa1,
	})
	actual, err := sha1Sum(r)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}
