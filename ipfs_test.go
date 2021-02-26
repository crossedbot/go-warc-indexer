package warcindexer

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/base64"
	"io"
	"io/ioutil"
	"testing"

	"github.com/crossedbot/common/golang/crypto/aes"
	"github.com/crossedbot/simplewarc"
	"github.com/stretchr/testify/require"
)

func TestCompress(t *testing.T) {
	original := []byte("helloworld")

	// compress gzip
	expected := bytes.NewBuffer([]byte{})
	w := gzip.NewWriter(expected)
	w.Write([]byte("helloworld"))
	w.Close()
	compressed, err := compress(
		bytes.NewReader(original),
		simplewarc.GzipCompression,
	)
	require.Nil(t, err)
	actual, err := ioutil.ReadAll(compressed)
	require.Nil(t, err)
	require.Equal(t, expected.Bytes(), actual)

	// compress none
	compressed, err = compress(
		bytes.NewReader(original),
		simplewarc.NoCompression,
	)
	require.Nil(t, err)
	actual, err = ioutil.ReadAll(compressed)
	require.Nil(t, err)
	require.Equal(t, original, actual)
}

func TestPrepare(t *testing.T) {
	var aead cipher.AEAD
	var nonce []byte
	var err error

	original := []byte("goodbyeworld")
	r, err := compress(
		bytes.NewReader(original),
		simplewarc.GzipCompression,
	)
	require.Nil(t, err)
	var buf bytes.Buffer
	tee := io.TeeReader(r, &buf)

	// without encyption
	b, err := ioutil.ReadAll(tee)
	require.Nil(t, err)
	expected := []byte(base64.URLEncoding.EncodeToString(b))
	actual, err := prepare(bytes.NewReader(original), aead, nonce)
	require.Nil(t, err)
	require.Equal(t, expected, actual)

	// with encryption
	key := []byte("helloworld")
	salt := []byte("saltsalt")
	aead, nonce, err = aes.NewKey(key, salt)
	require.Nil(t, err)
	expected = []byte(
		base64.URLEncoding.EncodeToString(
			aead.Seal(nil, nonce, buf.Bytes(), nil),
		),
	)
	actual, err = prepare(bytes.NewReader(original), aead, nonce)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}
