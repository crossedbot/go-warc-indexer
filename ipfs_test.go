package warcindexer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
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
	original := []byte("goodbyeworld")
	key := []byte("helloworld")
	salt := []byte("saltsalt")
	aead, nonce, err := aes.NewKey(key, salt)
	require.Nil(t, err)
	r, err := compress(
		bytes.NewReader(original),
		simplewarc.GzipCompression,
	)
	require.Nil(t, err)
	b, err := ioutil.ReadAll(r)
	require.Nil(t, err)
	expected := []byte(
		base64.URLEncoding.EncodeToString(
			aead.Seal(nil, nonce, b, nil),
		),
	)
	actual, err := prepare(bytes.NewReader(original), aead, nonce)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}
