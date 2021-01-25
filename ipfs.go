package warcindexer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ipfs/go-ipfs-files"
	ipfshttpapi "github.com/ipfs/go-ipfs-http-client"

	"github.com/crossedbot/simplewarc"
)

// compress compresses the reader's content using the given compression type
func compress(r io.Reader, c simplewarc.CompressionType) (io.Reader, error) {
	var w io.Writer
	buf := bytes.NewBuffer([]byte{})
	switch c {
	case simplewarc.GzipCompression:
		gzw := gzip.NewWriter(buf)
		defer gzw.Close()
		w = gzw
	case simplewarc.NoCompression:
		// just use the buffer if no compression is selected
		w = buf
	default:
		return nil, fmt.Errorf("uknown compression type")
	}
	_, err := io.Copy(w, r)
	return buf, err
}

// prepare prepares the content for IPFS by compressing, encrypting, encoding it
func prepare(r io.Reader, key cipher.AEAD, nonce []byte) ([]byte, error) {
	r, err := compress(r, simplewarc.GzipCompression)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	cipher := key.Seal(nil, nonce, buf.Bytes(), nil)
	return []byte(base64.URLEncoding.EncodeToString(cipher)), nil
}

// push pushes the given data to IPFS by adding it to the nodes filesystem
func push(ctx context.Context, client *ipfshttpapi.HttpApi, b []byte) (string, error) {
	fn := files.NewBytesFile(b)
	p, err := client.Unixfs().Add(ctx, fn)
	if err != nil {
		return "", err
	}
	return p.Cid().String(), nil
}
