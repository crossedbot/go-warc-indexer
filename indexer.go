package warcindexer

import (
	"bytes"
	"context"
	"crypto/cipher"
	"io"
	"os"
	"path/filepath"
	"strings"

	ipfshttpapi "github.com/ipfs/go-ipfs-http-client"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/crossedbot/common/golang/crypto"
	"github.com/crossedbot/common/golang/crypto/aes"
	"github.com/crossedbot/simplecdxj"
	"github.com/crossedbot/simplewarc"
)

const (
	// Encryption Types
	NoneEncryption   = "none"
	AesGcmEncryption = "aes-gcm"
)

var (
	// CDXJ Versioning
	VersionKey   = "WARC-CDXJ"
	VersionValue = "1.0"
)

// Indexer represents an interface to a WARC file to IPFS indexer
type Indexer interface {
	// Index indexes the WARC file at the given file path and returns a CDXJ
	Index(name string) (simplecdxj.CDXJ, error)

	// SetEncryptionKey sets the encryption key and salt used to encrypt data
	// before pushing to IPFS
	SetEncryptionKey(key, salt []byte)
}

// indexer implements a WARC file to IPFS indexer
type indexer struct {
	ctx    context.Context
	client *ipfshttpapi.HttpApi
	key    []byte
	salt   []byte
}

// New returns a new Indexer, using the given Multiaddr formatted address to
// interact with the IPFS node
func New(ctx context.Context, addr string) (Indexer, error) {
	multiaddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}
	client, err := ipfshttpapi.NewApi(multiaddr)
	if err != nil {
		return nil, err
	}
	return &indexer{
		ctx:    ctx,
		client: client,
	}, nil
}

// Index indexes the WARC file at the given file path and returns a CDXJ for
// each response WARC record
func (in *indexer) Index(name string) (simplecdxj.CDXJ, error) {
	fd, err := os.Open(name)
	if err != nil {
		return simplecdxj.CDXJ{}, err
	}
	rdr, err := simplewarc.New(fd)
	if err != nil {
		return simplecdxj.CDXJ{}, err
	}
	cdxj := simplecdxj.CDXJ{}
	rec, err := rdr.Next()
	if err != nil {
		return simplecdxj.CDXJ{}, err
	}
	for rec != nil {
		if rec.Header.Get("warc-type") == "response" {
			indexed, err := in.indexRecord(filepath.Base(name), rec)
			if err != nil {
				return simplecdxj.CDXJ{}, err
			}
			cdxj.Records = append(cdxj.Records, indexed)
		}
		rec, err = rdr.Next()
		if err != nil && err != io.EOF {
			return simplecdxj.CDXJ{}, err
		}
	}
	cdxj.Header = cdxjHeader(
		VersionKey,
		VersionValue,
		len(cdxj.Records),
	)
	return cdxj, nil
}

// SetEncryptionKey sets the encryption key and salt
func (in *indexer) SetEncryptionKey(key, salt []byte) {
	in.key = key
	in.salt = salt
}

// indexRecord indexes a single WARC record by parsing it and preparing the
// header and payload separately before pushing to IPFS
func (in *indexer) indexRecord(ref string, rec *simplewarc.Record) (*simplecdxj.Record, error) {
	var keyId []byte
	var key cipher.AEAD
	var nonce []byte
	var err error
	encMethod := NoneEncryption
	if in.key != nil && len(in.key) > 0 {
		// generate encryption values
		keyId = crypto.KeyId(in.key)
		key, nonce, err = aes.NewKey(in.key, in.salt)
		if err != nil {
			return nil, err
		}
		encMethod = AesGcmEncryption
	}
	// parse the HTML content
	resp, err := parseResponse(rec.Content)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// retrieve the title of the document
	var body bytes.Buffer
	tee := io.TeeReader(resp.Body, &body)
	title, err := getTitle(tee)
	if err != nil {
		return nil, err
	}
	// prepare the header and payload for IPFS
	preparedHeader, err := prepare(bytes.NewReader(resp.Header), key, nonce)
	if err != nil {
		return nil, err
	}
	preparedPayload, err := prepare(&body, key, nonce)
	if err != nil {
		return nil, err
	}
	// push the header and payload separately to IPFS
	headerCid, err := push(in.ctx, in.client, []byte(preparedHeader))
	if err != nil {
		return nil, err
	}
	payloadCid, err := push(in.ctx, in.client, []byte(preparedPayload))
	if err != nil {
		return nil, err
	}
	// generate a new CDXJ record
	locator := strings.Join(append(
		[]string{"ipfs"},
		[]string{headerCid, payloadCid}...,
	), "/")
	return cdxjRecord(
		metadata{
			ref:       ref,
			hsc:       resp.StatusCode,
			mct:       resp.ContentType,
			locator:   locator,
			title:     title,
			keyId:     keyId,
			encMethod: encMethod,
			nonce:     nonce,
		},
		rec,
	)
}
