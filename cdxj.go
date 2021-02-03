package warcindexer

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/crossedbot/simplecdxj"
	"github.com/crossedbot/simplesurt"
	"github.com/crossedbot/simplewarc"
)

// metadata represents the data related to the WARC record
type metadata struct {
	ref       string // Reference file name
	hsc       int    // Response Status Code
	mct       string // Response Content Type
	locator   string // IPFS locator(s)
	title     string // Response HTML title
	keyId     []byte // Encryption Key ID
	encMethod string // Encryption Method (E.g. AES GCM)
	nonce     []byte // Encryption Nonce
}

// jsonBlock represents the content block (AKA payload) of the CDXJ record
type jsonBlock struct {
	// Defined Fields
	Uri string `json:"uri"`
	Ref string `json:"ref"`
	Sha string `json:"sha"`
	Hsc int    `json:"hsc"`
	Mct string `json:"mct"`
	Rid string `json:"rid"`

	// Custom Fields
	Locator          string `json:"x_locator"`
	Title            string `json:"x_title,omitempty"`
	EncryptionKeyID  string `json:"x_encryption_key_id,omitempty"`
	EncryptionMethod string `json:"x_encryption_method,omitempty"`
	EncryptionNonce  string `json:"x_encryption_nonce,omitempty"`
}

// cdxjHeader builds and returns the CDXJ header
func cdxjHeader(versionKey, versionValue string, numOfRecords int) simplecdxj.Header {
	hdr := make(simplecdxj.Header)
	hdr.Set(versionKey, []byte(versionValue))
	hdr.Set(
		"keys",
		[]byte(`["surt_uri", "timestamp", "record_type", "payload"]`),
	)
	hdr.Set(
		"meta",
		[]byte(fmt.Sprintf(
			`{"record_count":%d, "updated_at":"%s"}`,
			numOfRecords, time.Now().Format(time.RFC3339),
		)),
	)
	return hdr
}

// cdxjRecord builds and returns a CDXJ record
func cdxjRecord(md metadata, rec *simplewarc.Record) (*simplecdxj.Record, error) {
	hdr := rec.Header
	sha, err := sha1Sum(rec.Content)
	if err != nil {
		return nil, err
	}
	jb := jsonBlock{
		Uri:              hdr.Get("warc-target-uri"),
		Ref:              fmt.Sprintf("warcfile:%s#%d", md.ref, rec.Offset),
		Sha:              sha,
		Hsc:              md.hsc,
		Mct:              md.mct,
		Rid:              hdr.Get("warc-record-id"),
		Locator:          md.locator,
		Title:            md.title,
		EncryptionKeyID:  base64.URLEncoding.EncodeToString(md.keyId),
		EncryptionMethod: md.encMethod,
		EncryptionNonce:  base64.URLEncoding.EncodeToString(md.nonce),
	}
	surt, err := simplesurt.Format(jb.Uri)
	if err != nil {
		return nil, err
	}
	ts, err := time.Parse(time.RFC3339, hdr.Get("warc-date"))
	if err != nil {
		return nil, err
	}
	warcType, err := simplecdxj.ParseRecordType(hdr.Get("warc-type"))
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(jb)
	if err != nil {
		return nil, err
	}
	return &simplecdxj.Record{
		SURT:      surt,
		Timestamp: ts,
		Type:      warcType,
		Content:   b,
	}, nil
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
