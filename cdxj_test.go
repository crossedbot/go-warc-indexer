package warcindexer

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crossedbot/simplecdxj"
	"github.com/crossedbot/simplewarc"
)

func TestCdxjHeader(t *testing.T) {
	versionKey := "Hello"
	versionValue := "World"
	numOfRecords := 123
	hdr := cdxjHeader(versionKey, versionValue, numOfRecords)

	// check version value
	require.Equal(t, []byte(versionValue), hdr.Get(versionKey))

	// check keys value
	expectedKeys := []string{"surt_uri", "timestamp", "record_type", "payload"}
	b := hdr.Get("keys")
	var actualKeys []string
	require.Nil(t, json.Unmarshal(b, &actualKeys))
	require.Equal(t, expectedKeys, actualKeys)

	// check meta value
	meta := struct {
		Count   int    `json:"record_count"`
		Updated string `json:"updated_at"`
	}{}
	b = hdr.Get("meta")
	require.Nil(t, json.Unmarshal(b, &meta))
	require.Equal(t, numOfRecords, meta.Count)
	require.True(t, len(meta.Updated) > 0)
}

func TestCdxjRecord(t *testing.T) {
	content := []byte("Hello World")
	sha := sha1.Sum(content)
	ts, err := time.Parse(time.RFC3339, "2009-11-10T23:12:00+01:00")
	require.Nil(t, err)
	warc := &simplewarc.Record{
		Header: simplewarc.Header{
			"warc-target-uri": "https://example.com",
			"warc-record-id":  "<urn:uuid:B0B3862C-B271-4670-A4B5-B127576C6118>",
			"warc-date":       "2009-11-10T23:12:00+01:00",
			"warc-type":       simplecdxj.ResponseRecordType.String(),
		},
		Content: bytes.NewReader(content),
		Offset:  123,
	}
	meta := metadata{
		ref:       "hello.warc",
		hsc:       200,
		mct:       "text/html",
		locator:   "ipfs/abc-123/def-456",
		title:     "Hello World",
		keyId:     []byte("QqqxKStb"),
		encMethod: "aes-gcm",
		nonce:     []byte("qYiUZUNB"),
	}
	jb := JsonBlock{
		Uri:              warc.Header["warc-target-uri"],
		Ref:              fmt.Sprintf("warcfile:%s#%d", meta.ref, warc.Offset),
		Sha:              string(sha[:]),
		Hsc:              meta.hsc,
		Mct:              meta.mct,
		Rid:              warc.Header["warc-record-id"],
		Locator:          meta.locator,
		Title:            meta.title,
		EncryptionKeyID:  base64.URLEncoding.EncodeToString(meta.keyId),
		EncryptionMethod: meta.encMethod,
		EncryptionNonce:  base64.URLEncoding.EncodeToString(meta.nonce),
	}
	b, err := json.Marshal(jb)
	require.Nil(t, err)
	expected := &simplecdxj.Record{
		SURT:      "https://(com,example,)",
		Timestamp: ts,
		Type:      simplecdxj.ResponseRecordType,
		Content:   b,
	}
	actual, err := cdxjRecord(meta, warc)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
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
