package warcindexer

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
)

// parsedResponse represents a parsed HTTP response
type parsedResponse struct {
	StatusCode  int           // Status Code
	Proto       string        // Protocol
	ContentType string        // Content Type
	Header      []byte        // Response Header
	Body        io.ReadCloser // Response Payload
}

// parseResponse returns the parsed HTTP response
func parseResponse(r io.Reader) (parsedResponse, error) {
	// read in the response
	resp, err := http.ReadResponse(bufio.NewReader(r), nil)
	if err != nil {
		return parsedResponse{}, err
	}
	// retrieve the header
	hdr := bytes.NewBuffer([]byte{})
	if err := resp.Header.Write(hdr); err != nil {
		return parsedResponse{}, err
	}
	// construct the response
	return parsedResponse{
		StatusCode:  resp.StatusCode,
		Proto:       resp.Proto,
		ContentType: resp.Header.Get("Content-Type"),
		Header:      bytes.TrimSpace(hdr.Bytes()),
		Body:        resp.Body,
	}, nil
}
