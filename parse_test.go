package warcindexer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseResponse(t *testing.T) {
	statusCode := 200
	proto := "HTTP/1.1"
	contentType := "text/html"
	hdr := []string{
		"Date: Mon, 06 Mar 2017 04:02:06 GMT",
		"Content-Length: 96",
		"Content-Type: text/html",
		"Connection: Closed",
	}
	body := []byte(`<html>
	<head>
		<title>Hello</title>
	</head>
	<body>
		<h1>Hello, World!</h1>
	</body>
</html>`)
	resp := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\n%s\n\n%s",
		strings.Join(hdr, "\n"),
		body,
	))
	parsedResponse, err := parseResponse(bytes.NewReader(resp))
	require.Nil(t, err)
	require.Equal(t, statusCode, parsedResponse.StatusCode)
	require.Equal(t, proto, parsedResponse.Proto)
	require.Equal(t, contentType, parsedResponse.ContentType)
	// check header
	headers := strings.Split(string(parsedResponse.Header), "\r\n")
	for _, expected := range hdr {
		found := false
		for _, actual := range headers {
			if strings.EqualFold(expected, actual) {
				found = true
				break
			}
		}
		require.True(t, found)
	}
	// check body
	actualBody, err := ioutil.ReadAll(parsedResponse.Body)
	require.Nil(t, err)
	require.Equal(t, body, actualBody)
}
