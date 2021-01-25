package warcindexer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestGetTitle(t *testing.T) {
	body := []byte(`<html>
<head>
<title>Hello</title>
</head>
<body>
<h1>Hello, World!</h1>
</body>
</html>`)
	expected := "Hello"
	actual, err := getTitle(bytes.NewReader(body))
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestIsTitle(t *testing.T) {
	body := []byte(`<html>
<head>
<title>Hello</title>
</head>
<body>
<h1>Hello, World!</h1>
</body>
</html>`)
	doc, err := html.Parse(bytes.NewReader(body))
	require.Nil(t, err)
	n := doc.FirstChild. // html
				FirstChild. // head
				FirstChild. // garbage (IE. '\n')
				NextSibling // title
	require.True(t, isTitle(n))
}

func TestMatchTitle(t *testing.T) {
	body := []byte(`<html>
<head>
<title>Hello</title>
</head>
<body>
<h1>Hello, World!</h1>
</body>
</html>`)
	doc, err := html.Parse(bytes.NewReader(body))
	require.Nil(t, err)
	nodes := matchTitle(doc, nil)
	require.True(t, len(nodes) > 0)
	require.True(t, isTitle(nodes[0]))
}

func TestNodesToText(t *testing.T) {
	body := []byte(`<html>
<head>
<title>Hello</title>
</head>
<body>
<h1>Hello, World!</h1>
</body>
</html>`)
	doc, err := html.Parse(bytes.NewReader(body))
	require.Nil(t, err)
	nodes := matchTitle(doc, nil)
	expected := "Hello"
	actual := nodesToText(nodes)
	require.Equal(t, expected, actual)
}
