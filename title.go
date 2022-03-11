package warcindexer

import (
	"bytes"
	"io"

	"golang.org/x/net/html"
)

// getTitle finds and returns the HTML title's value
func getTitle(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}
	return nodesToText(matchTitle(doc, nil)), nil
}

// isTitle returns true if the element is a title tag
func isTitle(n *html.Node) bool {
	return n.Type == html.ElementNode && n.Data == "title"
}

// matchTitle returns a list of title element nodes
func matchTitle(n *html.Node, tracked []*html.Node) []*html.Node {
	// recursively move down each chain of nodes and track them
	if isTitle(n) {
		tracked = append(tracked, n)
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		tracked = matchTitle(child, tracked)
	}
	return tracked
}

// nodesToText returns the text for all title elements
func nodesToText(nodes []*html.Node) string {
	var buf bytes.Buffer
	var fn func(*html.Node)
	// move through each node and its children, buffering their text
	fn = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		if n.FirstChild != nil {
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				fn(child)
			}
		}
	}
	for _, n := range nodes {
		fn(n)
	}
	return buf.String()
}
