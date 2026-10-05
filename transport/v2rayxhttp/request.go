package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// The request layout follows Xray-core transport/internet/splithttp
// (config.go, xpadding.go, v26.9.9): where the session ID, the sequence
// number, the padding and packet-up data go is set by the leg's config.

func (c *requestConfig) baseURL(scheme string) *url.URL {
	return &url.URL{
		Scheme:   scheme,
		Host:     c.host,
		Path:     c.normalizedPath(),
		RawQuery: c.rawQuery,
	}
}

// newStreamRequest builds a download GET (body == nil) or the request whose
// body streams the upload (stream-up, stream-one).
func (c *requestConfig) newStreamRequest(ctx context.Context, scheme string, sessionID string, body io.ReadCloser) *http.Request {
	method := http.MethodGet
	if body != nil {
		method = c.uplinkHTTPMethod
	}
	request := c.newRequest(ctx, method, scheme)
	if body != nil {
		request.Body = body
		// The length is unknown: chunked on HTTP/1.1, DATA frames until
		// END_STREAM on HTTP/2 and 3.
		request.ContentLength = -1
	}
	c.applyPadding(request)
	c.applyMeta(request, sessionID, "")
	if body != nil && !c.noGRPCHeader {
		// Reverse proxies and CDNs stream a response without buffering when they
		// see gRPC; Xray sends this unless no_grpc_header is set.
		request.Header.Set("Content-Type", "application/grpc")
	}
	return request
}

// newPacketRequest builds one packet-up upload carrying data.
func (c *requestConfig) newPacketRequest(ctx context.Context, scheme string, sessionID string, seq string, data []byte) *http.Request {
	request := c.newRequest(ctx, c.uplinkHTTPMethod, scheme)
	switch c.uplinkDataPlacement {
	case placementHeader:
		encoded := base64.RawURLEncoding.EncodeToString(data)
		for i := 0; len(encoded) > 0; i++ {
			size := min(c.chunkSize(), len(encoded))
			request.Header.Set(c.uplinkDataKey+"-"+strconv.Itoa(i), encoded[:size])
			encoded = encoded[size:]
		}
	case placementCookie:
		encoded := base64.RawURLEncoding.EncodeToString(data)
		for i := 0; len(encoded) > 0; i++ {
			size := min(c.chunkSize(), len(encoded))
			request.AddCookie(&http.Cookie{Name: c.uplinkDataKey + "_" + strconv.Itoa(i), Value: encoded[:size]})
			encoded = encoded[size:]
		}
	default:
		request.Body = io.NopCloser(bytes.NewReader(data))
		request.ContentLength = int64(len(data))
		// HTTP/2 replays a request the server refused with GOAWAY before it was
		// processed; without GetBody it cannot (Xray dffc7ada).
		request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
	}
	c.applyPadding(request)
	c.applyMeta(request, sessionID, seq)
	return request
}

func (c *requestConfig) newRequest(ctx context.Context, method string, scheme string) *http.Request {
	request := &http.Request{
		Method:     method,
		URL:        c.baseURL(scheme),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		// The options' header map is shared by all requests: each request gets
		// its own copy, so that nothing written below reaches another request.
		Header: c.header.Clone(),
		Host:   c.host,
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	return request.WithContext(ctx)
}

func appendToPath(path string, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func (c *requestConfig) applyMeta(request *http.Request, sessionID string, seq string) {
	if sessionID != "" {
		c.place(request, c.sessionPlacement, c.sessionKey, sessionID)
	}
	if seq != "" {
		c.place(request, c.seqPlacement, c.seqKey, seq)
	}
}

func (c *requestConfig) place(request *http.Request, placement string, key string, value string) {
	switch placement {
	case placementPath:
		request.URL.Path = appendToPath(request.URL.Path, value)
	case placementQuery:
		query := request.URL.Query()
		query.Set(key, value)
		request.URL.RawQuery = query.Encode()
	case placementHeader:
		request.Header.Set(key, value)
	case placementCookie:
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}

// applyPadding adds the random padding. It is computed from the URL before the
// session ID and sequence number are placed, as Xray does.
func (c *requestConfig) applyPadding(request *http.Request) {
	length := int(c.paddingBytes.rand())
	placement, key, header, method := placementQueryInHeader, "x_padding", "Referer", paddingMethodRepeatX
	if c.paddingObfsMode {
		placement, key, header, method = c.paddingPlacement, c.paddingKey, c.paddingHeader, c.paddingMethod
	}
	padding := generatePadding(method, length)
	switch placement {
	case placementHeader:
		request.Header.Set(header, padding)
	case placementQueryInHeader:
		paddedURL := *request.URL
		paddedURL.RawQuery = key + "=" + padding
		request.Header.Set(header, paddedURL.String())
	case placementCookie:
		request.AddCookie(&http.Cookie{Name: key, Value: padding, Path: "/"})
	case placementQuery:
		query := request.URL.Query()
		query.Set(key, padding)
		request.URL.RawQuery = query.Encode()
	}
}

const base62Characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// generatePadding returns length bytes of padding as they will travel in
// HPACK/QPACK: 'X' (and 'Z') take 8 bits in the static Huffman table, so
// repeat-x keeps its length on the wire; tokenish is random base62 sized by
// its Huffman length, give or take 2.
func generatePadding(method string, length int) string {
	if length <= 0 {
		return ""
	}
	if method == paddingMethodTokenish {
		if padding := tokenishPadding(length); padding != "" {
			return padding
		}
	}
	return strings.Repeat("X", length)
}

func tokenishPadding(target int) string {
	// Base62 averages 0.8 Huffman bytes per character.
	n := max(1, int(math.Ceil(float64(target)/0.8)))
	padding := make([]byte, 0, n+16)
	random := make([]byte, 256)
	limit := byte(256 - 256%len(base62Characters))
	for len(padding) < n {
		if _, err := rand.Read(random); err != nil {
			return ""
		}
		for _, b := range random {
			if b >= limit {
				continue
			}
			padding = append(padding, base62Characters[int(b)%len(base62Characters)])
			if len(padding) == n {
				break
			}
		}
	}
	adjust := byte('X')
	for iteration := 0; iteration < 150; iteration++ {
		diff := int(hpack.HuffmanEncodeLength(string(padding))) - target
		if diff >= -2 && diff <= 2 {
			break
		}
		if diff < 0 {
			padding = append(padding, adjust)
			if adjust == 'X' {
				adjust = 'Z'
			} else {
				adjust = 'X'
			}
		} else {
			if len(padding) <= 1 {
				break
			}
			padding = padding[:len(padding)-1]
		}
	}
	return string(padding)
}
