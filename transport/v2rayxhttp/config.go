package v2rayxhttp

import (
	"math/big"
	"math/rand/v2"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/net/http/httpguts"
)

const (
	modeAuto      = "auto"
	modePacketUp  = "packet-up"
	modeStreamUp  = "stream-up"
	modeStreamOne = "stream-one"

	placementPath          = "path"
	placementQuery         = "query"
	placementHeader        = "header"
	placementCookie        = "cookie"
	placementQueryInHeader = "queryInHeader"
	placementBody          = "body"
	placementAuto          = "auto"

	paddingMethodRepeatX  = "repeat-x"
	paddingMethodTokenish = "tokenish"

	maxPaddingBytes    = 64 * 1024
	maxSessionIDLength = 1024
	headerUploadSize   = 4096
)

// valueRange is an inclusive range a value is drawn from at random; the zero
// range means "not set".
type valueRange struct {
	from, to int32
}

func newValueRange(value *option.V2RayXHTTPRange) valueRange {
	if value == nil {
		return valueRange{}
	}
	return valueRange{value.From, value.To}
}

func (r valueRange) isZero() bool {
	return r.from == 0 && r.to == 0
}

func (r valueRange) rand() int32 {
	if r.to <= r.from {
		return r.from
	}
	// In int64: the width of a range may not fit int32 ("0-2147483647").
	return int32(int64(r.from) + rand.Int64N(int64(r.to)-int64(r.from)+1))
}

// Session ID alphabets Xray knows by name.
var sessionIDTables = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

// requestConfig is the request shape of one leg of a session (the upload leg,
// or the download leg when download is set), normalized and checked the way
// Xray's SplitHTTPConfig.Build does, so that every value Xray refuses fails
// `sing-box check` here instead of failing, or panicking, at a dial.
type requestConfig struct {
	host     string
	path     string
	rawQuery string
	header   http.Header

	paddingBytes     valueRange
	paddingObfsMode  bool
	paddingKey       string
	paddingHeader    string
	paddingPlacement string
	paddingMethod    string

	uplinkHTTPMethod    string
	sessionPlacement    string
	sessionKey          string
	sessionIDTable      string
	sessionIDLength     valueRange
	seqPlacement        string
	seqKey              string
	uplinkDataPlacement string
	uplinkDataKey       string
	uplinkChunkSize     valueRange
	noGRPCHeader        bool

	maxEachPostBytes   valueRange
	minPostsIntervalMs valueRange

	xmux xmuxConfig
}

type xmuxConfig struct {
	maxConcurrency   valueRange
	maxConnections   valueRange
	cMaxReuseTimes   valueRange
	hMaxRequestTimes valueRange
	hMaxReusableSecs valueRange
	hKeepAlivePeriod int64
}

// newRequestConfig normalizes one leg. mode is the configured mode ("" or
// "auto" included): Xray checks the packet-up only settings against it, not
// against the mode auto resolves to.
func newRequestConfig(options option.V2RayXHTTPBaseOptions, mode string) (*requestConfig, error) {
	c := &requestConfig{
		host:            options.Host,
		paddingObfsMode: options.XPaddingObfsMode,
		noGRPCHeader:    options.NoGRPCHeader,
	}
	header := make(http.Header)
	for key, values := range options.Headers.Build() {
		switch strings.ToLower(key) {
		case "host":
			return nil, E.New("headers can't contain host, set host instead")
		case "upgrade", "transfer-encoding", "connection", "content-length":
			return nil, E.New("headers can't contain ", key)
		}
		if !httpguts.ValidHeaderFieldName(key) {
			return nil, E.New("invalid header name: ", key)
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, E.New("invalid value of header ", key)
			}
		}
		header[key] = values
	}
	// Browser-like headers are fixed for the life of the process (Xray derives
	// them once at start), so they are applied once here and every request
	// takes a copy.
	applyDefaultHeaders(header)
	c.header = header

	pathAndQuery := strings.SplitN(options.Path, "?", 2)
	c.path = pathAndQuery[0]
	if len(pathAndQuery) > 1 {
		c.rawQuery = pathAndQuery[1]
	}

	c.paddingBytes = newValueRange(options.XPaddingBytes)
	if c.paddingBytes.isZero() {
		c.paddingBytes = valueRange{100, 1000}
	} else if c.paddingBytes.from <= 0 {
		return nil, E.New("x_padding_bytes cannot be disabled")
	} else if c.paddingBytes.to > maxPaddingBytes {
		// Every request carries this much: a mistyped range must not make each
		// of them allocate megabytes. Servers take 8 KiB of headers by default.
		return nil, E.New("x_padding_bytes is too large, the maximum is ", maxPaddingBytes)
	}
	c.paddingKey = options.XPaddingKey
	if c.paddingKey == "" {
		c.paddingKey = "x_padding"
	}
	c.paddingHeader = options.XPaddingHeader
	if c.paddingHeader == "" {
		c.paddingHeader = "X-Padding"
	}
	switch options.XPaddingPlacement {
	case "":
		c.paddingPlacement = placementQueryInHeader
	case placementCookie, placementHeader, placementQuery, placementQueryInHeader:
		c.paddingPlacement = options.XPaddingPlacement
	default:
		return nil, E.New("unsupported x_padding_placement: ", options.XPaddingPlacement)
	}
	if !httpguts.ValidHeaderFieldName(c.paddingHeader) {
		return nil, E.New("invalid x_padding_header: ", c.paddingHeader)
	}
	if !httpguts.ValidHeaderFieldName(c.paddingKey) {
		return nil, E.New("invalid x_padding_key: ", c.paddingKey)
	}
	switch options.XPaddingMethod {
	case "":
		c.paddingMethod = paddingMethodRepeatX
	case paddingMethodRepeatX, paddingMethodTokenish:
		c.paddingMethod = options.XPaddingMethod
	default:
		return nil, E.New("unsupported x_padding_method: ", options.XPaddingMethod)
	}

	switch options.UplinkDataPlacement {
	case "":
		c.uplinkDataPlacement = placementAuto
	case placementAuto, placementBody:
		c.uplinkDataPlacement = options.UplinkDataPlacement
	case placementCookie, placementHeader:
		if mode != modePacketUp {
			return nil, E.New("uplink_data_placement can be ", options.UplinkDataPlacement, " only in packet-up mode")
		}
		c.uplinkDataPlacement = options.UplinkDataPlacement
	default:
		return nil, E.New("unsupported uplink_data_placement: ", options.UplinkDataPlacement)
	}
	c.uplinkDataKey = options.UplinkDataKey
	if c.uplinkDataKey == "" {
		switch c.uplinkDataPlacement {
		case placementCookie:
			c.uplinkDataKey = "x_data"
		case placementAuto, placementHeader:
			c.uplinkDataKey = "X-Data"
		}
	}

	if c.uplinkDataKey != "" && !httpguts.ValidHeaderFieldName(c.uplinkDataKey) {
		return nil, E.New("invalid uplink_data_key: ", c.uplinkDataKey)
	}
	c.uplinkHTTPMethod = strings.ToUpper(options.UplinkHTTPMethod)
	if c.uplinkHTTPMethod == "" {
		c.uplinkHTTPMethod = http.MethodPost
	}
	// A method is a token, as a header name is. One that is not is refused by
	// the HTTP/1.1 and HTTP/3 clients at the first request and sent as it is
	// by the HTTP/2 client.
	if !httpguts.ValidHeaderFieldName(c.uplinkHTTPMethod) {
		return nil, E.New("invalid uplink_http_method: ", options.UplinkHTTPMethod)
	}
	if c.uplinkHTTPMethod == http.MethodGet && mode != modePacketUp {
		return nil, E.New("uplink_http_method can be GET only in packet-up mode")
	}

	var err error
	c.sessionPlacement, err = checkPlacement("session_placement", options.SessionPlacement)
	if err != nil {
		return nil, err
	}
	c.seqPlacement, err = checkPlacement("seq_placement", options.SeqPlacement)
	if err != nil {
		return nil, err
	}
	c.sessionKey = defaultKey(options.SessionKey, c.sessionPlacement, "x_session", "X-Session")
	c.seqKey = defaultKey(options.SeqKey, c.seqPlacement, "x_seq", "X-Seq")
	// A key names a header, a cookie or a query parameter: a token in each.
	if c.sessionPlacement != placementPath && !httpguts.ValidHeaderFieldName(c.sessionKey) {
		return nil, E.New("invalid session_key: ", c.sessionKey)
	}
	if c.seqPlacement != placementPath && !httpguts.ValidHeaderFieldName(c.seqKey) {
		return nil, E.New("invalid seq_key: ", c.seqKey)
	}

	c.sessionIDLength = newValueRange(options.SessionIDLength)
	if options.SessionIDTable != "" {
		table := options.SessionIDTable
		if predefined, loaded := sessionIDTables[table]; loaded {
			table = predefined
		}
		for i := 0; i < len(table); i++ {
			if table[i] >= 0x80 {
				return nil, E.New("session_id_table must contain only ASCII characters")
			}
			// The ID travels in a path, a query, a header or a cookie: a "/"
			// would split it in the path, and Xray's server would read the
			// rest as the sequence number.
			if !isUnreserved(table[i]) {
				return nil, E.New("session_id_table can contain only letters, digits and -._~")
			}
		}
		if c.sessionIDLength.from <= 0 {
			return nil, E.New("session_id_length must be greater than 0")
		}
		if c.sessionIDLength.to > maxSessionIDLength {
			return nil, E.New("session_id_length is too large, the maximum is ", maxSessionIDLength)
		}
		// Xray asks for at least 2^31 possible IDs.
		if sessionIDRoom(len(table), c.sessionIDLength).Cmp(big.NewInt(2<<30)) < 0 {
			return nil, E.New("session_id_table or session_id_length is too small")
		}
		c.sessionIDTable = table
	}

	c.uplinkChunkSize = newValueRange(options.UplinkChunkSize)
	c.maxEachPostBytes = newValueRange(options.ScMaxEachPostBytes)
	if c.maxEachPostBytes.to == 0 {
		c.maxEachPostBytes = valueRange{1000000, 1000000}
		if c.uplinkDataPlacement == placementHeader || c.uplinkDataPlacement == placementCookie {
			// Unlike Xray: its megabyte per request, carried in headers or
			// cookies, is far over the 8 KiB of headers servers accept, so a
			// bulk upload failed. 4 KiB fits with the default padding (lab:
			// 4 KiB passed, 6 KiB did not).
			c.maxEachPostBytes = valueRange{headerUploadSize, headerUploadSize}
		}
	} else if c.maxEachPostBytes.from <= 0 {
		// Xray panics at the dial on this value.
		return nil, E.New("sc_max_each_post_bytes must be greater than 0")
	}
	c.minPostsIntervalMs = newValueRange(options.ScMinPostsIntervalMs)
	if c.minPostsIntervalMs.to == 0 {
		c.minPostsIntervalMs = valueRange{30, 30}
	}

	if options.Xmux != nil {
		c.xmux = xmuxConfig{
			maxConcurrency:   newValueRange(options.Xmux.MaxConcurrency),
			maxConnections:   newValueRange(options.Xmux.MaxConnections),
			cMaxReuseTimes:   newValueRange(options.Xmux.CMaxReuseTimes),
			hMaxRequestTimes: newValueRange(options.Xmux.HMaxRequestTimes),
			hMaxReusableSecs: newValueRange(options.Xmux.HMaxReusableSecs),
			hKeepAlivePeriod: options.Xmux.HKeepAlivePeriod,
		}
	}
	if c.xmux.maxConnections.to > 0 && c.xmux.maxConcurrency.to > 0 {
		return nil, E.New("xmux: max_connections cannot be set together with max_concurrency")
	}
	// As in Xray, the defaults apply only when xmux sets nothing at all.
	if c.xmux == (xmuxConfig{}) {
		c.xmux.maxConnections = valueRange{3, 3}
		c.xmux.hMaxRequestTimes = valueRange{600, 900}
		c.xmux.hMaxReusableSecs = valueRange{1800, 3000}
	}
	return c, nil
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func checkPlacement(name string, placement string) (string, error) {
	switch placement {
	case "":
		return placementPath, nil
	case placementPath, placementCookie, placementHeader, placementQuery:
		return placement, nil
	default:
		return "", E.New("unsupported ", name, ": ", placement)
	}
}

func defaultKey(key string, placement string, lowerKey string, headerKey string) string {
	if key != "" || placement == placementPath {
		return key
	}
	if placement == placementHeader {
		return headerKey
	}
	return lowerKey
}

// sessionIDRoom is the number of session IDs a table and a length range give,
// counted only as far as the 2^31 Xray asks for.
func sessionIDRoom(tableSize int, length valueRange) *big.Int {
	enough := big.NewInt(2 << 30)
	room := new(big.Int)
	base := big.NewInt(int64(tableSize))
	for n := length.from; n <= length.to && n > 0 && room.Cmp(enough) < 0; n++ {
		room.Add(room, new(big.Int).Exp(base, big.NewInt(int64(n)), nil))
	}
	return room
}

// normalizedPath is the base path of every request; the session ID and the
// sequence number placed in the path are appended to it, so it then ends with
// a slash, which the server's prefix match needs (Xray since 26.7.11).
func (c *requestConfig) normalizedPath() string {
	path := c.path
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if (c.sessionPlacement == placementPath || c.seqPlacement == placementPath) && path[len(path)-1] != '/' {
		path += "/"
	}
	return path
}

func (c *requestConfig) newSessionID() string {
	if c.sessionIDTable != "" {
		id := make([]byte, c.sessionIDLength.rand())
		for i := range id {
			id[i] = c.sessionIDTable[rand.IntN(len(c.sessionIDTable))]
		}
		return string(id)
	}
	return uuid.Must(uuid.NewV4()).String()
}

// chunkSize is the size of one base64 piece of a packet-up upload carried in
// headers or cookies.
func (c *requestConfig) chunkSize() int {
	size := c.uplinkChunkSize
	switch {
	case size.to == 0:
		switch c.uplinkDataPlacement {
		case placementCookie:
			size = valueRange{2 * 1024, 3 * 1024}
		case placementHeader:
			size = valueRange{3000, 4000}
		default:
			size = c.maxEachPostBytes
		}
	case size.from < 64:
		size = valueRange{64, max(64, size.to)}
	}
	return int(size.rand())
}
