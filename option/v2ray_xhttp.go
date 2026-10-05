package option

import (
	"math"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// V2RayXHTTPOptions configures the client of Xray's XHTTP transport. The field
// names follow sing-box-extended, the form other sing-box based cores and the
// configuration generators for them already use.
type V2RayXHTTPOptions struct {
	Mode string `json:"mode,omitempty"`
	V2RayXHTTPBaseOptions
	Download *V2RayXHTTPDownloadOptions `json:"download,omitempty"`
}

type V2RayXHTTPBaseOptions struct {
	Host                 string                 `json:"host,omitempty"`
	Path                 string                 `json:"path,omitempty"`
	Headers              badoption.HTTPHeader   `json:"headers,omitempty"`
	XPaddingBytes        *V2RayXHTTPRange       `json:"x_padding_bytes,omitempty"`
	XPaddingObfsMode     bool                   `json:"x_padding_obfs_mode,omitempty"`
	XPaddingKey          string                 `json:"x_padding_key,omitempty"`
	XPaddingHeader       string                 `json:"x_padding_header,omitempty"`
	XPaddingPlacement    string                 `json:"x_padding_placement,omitempty"`
	XPaddingMethod       string                 `json:"x_padding_method,omitempty"`
	UplinkHTTPMethod     string                 `json:"uplink_http_method,omitempty"`
	SessionPlacement     string                 `json:"session_placement,omitempty"`
	SessionKey           string                 `json:"session_key,omitempty"`
	SessionIDTable       string                 `json:"session_id_table,omitempty"`
	SessionIDLength      *V2RayXHTTPRange       `json:"session_id_length,omitempty"`
	SeqPlacement         string                 `json:"seq_placement,omitempty"`
	SeqKey               string                 `json:"seq_key,omitempty"`
	UplinkDataPlacement  string                 `json:"uplink_data_placement,omitempty"`
	UplinkDataKey        string                 `json:"uplink_data_key,omitempty"`
	UplinkChunkSize      *V2RayXHTTPRange       `json:"uplink_chunk_size,omitempty"`
	NoGRPCHeader         bool                   `json:"no_grpc_header,omitempty"`
	ScMaxEachPostBytes   *V2RayXHTTPRange       `json:"sc_max_each_post_bytes,omitempty"`
	ScMinPostsIntervalMs *V2RayXHTTPRange       `json:"sc_min_posts_interval_ms,omitempty"`
	Xmux                 *V2RayXHTTPXmuxOptions `json:"xmux,omitempty"`

	// Server side settings, accepted so that a configuration shared with an XHTTP
	// server loads, and not used by the client.
	NoSSEHeader          bool             `json:"no_sse_header,omitempty"`
	ScMaxBufferedPosts   int64            `json:"sc_max_buffered_posts,omitempty"`
	ScStreamUpServerSecs *V2RayXHTTPRange `json:"sc_stream_up_server_secs,omitempty"`
	ServerMaxHeaderBytes int              `json:"server_max_header_bytes,omitempty"`
}

type V2RayXHTTPXmuxOptions struct {
	MaxConcurrency   *V2RayXHTTPRange `json:"max_concurrency,omitempty"`
	MaxConnections   *V2RayXHTTPRange `json:"max_connections,omitempty"`
	CMaxReuseTimes   *V2RayXHTTPRange `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTimes *V2RayXHTTPRange `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs *V2RayXHTTPRange `json:"h_max_reusable_secs,omitempty"`
	HKeepAlivePeriod int64            `json:"h_keep_alive_period,omitempty"`
}

// V2RayXHTTPDownloadOptions moves the download half of a session to another
// server: its own address, TLS, outbound to dial through and XHTTP request shape.
type V2RayXHTTPDownloadOptions struct {
	V2RayXHTTPBaseOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Detour string `json:"detour,omitempty"`
}

// V2RayXHTTPRange is an inclusive range of integers, a value is drawn from it
// at random. It reads as "from-to", as one number in a string or as a plain
// number (Xray's forms) and as {"from": a, "to": b}. A reversed range is
// swapped, as Xray does.
type V2RayXHTTPRange struct {
	From int32
	To   int32
}

func (r V2RayXHTTPRange) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return json.Marshal(strconv.FormatInt(int64(r.From), 10))
	}
	return json.Marshal(strconv.FormatInt(int64(r.From), 10) + "-" + strconv.FormatInt(int64(r.To), 10))
}

func (r *V2RayXHTTPRange) UnmarshalJSON(content []byte) error {
	var (
		from, to int64
		err      error
	)
	switch {
	case len(content) > 0 && content[0] == '"':
		var value string
		err = json.Unmarshal(content, &value)
		if err == nil {
			from, to, err = parseXHTTPRange(value)
		}
	case len(content) > 0 && content[0] == '{':
		var value struct {
			From int64 `json:"from"`
			To   int64 `json:"to"`
		}
		err = json.Unmarshal(content, &value)
		from, to = value.From, value.To
	default:
		err = json.Unmarshal(content, &from)
		to = from
	}
	if err != nil {
		return E.Cause(err, "invalid range, expected \"from-to\", a number or {\"from\", \"to\"}")
	}
	if from < math.MinInt32 || from > math.MaxInt32 || to < math.MinInt32 || to > math.MaxInt32 {
		return E.New("range out of bounds: ", string(content))
	}
	if from > to {
		from, to = to, from
	}
	r.From, r.To = int32(from), int32(to)
	return nil
}

// parseXHTTPRange reads "n", "from-to" and the negative forms "-n-m" and
// "-n--m" (Xray's ParseRangeString); an empty string is 0.
func parseXHTTPRange(value string) (int64, int64, error) {
	if value == "" {
		return 0, 0, nil
	}
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		return number, number, nil
	}
	separator := strings.Index(value[1:], "-")
	if separator < 0 {
		return 0, 0, E.New("invalid range: ", value)
	}
	separator++
	from, err := strconv.ParseInt(value[:separator], 10, 64)
	if err != nil {
		return 0, 0, E.New("invalid range: ", value)
	}
	to, err := strconv.ParseInt(value[separator+1:], 10, 64)
	if err != nil {
		return 0, 0, E.New("invalid range: ", value)
	}
	return from, to, nil
}
