package sharelink

import (
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// The settings of XHTTP as Xray writes them (infra/conf, v26.9.9). A link
// carries them as JSON in the "extra" parameter.
type xraySplitHTTP struct {
	Host                 string                  `json:"host"`
	Path                 string                  `json:"path"`
	Mode                 string                  `json:"mode"`
	Headers              map[string]string       `json:"headers"`
	XPaddingBytes        *option.V2RayXHTTPRange `json:"xPaddingBytes"`
	XPaddingObfsMode     bool                    `json:"xPaddingObfsMode"`
	XPaddingKey          string                  `json:"xPaddingKey"`
	XPaddingHeader       string                  `json:"xPaddingHeader"`
	XPaddingPlacement    string                  `json:"xPaddingPlacement"`
	XPaddingMethod       string                  `json:"xPaddingMethod"`
	UplinkHTTPMethod     string                  `json:"uplinkHTTPMethod"`
	SessionIDPlacement   string                  `json:"sessionIDPlacement"`
	SessionIDKey         string                  `json:"sessionIDKey"`
	SessionIDTable       string                  `json:"sessionIDTable"`
	SessionIDLength      *option.V2RayXHTTPRange `json:"sessionIDLength"`
	SeqPlacement         string                  `json:"seqPlacement"`
	SeqKey               string                  `json:"seqKey"`
	UplinkDataPlacement  string                  `json:"uplinkDataPlacement"`
	UplinkDataKey        string                  `json:"uplinkDataKey"`
	UplinkChunkSize      *option.V2RayXHTTPRange `json:"uplinkChunkSize"`
	NoGRPCHeader         bool                    `json:"noGRPCHeader"`
	NoSSEHeader          bool                    `json:"noSSEHeader"`
	ScMaxEachPostBytes   *option.V2RayXHTTPRange `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs *option.V2RayXHTTPRange `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64                   `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs *option.V2RayXHTTPRange `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int32                   `json:"serverMaxHeaderBytes"`
	Xmux                 json.RawMessage         `json:"xmux"`
	DownloadSettings     json.RawMessage         `json:"downloadSettings"`
	Extra                json.RawMessage         `json:"extra"`

	// The names of the session settings before Xray v26.6.22; some panels
	// still write them, alone or next to the new ones.
	SessionPlacement string `json:"sessionPlacement"`
	SessionKey       string `json:"sessionKey"`
	// Settings Xray has dropped, still written by Marzban.
	ScMaxConcurrentPosts json.RawMessage `json:"scMaxConcurrentPosts"`
	KeepAlivePeriod      json.RawMessage `json:"keepAlivePeriod"`
}

type xrayXmux struct {
	MaxConcurrency   *option.V2RayXHTTPRange `json:"maxConcurrency"`
	MaxConnections   *option.V2RayXHTTPRange `json:"maxConnections"`
	CMaxReuseTimes   *option.V2RayXHTTPRange `json:"cMaxReuseTimes"`
	HMaxRequestTimes *option.V2RayXHTTPRange `json:"hMaxRequestTimes"`
	HMaxReusableSecs *option.V2RayXHTTPRange `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64                   `json:"hKeepAlivePeriod"`
}

type xrayStream struct {
	Address           string          `json:"address"`
	Port              uint16          `json:"port"`
	Network           string          `json:"network"`
	Security          string          `json:"security"`
	TLSSettings       json.RawMessage `json:"tlsSettings"`
	REALITYSettings   json.RawMessage `json:"realitySettings"`
	XHTTPSettings     json.RawMessage `json:"xhttpSettings"`
	SplitHTTPSettings json.RawMessage `json:"splithttpSettings"`
}

type xrayTLS struct {
	AllowInsecure bool           `json:"allowInsecure"`
	ServerName    string         `json:"serverName"`
	ALPN          xrayStringList `json:"alpn"`
	Fingerprint   string         `json:"fingerprint"`
}

type xrayREALITY struct {
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	Password    string `json:"password"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

// xrayStringList is a list written as an array or as one comma separated string.
type xrayStringList []string

func (l *xrayStringList) UnmarshalJSON(content []byte) error {
	var list []string
	if err := json.Unmarshal(content, &list); err == nil {
		*l = list
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return err
	}
	*l = splitList(value)
	return nil
}

// readObject reads a JSON object into the Xray structure and reports the keys
// the structure does not have: Xray ignores them, and so does the link, but a
// setting silently dropped is how a link "does not work" with no reason shown.
//
// It returns the keys the object has, in lower case.
func (d *decoder) readObject(name string, content []byte, target any) (map[string]bool, error) {
	err := json.Unmarshal(content, target)
	if err != nil {
		return nil, E.New("read ", name, ": ", plainJSONError(err))
	}
	var keys map[string]json.RawMessage
	err = json.Unmarshal(content, &keys)
	if err != nil {
		return nil, E.New("read ", name, ": ", plainJSONError(err))
	}
	present := make(map[string]bool, len(keys))
	for key := range keys {
		present[strings.ToLower(key)] = true
	}
	known := make(map[string]bool)
	targetType := reflect.TypeOf(target).Elem()
	for i := 0; i < targetType.NumField(); i++ {
		known[strings.ToLower(targetType.Field(i).Tag.Get("json"))] = true
	}
	var unknown []string
	for key := range keys {
		if !known[strings.ToLower(key)] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	for _, key := range unknown {
		d.warn(name, ": ", key, " is not supported and is ignored")
	}
	return present, nil
}

// plainJSONError drops the names of this package's types from an error of the
// JSON decoder.
func plainJSONError(err error) string {
	message := err.Error()
	const marker = "Go struct field "
	if index := strings.Index(message, marker); index >= 0 {
		field := message[index+len(marker):]
		if dot := strings.IndexByte(field, '.'); dot >= 0 {
			field = field[dot+1:]
		}
		if space := strings.IndexByte(field, ' '); space >= 0 {
			field = field[:space]
		}
		return field + " has a value of the wrong type"
	}
	return strings.TrimPrefix(message, "json: ")
}

func (d *decoder) xhttp() (*option.V2RayXHTTPOptions, error) {
	settings := new(xraySplitHTTP)
	var present map[string]bool
	if extra := strings.TrimSpace(d.query["extra"]); extra != "" {
		// escaped twice by some panels and clients
		if strings.HasPrefix(extra, "%7B") || strings.HasPrefix(extra, "%7b") {
			if decoded, err := url.QueryUnescape(extra); err == nil {
				extra = decoded
			}
		}
		var err error
		present, err = d.readObject("extra", []byte(extra), settings)
		if err != nil {
			return nil, err
		}
	}
	// As in Xray, these three always come from the link itself, also when the
	// link leaves them empty and "extra" has them. v2rayA names the mode its
	// own way.
	settings.Host, settings.Path, settings.Mode = d.query["host"], d.query["path"], d.first("mode", "xhttpmode")
	// 3x-ui repeats the padding outside of "extra" under this name
	if !present["xpaddingbytes"] && d.query["x_padding_bytes"] != "" {
		settings.XPaddingBytes = new(option.V2RayXHTTPRange)
		err := settings.XPaddingBytes.UnmarshalJSON([]byte(strconv.Quote(d.query["x_padding_bytes"])))
		if err != nil {
			return nil, E.Cause(err, "read x_padding_bytes")
		}
	}
	err := d.flatSettings(settings, present)
	if err != nil {
		return nil, err
	}
	hasDownload := len(settings.DownloadSettings) > 0 && string(settings.DownloadSettings) != "null"
	if hasDownload && settings.Mode == "stream-one" {
		// as Xray: one request cannot have its download elsewhere
		return nil, E.New("downloadSettings cannot be used with the stream-one mode")
	}
	options := &option.V2RayXHTTPOptions{Mode: settings.Mode}
	options.V2RayXHTTPBaseOptions, err = d.xhttpBase("extra", settings)
	if err != nil {
		return nil, err
	}
	if hasDownload {
		download, err := d.xhttpDownload(settings.DownloadSettings)
		if err != nil {
			return nil, err
		}
		options.Download = download
	}
	return options, nil
}

func nonZero(value *option.V2RayXHTTPRange) *option.V2RayXHTTPRange {
	// zero is "the default" for every range of Xray's
	if value == nil || (value.From == 0 && value.To == 0) {
		return nil
	}
	return value
}

// flatKeys are the settings of XHTTP some generators (3x-ui's panel among
// them) also write as parameters of the link, under Xray's names: the plain
// values, not the objects.
var flatKeys = func() map[string]int {
	keys := make(map[string]int)
	settingsType := reflect.TypeOf(xraySplitHTTP{})
	for i := 0; i < settingsType.NumField(); i++ {
		field := settingsType.Field(i)
		switch field.Name {
		case "Host", "Path", "Mode", "Extra", "ScMaxConcurrentPosts", "KeepAlivePeriod":
			continue
		}
		switch field.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Int32, reflect.Int64, reflect.Pointer:
			key := strings.ToLower(field.Tag.Get("json"))
			keys[key] = i
			knownKeys[key] = true
		}
	}
	return keys
}()

// The session settings have an older name each; one of a pair set in "extra"
// settles both.
var sameSetting = map[string]string{
	"sessionplacement": "sessionidplacement", "sessionidplacement": "sessionplacement",
	"sessionkey": "sessionidkey", "sessionidkey": "sessionkey",
}

// flatSettings fills what "extra" does not mention from the parameters of the
// link: a setting "extra" has, also as false or empty, is settled there.
func (d *decoder) flatSettings(settings *xraySplitHTTP, present map[string]bool) error {
	value := reflect.ValueOf(settings).Elem()
	keys := make([]string, 0, len(flatKeys))
	for key := range flatKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		text := d.query[key]
		field := value.Field(flatKeys[key])
		if text == "" || present[key] || present[sameSetting[key]] {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			field.SetString(text)
		case reflect.Bool:
			field.SetBool(isTrue(text))
		case reflect.Int32, reflect.Int64:
			number, err := strconv.ParseInt(text, 10, 32)
			if err != nil {
				return E.New("invalid number in the link parameter ", key)
			}
			field.SetInt(number)
		case reflect.Pointer:
			valueRange := new(option.V2RayXHTTPRange)
			err := valueRange.UnmarshalJSON([]byte(strconv.Quote(text)))
			if err != nil {
				return E.Cause(err, "read ", key)
			}
			field.Set(reflect.ValueOf(valueRange))
		}
	}
	return nil
}

func (d *decoder) xhttpBase(name string, settings *xraySplitHTTP) (option.V2RayXHTTPBaseOptions, error) {
	options := option.V2RayXHTTPBaseOptions{
		Host:                 settings.Host,
		Path:                 settings.Path,
		XPaddingBytes:        nonZero(settings.XPaddingBytes),
		XPaddingObfsMode:     settings.XPaddingObfsMode,
		XPaddingKey:          settings.XPaddingKey,
		XPaddingHeader:       settings.XPaddingHeader,
		XPaddingPlacement:    settings.XPaddingPlacement,
		XPaddingMethod:       settings.XPaddingMethod,
		UplinkHTTPMethod:     settings.UplinkHTTPMethod,
		SessionPlacement:     settings.SessionIDPlacement,
		SessionKey:           settings.SessionIDKey,
		SessionIDTable:       settings.SessionIDTable,
		SessionIDLength:      nonZero(settings.SessionIDLength),
		SeqPlacement:         settings.SeqPlacement,
		SeqKey:               settings.SeqKey,
		UplinkDataPlacement:  settings.UplinkDataPlacement,
		UplinkDataKey:        settings.UplinkDataKey,
		UplinkChunkSize:      nonZero(settings.UplinkChunkSize),
		NoGRPCHeader:         settings.NoGRPCHeader,
		ScMaxEachPostBytes:   nonZero(settings.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: nonZero(settings.ScMinPostsIntervalMs),
		NoSSEHeader:          settings.NoSSEHeader,
		ScMaxBufferedPosts:   settings.ScMaxBufferedPosts,
		ScStreamUpServerSecs: nonZero(settings.ScStreamUpServerSecs),
		ServerMaxHeaderBytes: int(settings.ServerMaxHeaderBytes),
	}
	if options.SessionPlacement == "" {
		options.SessionPlacement = settings.SessionPlacement
	}
	if options.SessionKey == "" {
		options.SessionKey = settings.SessionKey
	}
	if len(settings.Headers) > 0 {
		headers := make(badoption.HTTPHeader)
		// in the order of the names: with several spellings of Host the result
		// must not depend on the order of a map
		names := make([]string, 0, len(settings.Headers))
		for key := range settings.Headers {
			names = append(names, key)
		}
		sort.Strings(names)
		for _, key := range names {
			value := settings.Headers[key]
			// Xray refuses a Host among the headers; panels put it there for
			// the lack of a host of their own
			if strings.EqualFold(key, "Host") {
				if options.Host == "" {
					options.Host = value
				} else if options.Host != value {
					d.warn(name, ": the Host header is ignored, the host is ", options.Host)
				}
				continue
			}
			headers[key] = badoption.Listable[string]{value}
		}
		if len(headers) > 0 {
			options.Headers = headers
		}
	}
	if len(settings.Xmux) > 0 && string(settings.Xmux) != "null" {
		xmux := new(xrayXmux)
		_, err := d.readObject(name+".xmux", settings.Xmux, xmux)
		if err != nil {
			return options, err
		}
		xmuxOptions := option.V2RayXHTTPXmuxOptions{
			MaxConcurrency:   nonZero(xmux.MaxConcurrency),
			MaxConnections:   nonZero(xmux.MaxConnections),
			CMaxReuseTimes:   nonZero(xmux.CMaxReuseTimes),
			HMaxRequestTimes: nonZero(xmux.HMaxRequestTimes),
			HMaxReusableSecs: nonZero(xmux.HMaxReusableSecs),
			HKeepAlivePeriod: xmux.HKeepAlivePeriod,
		}
		if xmuxOptions != (option.V2RayXHTTPXmuxOptions{}) {
			options.Xmux = &xmuxOptions
		}
	}
	return options, nil
}

// xhttpDownload reads "downloadSettings": a whole stream configuration of
// Xray's, with the address of the server the download half goes to.
func (d *decoder) xhttpDownload(content []byte) (*option.V2RayXHTTPDownloadOptions, error) {
	const name = "downloadSettings"
	stream := new(xrayStream)
	_, err := d.readObject(name, content, stream)
	if err != nil {
		return nil, err
	}
	stream.Address = strings.TrimSuffix(strings.TrimPrefix(stream.Address, "["), "]")
	stream.Network, stream.Security = strings.ToLower(stream.Network), strings.ToLower(stream.Security)
	if stream.Address == "" {
		return nil, E.New(name, ": missing address")
	}
	if stream.Port == 0 {
		return nil, E.New(name, ": missing port")
	}
	switch stream.Network {
	case "", "xhttp", "splithttp":
	default:
		return nil, E.New(name, ": unsupported network: ", stream.Network)
	}
	options := &option.V2RayXHTTPDownloadOptions{
		ServerOptions: option.ServerOptions{Server: stream.Address, ServerPort: stream.Port},
	}
	switch stream.Security {
	case "", "none":
	case "tls":
		tlsSettings := new(xrayTLS)
		if len(stream.TLSSettings) > 0 {
			_, err = d.readObject(name+".tlsSettings", stream.TLSSettings, tlsSettings)
			if err != nil {
				return nil, err
			}
		}
		options.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: tlsSettings.ServerName,
			Insecure:   tlsSettings.AllowInsecure,
			ALPN:       badoption.Listable[string](tlsSettings.ALPN),
		}
		options.TLS.UTLS, err = utlsOptions(tlsSettings.Fingerprint, false)
		if err != nil {
			return nil, E.Cause(err, name)
		}
	case "reality":
		realitySettings := new(xrayREALITY)
		if len(stream.REALITYSettings) > 0 {
			_, err = d.readObject(name+".realitySettings", stream.REALITYSettings, realitySettings)
			if err != nil {
				return nil, err
			}
		}
		// "password" is the name of the public key since Xray v25.x
		publicKey := realitySettings.Password
		if publicKey == "" {
			publicKey = realitySettings.PublicKey
		}
		if publicKey == "" {
			return nil, E.New(name, ": missing REALITY public key")
		}
		utls, err := utlsOptions(realitySettings.Fingerprint, true)
		if err != nil {
			return nil, E.Cause(err, name)
		}
		options.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: realitySettings.ServerName,
			UTLS:       utls,
			Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: publicKey, ShortID: realitySettings.ShortID},
		}
	default:
		return nil, E.New(name, ": unsupported security: ", stream.Security)
	}
	content = stream.XHTTPSettings
	if len(content) == 0 || string(content) == "null" {
		content = stream.SplitHTTPSettings
	}
	settings := new(xraySplitHTTP)
	if len(content) > 0 && string(content) != "null" {
		_, err = d.readObject(name+".xhttpSettings", content, settings)
		if err != nil {
			return nil, err
		}
		// "extra" replaces everything but the host, the path and the mode
		if len(settings.Extra) > 0 && string(settings.Extra) != "null" {
			inner := new(xraySplitHTTP)
			_, err = d.readObject(name+".xhttpSettings.extra", settings.Extra, inner)
			if err != nil {
				return nil, err
			}
			inner.Host, inner.Path, inner.Mode = settings.Host, settings.Path, settings.Mode
			settings = inner
		}
	}
	// The download leg sends GETs only: what says how uploads go is not its.
	settings.UplinkHTTPMethod, settings.UplinkDataPlacement, settings.UplinkDataKey, settings.UplinkChunkSize = "", "", "", nil
	if len(settings.DownloadSettings) > 0 && string(settings.DownloadSettings) != "null" {
		d.warn(name, ": nested downloadSettings are ignored")
	}
	options.V2RayXHTTPBaseOptions, err = d.xhttpBase(name+".xhttpSettings", settings)
	if err != nil {
		return nil, err
	}
	return options, nil
}
