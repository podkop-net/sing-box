package sharelink

import (
	"context"
	"reflect"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// The options of sing-box that no link has a name for.
//
// A link names an option of the outbound by its path in the configuration, after "sb.":
// "sb.tls.fragment=1", "sb.multiplex.protocol=h2mux", "sb.transport.headers.User-Agent=...".
// The value is read by the type the option has in this very sing-box: a flag as 1 or 0,
// a list by commas, anything else as the configuration writes it, in JSON when it begins
// with a bracket. The names a few clients already use are read as the options they stand
// for (linkAliases).
//
// A link is somebody else's text. It may tune how its own server is reached, and nothing
// more: what points at other objects of the configuration, chooses the local route, reads
// local files or turns on a feature of the system is not for a link to set (deniedOption).

// optionTypes are the options of the outbound types a link makes.
var optionTypes = map[string]reflect.Type{
	C.TypeVLESS:       reflect.TypeOf(option.VLESSOutboundOptions{}),
	C.TypeTrojan:      reflect.TypeOf(option.TrojanOutboundOptions{}),
	C.TypeShadowsocks: reflect.TypeOf(option.ShadowsocksOutboundOptions{}),
	C.TypeSOCKS:       reflect.TypeOf(option.SOCKSOutboundOptions{}),
	C.TypeHysteria2:   reflect.TypeOf(option.Hysteria2OutboundOptions{}),
	C.TypeTUIC:        reflect.TypeOf(option.TUICOutboundOptions{}),
	C.TypeVMess:       reflect.TypeOf(option.VMessOutboundOptions{}),
	C.TypeHTTP:        reflect.TypeOf(option.HTTPOutboundOptions{}),
	C.TypeHysteria:    reflect.TypeOf(option.HysteriaOutboundOptions{}),
	C.TypeAnyTLS:      reflect.TypeOf(option.AnyTLSOutboundOptions{}),
	C.TypeNaive:       reflect.TypeOf(option.NaiveOutboundOptions{}),
}

// linkAliases are the names clients use in links for options of sing-box: tfo and
// tcp-fast-open (sing-box-extended), uot and udp-over-tcp (mihomo), the rest Throne's.
// The bare "mux" and "fragment" are not among them: clients mean different things by each.
var linkAliases = map[string]string{
	"tfo":                         "tcp_fast_open",
	"tcp-fast-open":               "tcp_fast_open",
	"tcp_fast_open":               "tcp_fast_open",
	"uot":                         "udp_over_tcp",
	"udp-over-tcp":                "udp_over_tcp",
	"tls_fragment":                "tls.fragment",
	"tls_record_fragment":         "tls.record_fragment",
	"tls_fragment_fallback_delay": "tls.fragment_fallback_delay",
	"tls_spoof":                   "tls.spoof",
	"tls_spoof_method":            "tls.spoof_method",
	"mux_protocol":                "multiplex.protocol",
	"mux_max_connections":         "multiplex.max_connections",
	"mux_min_streams":             "multiplex.min_streams",
	"mux_max_streams":             "multiplex.max_streams",
	"mux_padding":                 "multiplex.padding",
	"brutal_up_mbps":              "multiplex.brutal.up_mbps",
	"brutal_down_mbps":            "multiplex.brutal.down_mbps",
}

// The options a link does not set, by the name of the option at any depth.
var deniedNames = map[string]string{
	// other objects of the configuration
	"detour": "another object", "domain_resolver": "another object", "netns": "another object", "http_client": "another object",
	// the local route
	"bind_interface": "the local route", "inet4_bind_address": "the local route", "inet6_bind_address": "the local route",
	"bind_address_no_port": "the local route", "reuse_addr": "the local route", "routing_mark": "the local route",
	"protect_path": "the local route", "network_strategy": "the local route", "network_type": "the local route",
	"fallback_network_type": "the local route", "fallback_delay": "the local route",
	// features of the system
	"engine": "the system", "kernel_tx": "the system", "kernel_rx": "the system",
	// the Hysteria realm: other servers are asked, and ports of the gateway opened
	"realm": "another service",
	// deprecated: a run ends at one about to be removed
	"domain_strategy": "deprecated", "pq_signature_schemes_enabled": "deprecated", "dynamic_record_sizing_disabled": "deprecated",
	"recv_window_conn": "deprecated", "recv_window": "deprecated", "disable_mtu_discovery": "deprecated",
}

// What a link says by itself: the type of the outbound, its name and its server.
var linkOptions = map[string]bool{"type": true, "tag": true, "server": true, "server_port": true}

// deniedOption tells why a link may not set an option, by its name and by how the option
// is declared: a reference to another object, an option left out of the schema, a file.
func deniedOption(name string, field *reflect.StructField) string {
	if reason, denied := deniedNames[name]; denied {
		return reason
	}
	// tcp_multi_path is not a path
	if strings.HasSuffix(name, "_path") && name != "tcp_multi_path" {
		return "a local file"
	}
	if field != nil {
		if _, isReference := field.Tag.Lookup("reference"); isReference {
			return "another object"
		}
		if field.Tag.Get("schema") == "omit" {
			return "deprecated"
		}
	}
	return ""
}

// Structures of options with several shapes keep the shapes in fields left out of JSON,
// and write the one that their type names. unionMembers maps the type to the field.
var unionMembers = map[string]string{
	"http":        "HTTPOptions",
	"ws":          "WebsocketOptions",
	"quic":        "QUICOptions",
	"grpc":        "GRPCOptions",
	"httpupgrade": "HTTPUpgradeOptions",
	"xhttp":       "XHTTPOptions",
	"gecko":       "GeckoOptions",
}

type optionField struct {
	field reflect.StructField
	// the union member the field belongs to, if any
	member string
}

// jsonFields lists the options a structure has, by their names in JSON, each with every
// field of that name: the shapes of a union may have options of one name.
func jsonFields(structType reflect.Type) map[string][]optionField {
	fields := make(map[string][]optionField)
	collectFields(structType, "", fields)
	return fields
}

func collectFields(structType reflect.Type, member string, fields map[string][]optionField) {
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if !field.IsExported() {
			continue
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		tag, hasTag := field.Tag.Lookup("json")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case name == "-":
			if fieldType.Kind() == reflect.Struct {
				collectFields(fieldType, field.Name, fields)
			}
		case field.Anonymous && (!hasTag || name == "") && fieldType.Kind() == reflect.Struct:
			collectFields(fieldType, member, fields)
		case name != "":
			fields[name] = append(fields[name], optionField{field, member})
		}
	}
}

// optionType finds the type of the option at a path, as this sing-box declares it, and
// whether it is a value of a map (a header). node is what the outbound has at the path so
// far: it tells the shape of a union.
func optionType(valueType reflect.Type, segments []string, node *object, walked string) (reflect.Type, bool, error) {
	mapValue := valueType.Kind() == reflect.Map
	if mapValue {
		valueType = valueType.Elem()
	}
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if len(segments) == 0 {
		return valueType, mapValue, nil
	}
	name := segments[0]
	walked = strings.TrimPrefix(walked+"."+name, ".")
	var child *object
	if node != nil {
		child, _ = node.values[name].(*object)
	}
	switch valueType.Kind() {
	case reflect.Struct:
		name = strings.ToLower(name)
		candidates := jsonFields(valueType)[name]
		if len(candidates) == 0 {
			return nil, false, refuse("sb-unknown", "this sing-box has no option ", walked)
		}
		chosen := candidates[0]
		if node != nil {
			member := unionMembers[strings.ToLower(node.text("type"))]
			for _, candidate := range candidates {
				if candidate.member != "" && candidate.member == member {
					chosen = candidate
				}
			}
		}
		if reason := deniedOption(name, &chosen.field); reason != "" {
			return nil, false, refuse("sb-denied", "the option ", walked, " is not for a link to set (", reason, ")")
		}
		if chosen.field.Type.Kind() == reflect.Map && len(segments) > 1 {
			// the next name is a key of the map
			return optionType(chosen.field.Type, segments[2:], nil, walked+"."+segments[1])
		}
		return optionType(chosen.field.Type, segments[1:], child, walked)
	default:
		return nil, false, refuse("sb-unknown", "this sing-box has no option ", walked)
	}
}

var (
	unmarshalerType        = reflect.TypeOf((*interface{ UnmarshalJSON([]byte) error })(nil)).Elem()
	contextUnmarshalerType = reflect.TypeOf((*json.ContextUnmarshaler)(nil)).Elem()
)

func readsItself(valueType reflect.Type) bool {
	pointer := reflect.PointerTo(valueType)
	return pointer.Implements(unmarshalerType) || pointer.Implements(contextUnmarshalerType)
}

func fits(valueType reflect.Type, content []byte) bool {
	return json.UnmarshalContext(context.Background(), content, reflect.New(valueType).Interface()) == nil
}

// optionValue reads the text of a link parameter as a value of the type: a flag as 1, 0,
// true or false, a list by commas, JSON when the text begins with a bracket or a quote,
// and for a type that reads itself, the first of these that it takes. whole is for a
// value that is not split by commas: a header has commas of its own.
func optionValue(valueType reflect.Type, text string, whole bool) (any, bool) {
	trimmed := strings.TrimSpace(text)
	quoted, _ := json.Marshal(text)
	var candidates [][]byte
	if trimmed != "" && strings.ContainsRune(`{["`, rune(trimmed[0])) {
		candidates = append(candidates, []byte(trimmed))
	}
	list := func() []byte {
		elementType := valueType.Elem()
		var items []json.RawMessage
		for _, item := range strings.Split(text, ",") {
			value, fit := optionValue(elementType, strings.TrimSpace(item), true)
			if !fit {
				return nil
			}
			content, err := json.Marshal(value)
			if err != nil {
				return nil
			}
			items = append(items, content)
		}
		content, _ := json.Marshal(items)
		return content
	}
	flag := func() []byte {
		switch strings.ToLower(trimmed) {
		case "1", "true":
			return []byte("true")
		case "0", "false":
			return []byte("false")
		}
		return nil
	}
	plain := func() []byte {
		if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
			return []byte(trimmed)
		}
		return nil
	}
	if readsItself(valueType) {
		if valueType.Kind() == reflect.Slice && !whole {
			candidates = append(candidates, list())
		}
		candidates = append(candidates, quoted, plain(), flag())
	} else {
		switch valueType.Kind() {
		case reflect.Bool:
			candidates = append(candidates, flag())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			candidates = append(candidates, plain())
		case reflect.String:
			candidates = append(candidates, quoted)
		case reflect.Slice:
			if valueType.Elem().Kind() == reflect.Uint8 {
				candidates = append(candidates, quoted)
			} else if !whole {
				candidates = append(candidates, list())
			}
		}
	}
	for _, candidate := range candidates {
		if candidate == nil || !fits(valueType, candidate) {
			continue
		}
		value, err := parseValue(candidate)
		if err != nil {
			continue
		}
		return value, true
	}
	return nil, false
}

// fallback sets the options a link names by their paths ("sb.<path>") and by the names
// of other clients. A path wins over what the link says otherwise, and a name of another
// client over nothing: it is skipped when the scheme has read it itself.
func (d *decoder) fallback(outboundType string, options *object) error {
	type setting struct {
		key  string // the parameter, as the link writes it
		path string
		text string
	}
	var settings []setting
	for key, text := range d.query {
		if path, isAlias := linkAliases[key]; isAlias && !d.known[key] {
			settings = append(settings, setting{d.names[key], path, text})
		}
	}
	for key, text := range d.query {
		if strings.HasPrefix(key, "sb.") {
			// the path with the case the link writes: a header has one
			name := d.names[key]
			settings = append(settings, setting{name, name[len(name)-len(key)+len("sb."):], text})
		}
	}
	if len(settings) == 0 {
		return nil
	}
	sort.SliceStable(settings, func(i, j int) bool {
		iPath, jPath := strings.HasPrefix(strings.ToLower(settings[i].key), "sb."), strings.HasPrefix(strings.ToLower(settings[j].key), "sb.")
		if iPath != jPath {
			return jPath
		}
		return settings[i].key < settings[j].key
	})
	structType, known := optionTypes[outboundType]
	if !known {
		return E.New("no options are known for the outbound type ", outboundType)
	}
	for _, entry := range settings {
		d.reads(strings.ToLower(entry.key))
		segments := strings.Split(entry.path, ".")
		for _, segment := range segments {
			if segment == "" {
				return refuse("sb-unknown", "the link parameter ", entry.key, " names no option")
			}
		}
		if linkOptions[strings.ToLower(segments[0])] {
			return refuse("sb-denied", "the option ", strings.ToLower(segments[0]), " is not for a link parameter to set (the link)")
		}
		valueType, mapValue, err := optionType(structType, segments, options, "")
		if err != nil {
			if strings.HasPrefix(strings.ToLower(entry.key), "sb.") {
				return err
			}
			// the name of another client for an option this outbound does not have
			d.warn(entry.key, " is not an option of this outbound and is ignored")
			continue
		}
		value, fit := optionValue(valueType, entry.text, mapValue)
		if !fit {
			return refuse("sb-value", "the value of the link parameter ", entry.key, " does not fit the option")
		}
		path := lowerOptionNames(structType, segments)
		if previous, exists := options.at(path); exists {
			previousJSON, _ := json.Marshal(previous)
			valueJSON, _ := json.Marshal(value)
			if string(previousJSON) != string(valueJSON) {
				d.warn(entry.key, " replaces what the link sets otherwise")
			}
		}
		options.set(path, value)
	}
	d.notEnabled(structType, options, "")
	return nil
}

// lowerOptionNames gives a path with the names of options in lower case, as the
// configuration has them, and the keys of maps as written.
func lowerOptionNames(valueType reflect.Type, segments []string) string {
	path := make([]string, 0, len(segments))
	for _, segment := range segments {
		for valueType.Kind() == reflect.Pointer {
			valueType = valueType.Elem()
		}
		switch valueType.Kind() {
		case reflect.Struct:
			segment = strings.ToLower(segment)
			candidates := jsonFields(valueType)[segment]
			if len(candidates) == 0 {
				return strings.Join(append(path, segment), ".")
			}
			valueType = candidates[0].field.Type
		case reflect.Map:
			valueType = valueType.Elem()
		}
		path = append(path, segment)
	}
	return strings.Join(path, ".")
}

// notEnabled warns of a group of options that has a switch, has options set and is not
// switched on: sing-box would not use it.
func (d *decoder) notEnabled(valueType reflect.Type, node *object, path string) {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct || node == nil {
		return
	}
	fields := jsonFields(valueType)
	if switches, hasSwitch := fields["enabled"]; hasSwitch && switches[0].field.Type.Kind() == reflect.Bool && path != "" && !node.empty() {
		if enabled, _ := node.values["enabled"].(bool); !enabled {
			d.warn(path, " has options and is not enabled (sb.", path, ".enabled=1): it is not used")
		}
	}
	for _, name := range node.keys {
		child, isObject := node.values[name].(*object)
		if !isObject || len(fields[name]) == 0 {
			continue
		}
		d.notEnabled(fields[name][0].field.Type, child, strings.TrimPrefix(path+"."+name, "."))
	}
}
