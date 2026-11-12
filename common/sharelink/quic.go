package sharelink

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// portRanges reads a list of ports as the Hysteria links write it, "443,5000-6000", into
// the ranges sing-box takes, "443:443" and "5000:6000".
func portRanges(list string) ([]string, error) {
	var ranges []string
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		from, to, isRange := strings.Cut(item, "-")
		if !isRange {
			from, to, isRange = strings.Cut(item, ":")
		}
		if !isRange {
			to = from
		}
		for _, port := range []string{from, to} {
			number, err := strconv.ParseUint(port, 10, 16)
			if err != nil || number == 0 {
				return nil, E.New("invalid port in the list of ports")
			}
		}
		ranges = append(ranges, from+":"+to)
	}
	return ranges, nil
}

// megabits reads a speed in Mbps: a number, with or without the unit some clients add.
func megabits(value string) int {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(value[end:])) {
	case "", "m", "mb", "mbps":
	default:
		return 0
	}
	number, err := strconv.Atoi(value[:end])
	if err != nil {
		return 0
	}
	return number
}

// hopPorts takes a list of ports from the place of the port, "host:443,5000-6000", as
// Hysteria 2 writes it, and gives the link back with one port there.
func hopPorts(body string) (string, string) {
	at := strings.LastIndexByte(body, '@')
	hostStart := at + 1
	end := len(body)
	if slash := strings.IndexByte(body[hostStart:], '/'); slash >= 0 {
		end = hostStart + slash
	}
	hostPort := body[hostStart:end]
	colon := strings.LastIndexByte(hostPort, ':')
	if colon < 0 || strings.HasSuffix(hostPort, "]") {
		return body, ""
	}
	ports := hostPort[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return body, ""
	}
	first := ports
	if index := strings.IndexAny(ports, ",-"); index >= 0 {
		first = ports[:index]
	}
	return body[:hostStart] + hostPort[:colon+1] + first + body[end:], ports
}

// hysteria2 reads a Hysteria 2 link, as its project defines it:
// "hysteria2://[auth@]host[:ports]/?parameters#name", also as "hy2://".
func (d *decoder) hysteria2() (any, error) {
	d.reads("obfs", "obfs-password", "mport", "up", "down", "upmbps", "downmbps", "fm")
	body, ports := hopPorts(d.body)
	user, _, server, _, err := parseAuthority(body, 443)
	if err != nil {
		return nil, err
	}
	options := option.Hysteria2OutboundOptions{
		ServerOptions: server,
		Password:      user,
		UpMbps:        megabits(d.first("upmbps", "up")),
		DownMbps:      megabits(d.first("downmbps", "down")),
	}
	if ports == "" {
		ports = d.query["mport"]
	}
	if ports != "" {
		ranges, err := portRanges(ports)
		if err != nil {
			return nil, err
		}
		options.ServerPorts = badoption.Listable[string](ranges)
	}
	if obfs := strings.ToLower(d.query["obfs"]); obfs != "" && obfs != "none" && obfs != "plain" {
		if !plainWord(obfs) {
			return nil, E.New("unsupported obfuscation of Hysteria 2")
		}
		options.Obfs = &option.Hysteria2Obfs{Type: obfs, Password: d.query["obfs-password"]}
	}
	err = d.hysteria2Mask(&options)
	if err != nil {
		return nil, err
	}
	options.TLS = d.tlsAlways()
	return options, nil
}

// hysteria2Mask reads "fm", the finalmask of Xray, in a Hysteria 2 link: Remnawave writes
// the obfuscation, the port hopping and the speeds of its Hysteria inbounds there.
func (d *decoder) hysteria2Mask(options *option.Hysteria2OutboundOptions) error {
	content := strings.TrimSpace(d.query["fm"])
	if content == "" {
		return nil
	}
	var mask struct {
		UDP []struct {
			Type     string `json:"type"`
			Settings struct {
				Password string `json:"password"`
			} `json:"settings"`
		} `json:"udp"`
		QUIC struct {
			BrutalUp   vmessText `json:"brutalUp"`
			BrutalDown vmessText `json:"brutalDown"`
			UDPHop     struct {
				Ports    vmessText `json:"ports"`
				Interval vmessText `json:"interval"`
			} `json:"udpHop"`
		} `json:"quicParams"`
	}
	err := json.Unmarshal([]byte(content), &mask)
	if err != nil {
		d.warn("fm (finalmask) cannot be read and is ignored")
		return nil
	}
	for _, entry := range mask.UDP {
		switch strings.ToLower(entry.Type) {
		case "salamander":
			if options.Obfs == nil {
				options.Obfs = &option.Hysteria2Obfs{Type: "salamander", Password: entry.Settings.Password}
			}
		case "noise":
		default:
			return refuse("finalmask", "fm (finalmask) asks for the mask", shown(entry.Type), ", which is not supported: the server expects it")
		}
	}
	if ports := string(mask.QUIC.UDPHop.Ports); ports != "" && len(options.ServerPorts) == 0 {
		ranges, err := portRanges(ports)
		if err != nil {
			return err
		}
		options.ServerPorts = badoption.Listable[string](ranges)
		// seconds; a range of them is how often Xray hops, between the two
		interval, _, _ := strings.Cut(string(mask.QUIC.UDPHop.Interval), "-")
		if seconds, err := strconv.Atoi(strings.TrimSpace(interval)); err == nil && seconds > 0 {
			err = options.HopInterval.UnmarshalJSON([]byte(strconv.Quote(strconv.Itoa(seconds) + "s")))
			if err != nil {
				return E.New("invalid hop interval in fm")
			}
		}
	}
	if options.UpMbps == 0 {
		options.UpMbps = megabits(string(mask.QUIC.BrutalUp))
	}
	if options.DownMbps == 0 {
		options.DownMbps = megabits(string(mask.QUIC.BrutalDown))
	}
	return nil
}

// hysteria reads a link of the first Hysteria:
// "hysteria://host:port?protocol=udp&auth=...&peer=...&upmbps=...&downmbps=...#name".
func (d *decoder) hysteria() (any, error) {
	d.reads("protocol", "auth", "upmbps", "downmbps", "obfs", "obfsparam", "mport")
	_, _, server, _, err := parseAuthority(d.body, 0)
	if err != nil {
		return nil, err
	}
	if protocol := strings.ToLower(d.query["protocol"]); protocol != "" && protocol != "udp" {
		return nil, refuse("hysteria-protocol", "the Hysteria protocol", shown(protocol), " is not supported, only udp")
	}
	options := option.HysteriaOutboundOptions{
		ServerOptions: server,
		AuthString:    d.query["auth"],
		UpMbps:        megabits(d.query["upmbps"]),
		DownMbps:      megabits(d.query["downmbps"]),
	}
	switch obfs := d.query["obfs"]; {
	case obfs == "" || strings.EqualFold(obfs, "none"):
	case strings.EqualFold(obfs, "xplus"):
		options.Obfs = d.query["obfsparam"]
	default:
		return nil, refuse("hysteria-obfs", "the Hysteria obfuscation", shown(obfs), " is not supported, only xplus")
	}
	if ports := d.query["mport"]; ports != "" {
		ranges, err := portRanges(ports)
		if err != nil {
			return nil, err
		}
		options.ServerPorts = badoption.Listable[string](ranges)
	}
	options.TLS = d.tlsAlways()
	return options, nil
}

// tuic reads a TUIC link: "tuic://uuid:password@host:port?parameters#name".
func (d *decoder) tuic() (any, error) {
	d.reads("congestion_control", "congestion-control", "udp_relay_mode", "udp-relay-mode", "udp_over_stream",
		"zero_rtt_handshake", "reduce_rtt", "reduce-rtt", "heartbeat_interval", "heartbeat")
	user, _, server, _, err := parseAuthority(d.body, 443)
	if err != nil {
		return nil, err
	}
	uuid, password, hasPassword := strings.Cut(user, ":")
	if !hasPassword {
		// TUIC v4 had a token here; sing-box speaks v5, with a UUID and a password
		return nil, refuse("tuic-v4", "a TUIC link without a password is of TUIC v4, which is not supported")
	}
	if !isUUID(uuid) {
		return nil, E.New("the user of the link is not a UUID and a password")
	}
	if d.query["alpn"] == "" {
		// sing-box offers no ALPN of its own for TUIC, as it does for Hysteria; which
		// servers take that is their configuration
		d.warn("the link names no ALPN and none is offered: a TUIC server that has one set (h3, as a rule) refuses such a client, add alpn=h3 to the link then")
	}
	options := option.TUICOutboundOptions{
		ServerOptions:     server,
		UUID:              uuid,
		Password:          password,
		CongestionControl: d.first("congestion_control", "congestion-control"),
		UDPRelayMode:      d.first("udp_relay_mode", "udp-relay-mode"),
		UDPOverStream:     isTrue(d.query["udp_over_stream"]),
		ZeroRTTHandshake:  isTrue(d.first("zero_rtt_handshake", "reduce_rtt", "reduce-rtt")),
	}
	if heartbeat := d.first("heartbeat_interval", "heartbeat"); heartbeat != "" {
		// a duration; a bare number is seconds
		if _, err := strconv.Atoi(heartbeat); err == nil {
			heartbeat += "s"
		}
		err = options.Heartbeat.UnmarshalJSON([]byte(strconv.Quote(heartbeat)))
		if err != nil {
			return nil, E.New("invalid duration in the link parameter heartbeat_interval")
		}
	}
	options.TLS = d.tlsAlways()
	return options, nil
}
