package sharelink

import (
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
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
// the obfuscation, the port hopping and the speeds of its Hysteria inbounds there. What the
// link says itself (obfs, a list of ports) stands, apart from the packet size of salamander:
// that makes Xray's gecko, which Remnawave writes into the link as obfs=salamander too.
func (d *decoder) hysteria2Mask(options *option.Hysteria2OutboundOptions) error {
	content := strings.TrimSpace(d.query["fm"])
	if content == "" {
		return nil
	}
	var mask struct {
		UDP []struct {
			Type     string          `json:"type"`
			Settings json.RawMessage `json:"settings"`
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
		kind := strings.ToLower(entry.Type)
		switch kind {
		case "noise":
			d.warn("fm (finalmask): the mask noise is not applied: it is the client's own")
		case "salamander", "udphop":
		case "realm":
			return refuse("hysteria-realm", "fm (finalmask) asks for the realm of Hysteria, which a link does not set: it has other servers asked, and may open ports of the gateway")
		default:
			return refuse("finalmask", "fm (finalmask) asks for the mask", shown(entry.Type), ", which is not supported: the server expects it")
		}
	}
	for _, entry := range mask.UDP {
		var err error
		switch strings.ToLower(entry.Type) {
		case "salamander":
			err = d.salamanderMask(options, entry.Settings)
		case "udphop":
			err = d.udpHopMask(options, entry.Settings)
		}
		if err != nil {
			return err
		}
	}
	if ports := string(mask.QUIC.UDPHop.Ports); ports != "" && len(options.ServerPorts) == 0 {
		ranges, err := portRanges(ports)
		if err != nil {
			return err
		}
		options.ServerPorts = badoption.Listable[string](ranges)
		// seconds; a range of them is how often Xray hops, between the two
		from, to, _ := strings.Cut(string(mask.QUIC.UDPHop.Interval), "-")
		err = hopInterval(options, from, to)
		if err != nil {
			return err
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

// hopInterval sets how often the ports hop from a range of seconds: hop_interval, and
// hop_interval_max when the range has two ends. Under 5 s Xray refuses it, and sing-quic
// refuses every connection (hysteria/hop.go).
func hopInterval(options *option.Hysteria2OutboundOptions, from, to string) error {
	least, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil || least <= 0 {
		return nil
	}
	if least < 5 {
		return E.New("fm (finalmask): the interval of the port hopping is under 5 s")
	}
	most, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil {
		most = least
	}
	options.HopInterval = badoption.Duration(time.Duration(least) * time.Second)
	if most > least {
		options.HopIntervalMax = badoption.Duration(time.Duration(most) * time.Second)
	}
	return nil
}

// salamanderMask reads the salamander mask. With a packet size Xray makes it gecko
// (infra/conf Salamander.Build): the same framing as the gecko of sing-box (a flag 0x80,
// a header of 5 bytes, 2 to 8 chunks, under salamander), which then replaces what obfs of
// the link says.
func (d *decoder) salamanderMask(options *option.Hysteria2OutboundOptions, content json.RawMessage) error {
	var settings struct {
		Password   string                  `json:"password"`
		PacketSize *option.V2RayXHTTPRange `json:"packetSize"`
	}
	if len(content) > 0 && string(content) != "null" {
		if err := json.Unmarshal(content, &settings); err != nil {
			// the server expects the obfuscation: without it nothing connects (Xray refuses it too)
			return E.New("fm (finalmask): the salamander mask cannot be read")
		}
	}
	if settings.PacketSize != nil && settings.PacketSize.To > 0 {
		least, most := int(settings.PacketSize.From), int(settings.PacketSize.To)
		if least <= 0 || most > 2048 || least > most {
			return E.New("fm (finalmask): the packet size of gecko is not between 1 and 2048 bytes")
		}
		options.Obfs = &option.Hysteria2Obfs{
			Type:         C.Hysteria2ObfsTypeGecko,
			Password:     settings.Password,
			GeckoOptions: option.Hysteria2ObfsGecko{MinPacketSize: least, MaxPacketSize: most},
		}
		return nil
	}
	if options.Obfs == nil {
		options.Obfs = &option.Hysteria2Obfs{Type: C.Hysteria2ObfsTypeSalamander, Password: settings.Password}
	}
	return nil
}

// udpHopMask reads the udphop mask, the hopping of Xray's client between ports (and
// addresses): the ports become the server ports of sing-box's hopping, unless the link
// names its own. The server listens on all of them either way.
func (d *decoder) udpHopMask(options *option.Hysteria2OutboundOptions, content json.RawMessage) error {
	var settings struct {
		Mode        string                  `json:"mode"`
		Interval    *option.V2RayXHTTPRange `json:"interval"`
		RemoteIPs   []string                `json:"remoteIPs"`
		RemotePorts json.RawMessage         `json:"remotePorts"`
	}
	if len(content) > 0 && string(content) != "null" {
		if err := json.Unmarshal(content, &settings); err != nil {
			d.warn("fm (finalmask): the udphop mask cannot be read and is ignored")
			return nil
		}
	}
	// Xray moves to the ports of remotePorts only in the modes intervalRemote and
	// perConnRemote (udphop/conn.go); intervalLocal alone keeps the port of the link
	remote := false
	for _, mode := range strings.Split(settings.Mode, ",") {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "intervalremote", "perconnremote":
			remote = true
		case "intervallocal":
		default:
			d.warn("fm (finalmask): udphop of an unknown mode is ignored")
			return nil
		}
	}
	if !remote {
		d.warn("fm (finalmask): udphop of the local port only is not supported and is ignored")
		return nil
	}
	if len(settings.RemoteIPs) > 0 {
		d.warn("fm (finalmask): udphop between addresses (remoteIPs) is not supported, the address of the link is used")
	}
	var ports string
	if len(settings.RemotePorts) > 0 && string(settings.RemotePorts) != "null" {
		var text vmessText
		if err := json.Unmarshal(settings.RemotePorts, &text); err != nil {
			return E.New("fm (finalmask): the ports of udphop cannot be read")
		}
		ports = string(text)
	}
	if strings.TrimSpace(ports) == "" {
		return nil
	}
	if len(options.ServerPorts) == 0 {
		ranges, err := portRanges(ports)
		if err != nil {
			return err
		}
		options.ServerPorts = badoption.Listable[string](ranges)
	}
	// Xray's default is 30 s, sing-box's too
	if options.HopInterval == 0 && settings.Interval != nil && settings.Interval.From > 0 {
		return hopInterval(options, strconv.Itoa(int(settings.Interval.From)), strconv.Itoa(int(settings.Interval.To)))
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
