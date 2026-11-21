package option

// FinalMaskOptions are the masks put on the TCP connections an outbound opens itself, as
// Xray's finalmask (streamSettings.finalmask) puts them: they change how the bytes go over
// the wire, not the bytes. Only the masks the server does not see are taken: "fragment".
// Through a detour an outbound opens no connection of its own, and the masks do nothing.
// The list is chained as Xray chains it: the first mask takes the writes first, the last
// one is nearest to the socket.
type FinalMaskOptions struct {
	TCP []FinalMaskTCPOptions `json:"tcp,omitempty"`
}

// FinalMaskTCPOptions is one mask of the TCP list. "fragment" is Xray's fragment mask
// (transport/internet/finalmask/fragment of Xray-core):
//
//   - packets "tlshello": the first write, when it is a whole TLS record of the handshake
//     (the ClientHello), is cut into TLS records of the lengths below; with a single delay
//     of 0 the records go out in one write, otherwise each in a write of its own, the delay
//     after it.
//   - packets "N-M": the writes N to M of the connection (from 1) are cut into pieces of the
//     lengths below, each a write of its own; "" cuts every write.
//
// length or lengths (a range per piece, the last one for the rest) are required; delay or
// delays are milliseconds (none: 0); max_split bounds the number of pieces (0: none), the
// last piece takes what remains. A range is "from-to", a number, or {"from", "to"}.
type FinalMaskTCPOptions struct {
	Type     string            `json:"type"`
	Packets  string            `json:"packets,omitempty"`
	Length   *V2RayXHTTPRange  `json:"length,omitempty"`
	Lengths  []V2RayXHTTPRange `json:"lengths,omitempty"`
	Delay    *V2RayXHTTPRange  `json:"delay,omitempty"`
	Delays   []V2RayXHTTPRange `json:"delays,omitempty"`
	MaxSplit *V2RayXHTTPRange  `json:"max_split,omitempty"`
}
