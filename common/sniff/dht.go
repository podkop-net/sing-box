package sniff

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// DHT detects a message of the BitTorrent DHT (KRPC, BEP 5) (podkop-engine). The whole packet is
// one bencoded dictionary with a transaction id "t" and a type "y": "q", a query with its method
// "q" and its arguments "a"; "r", a response with "r"; or "e", an error with "e". A client sends
// DHT, uTP and the UDP tracker over one socket, and its first packet is a DHT query, which decides
// the protocol of the whole socket.
func DHT(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if len(packet) == 0 || packet[0] != 'd' {
		return os.ErrInvalid
	}
	keys := make(map[string]byte, 8)
	end, valid := bencodeDictionary(packet, 0, 0, keys)
	if !valid || end != len(packet) || keys["t"] != 's' || keys["y"] != 's' {
		return os.ErrInvalid
	}
	switch kind, _ := bencodeTopString(packet, "y"); kind {
	case "q":
		if keys["q"] != 's' || keys["a"] != 'd' {
			return os.ErrInvalid
		}
	case "r":
		if keys["r"] != 'd' {
			return os.ErrInvalid
		}
	case "e":
		if keys["e"] != 'l' {
			return os.ErrInvalid
		}
	default:
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// bencodeMaxDepth bounds the nesting a packet may make the scanner follow.
const bencodeMaxDepth = 8

// bencodeValue skips the bencoded value at offset and returns where it ends and its kind: 's' a
// string, 'i' an integer, 'l' a list, 'd' a dictionary.
func bencodeValue(packet []byte, offset int, depth int) (int, byte, bool) {
	if offset >= len(packet) || depth > bencodeMaxDepth {
		return 0, 0, false
	}
	switch c := packet[offset]; {
	case c == 'i':
		i := offset + 1
		if i < len(packet) && packet[i] == '-' {
			i++
		}
		digits := i
		for i < len(packet) && packet[i] >= '0' && packet[i] <= '9' {
			i++
		}
		if i == digits || i >= len(packet) || packet[i] != 'e' {
			return 0, 0, false
		}
		return i + 1, 'i', true
	case c >= '0' && c <= '9':
		end, valid := bencodeString(packet, offset)
		return end, 's', valid
	case c == 'l':
		i := offset + 1
		for i < len(packet) && packet[i] != 'e' {
			var valid bool
			i, _, valid = bencodeValue(packet, i, depth+1)
			if !valid {
				return 0, 0, false
			}
		}
		if i >= len(packet) {
			return 0, 0, false
		}
		return i + 1, 'l', true
	case c == 'd':
		end, valid := bencodeDictionary(packet, offset, depth, nil)
		return end, 'd', valid
	}
	return 0, 0, false
}

// bencodeString skips the string at offset, its length, a colon and its bytes.
func bencodeString(packet []byte, offset int) (int, bool) {
	length, i := 0, offset
	for i < len(packet) && packet[i] >= '0' && packet[i] <= '9' {
		length = length*10 + int(packet[i]-'0')
		if length > len(packet) {
			return 0, false
		}
		i++
	}
	if i == offset || i >= len(packet) || packet[i] != ':' {
		return 0, false
	}
	end := i + 1 + length
	if end > len(packet) {
		return 0, false
	}
	return end, true
}

// bencodeDictionary skips the dictionary at offset; keys, when not nil, gets the kind of the value
// of each of its keys.
func bencodeDictionary(packet []byte, offset int, depth int, keys map[string]byte) (int, bool) {
	i := offset + 1
	for i < len(packet) && packet[i] != 'e' {
		keyEnd, valid := bencodeString(packet, i)
		if !valid {
			return 0, false
		}
		var kind byte
		var valueEnd int
		valueEnd, kind, valid = bencodeValue(packet, keyEnd, depth+1)
		if !valid {
			return 0, false
		}
		if keys != nil {
			colon := i
			for packet[colon] != ':' {
				colon++
			}
			keys[string(packet[colon+1:keyEnd])] = kind
		}
		i = valueEnd
	}
	if i >= len(packet) {
		return 0, false
	}
	return i + 1, true
}

// bencodeTopString returns the value of a string key of the dictionary that is the packet.
func bencodeTopString(packet []byte, key string) (string, bool) {
	i := 1
	for i < len(packet) && packet[i] != 'e' {
		keyEnd, valid := bencodeString(packet, i)
		if !valid {
			return "", false
		}
		colon := i
		for packet[colon] != ':' {
			colon++
		}
		valueEnd, kind, valid := bencodeValue(packet, keyEnd, 1)
		if !valid {
			return "", false
		}
		if string(packet[colon+1:keyEnd]) == key && kind == 's' {
			valueColon := keyEnd
			for packet[valueColon] != ':' {
				valueColon++
			}
			return string(packet[valueColon+1 : valueEnd]), true
		}
		i = valueEnd
	}
	return "", false
}
