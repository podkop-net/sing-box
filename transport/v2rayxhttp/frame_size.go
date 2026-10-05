package v2rayxhttp

import (
	"encoding/binary"
	"io"
	"net"
)

// maxWriteFrameSize is the largest HTTP/2 DATA frame sent to the server, the
// protocol's initial value and what Chrome sends.
const maxWriteFrameSize = 16 * 1024

// frameSizeCapConn lowers the SETTINGS_MAX_FRAME_SIZE of the server's first
// SETTINGS frame to maxWriteFrameSize before the HTTP/2 client reads it.
//
// The client of golang.org/x/net/http2 writes a request body through a
// buffer as large as the server's maximum frame size, up to 512 KiB, held
// until the body ends. A streamed upload (stream-up, stream-one) ends with its
// session, and Xray's server announces 1 MiB: every such session held 512 KiB
// (lab: 300 idle stream-one sessions, 567 KB each). Smaller frames cost a few
// more of them on a bulk upload.
//
// The server's connection preface starts with a SETTINGS frame; a later
// SETTINGS frame raising the size again is left alone.
type frameSizeCapConn struct {
	net.Conn
	done    bool
	pending []byte
}

// maxSettingsFrame bounds the first frame read whole: a SETTINGS frame has
// six bytes per setting, and there are few.
const maxSettingsFrame = 1024

func (c *frameSizeCapConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.done {
		return c.Conn.Read(b)
	}
	c.done = true
	frame := make([]byte, 9, 9+64)
	_, err := io.ReadFull(c.Conn, frame)
	if err != nil {
		return 0, err
	}
	length := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	const frameTypeSettings, flagAck = 0x4, 0x1
	if frame[3] == frameTypeSettings && frame[4]&flagAck == 0 && length <= maxSettingsFrame && length%6 == 0 {
		payload := make([]byte, length)
		_, err = io.ReadFull(c.Conn, payload)
		if err != nil {
			return 0, err
		}
		const settingMaxFrameSize = 0x5
		for i := 0; i+6 <= len(payload); i += 6 {
			if binary.BigEndian.Uint16(payload[i:]) == settingMaxFrameSize && binary.BigEndian.Uint32(payload[i+2:]) > maxWriteFrameSize {
				binary.BigEndian.PutUint32(payload[i+2:], maxWriteFrameSize)
			}
		}
		frame = append(frame, payload...)
	}
	n := copy(b, frame)
	c.pending = frame[n:]
	return n, nil
}

func (c *frameSizeCapConn) Upstream() any {
	return c.Conn
}
