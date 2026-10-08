package tlsspoof

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const PlatformSupported = true

const (
	// Values of enum { TCP_NO_QUEUE, TCP_RECV_QUEUE, TCP_SEND_QUEUE } from
	// include/net/tcp.h; not exported by golang.org/x/sys/unix.
	tcpRecvQueue = 1
	tcpSendQueue = 2
	// TCPI_OPT_TIMESTAMPS of include/uapi/linux/tcp.h, a bit of tcp_info.tcpi_options
	tcpInfoOptionTimestamps = 1
)

type linuxSpoofer struct {
	method      Method
	tcpConn     *net.TCPConn
	src         netip.AddrPort
	dst         netip.AddrPort
	rawFD       int
	rawSockAddr unix.Sockaddr
	sendNext    uint32
	receiveNext uint32
	timestamp   uint32
}

// The raw socket is opened when the forged ClientHello is sent (Inject), not here. A
// handshake that fails before its first write is ended by closing the underlying
// connection, which does not reach the spoofer: a socket opened here would stay open
// for the life of the process.
func newRawSpoofer(conn net.Conn, method Method) (rawSpoofer, error) {
	tcpConn, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	return &linuxSpoofer{
		method:  method,
		tcpConn: tcpConn,
		src:     src,
		dst:     dst,
		rawFD:   -1,
	}, nil
}

func (s *linuxSpoofer) open() error {
	fd, sockaddr, err := openLinuxRawSocket(s.dst)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return E.Cause(err, "CAP_NET_RAW and CAP_NET_ADMIN are needed (sing-box run as root)")
		}
		return err
	}
	s.rawFD = fd
	s.rawSockAddr = sockaddr
	err = s.followConnection(s.tcpConn)
	if err != nil {
		return err
	}
	return s.loadSequenceNumbers(s.tcpConn)
}

// followConnection makes the raw socket send the way the connection does: with its mark,
// through its device, from its address. Routing takes all three from the socket, not
// from the packet, so a raw socket without them is routed by the destination alone, past
// the rules the connection was dialed under (routing_mark, bind_interface,
// auto_detect_interface, a rule by source address), and the forged ClientHello may leave
// through another interface than the connection it belongs to.
func (s *linuxSpoofer) followConnection(tcpConn *net.TCPConn) error {
	return control.Conn(tcpConn, func(raw uintptr) error {
		fd := int(raw)
		mark, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
		if err == nil && mark != 0 {
			err = unix.SetsockoptInt(s.rawFD, unix.SOL_SOCKET, unix.SO_MARK, mark)
			if err != nil {
				return E.Cause(err, "set the mark of the connection")
			}
		}
		device, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if err == nil && device != "" {
			err = unix.BindToDevice(s.rawFD, device)
			if err != nil {
				return E.Cause(err, "bind to the device of the connection")
			}
		}
		var local unix.Sockaddr
		if s.src.Addr().Is4() {
			local = &unix.SockaddrInet4{Addr: s.src.Addr().As4()}
		} else {
			local6 := &unix.SockaddrInet6{Addr: s.src.Addr().As16()}
			if zone := s.src.Addr().Zone(); zone != "" {
				zoneInterface, err := net.InterfaceByName(zone)
				if err != nil {
					return E.Cause(err, "find the interface of the local address")
				}
				local6.ZoneId = uint32(zoneInterface.Index)
			}
			local = local6
		}
		err = unix.Bind(s.rawFD, local)
		if err != nil {
			return E.Cause(err, "bind to the local address of the connection")
		}
		return nil
	})
}

func openLinuxRawSocket(dst netip.AddrPort) (int, unix.Sockaddr, error) {
	if dst.Addr().Is4() {
		return openIPv4RawSocket(dst)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, E.Cause(err, "open AF_INET6 SOCK_RAW")
	}
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	if err != nil {
		unix.Close(fd)
		return -1, nil, E.Cause(err, "set IPV6_HDRINCL")
	}
	// Linux raw IPv6 sockets interpret sin6_port as a nexthdr protocol number
	// (see raw(7)); any value other than 0 or the socket's IPPROTO_TCP causes
	// sendto to fail with EINVAL. The destination is already encoded in the
	// user-supplied IPv6 header under IPV6_HDRINCL.
	sockaddr := &unix.SockaddrInet6{Addr: dst.Addr().As16()}
	return fd, sockaddr, nil
}

// loadSequenceNumbers puts the socket briefly into TCP_REPAIR mode to read
// snd_nxt and rcv_nxt from the kernel. TCP_REPAIR requires CAP_NET_ADMIN;
// callers must run as root or grant both CAP_NET_RAW and CAP_NET_ADMIN.
//
// If the TCP_REPAIR_OFF revert fails, the socket would stay in TCP_REPAIR
// state and subsequent Write() calls would silently buffer instead of sending.
// Surface that error so callers can abort.
func (s *linuxSpoofer) loadSequenceNumbers(tcpConn *net.TCPConn) error {
	return control.Conn(tcpConn, func(raw uintptr) (err error) {
		fd := int(raw)

		if s.method == MethodWrongTimestamp {
			// a peer that has not agreed on timestamps does not look at the option: it
			// would take the forged ClientHello, in sequence and with a valid checksum,
			// for the data of the connection
			info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
			if err != nil {
				return E.Cause(err, "read TCP_INFO")
			}
			if info.Options&tcpInfoOptionTimestamps == 0 {
				return E.New("wrong-timestamp needs TCP timestamps, and this connection has none; use another spoof_method")
			}
			timestamp, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
			if err != nil {
				return E.Cause(err, "read timestamp")
			}
			s.timestamp = uint32(timestamp)
		}

		err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
		if err != nil {
			return E.Cause(err, "enter TCP_REPAIR (need CAP_NET_ADMIN)")
		}
		defer func() {
			// without the window probe that leaving the plain way sends: a segment before
			// the ClientHello that no connection of its own sends
			offErr := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF_NO_WP)
			if errors.Is(offErr, unix.EINVAL) { // Linux before 4.19
				offErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)
			}
			if err == nil && offErr != nil {
				err = E.Cause(offErr, "leave TCP_REPAIR")
			}
		}()

		err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue)
		if err != nil {
			return E.Cause(err, "select TCP_SEND_QUEUE")
		}
		sendSequence, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			return E.Cause(err, "read send queue sequence")
		}
		err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRecvQueue)
		if err != nil {
			return E.Cause(err, "select TCP_RECV_QUEUE")
		}
		receiveSequence, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			return E.Cause(err, "read recv queue sequence")
		}
		s.sendNext = uint32(sendSequence)
		s.receiveNext = uint32(receiveSequence)
		return nil
	})
}

func (s *linuxSpoofer) Inject(payload []byte) error {
	defer s.Close()
	err := s.open()
	if err != nil {
		return err
	}
	frame, err := buildSpoofFrame(s.method, s.src, s.dst, s.sendNext, s.receiveNext, s.timestamp, nil, payload)
	if err != nil {
		return err
	}
	err = unix.Sendto(s.rawFD, frame, 0, s.rawSockAddr)
	if err != nil {
		return E.Cause(err, "sendto raw socket")
	}
	return nil
}

func (s *linuxSpoofer) Close() error {
	if s.rawFD < 0 {
		return nil
	}
	err := unix.Close(s.rawFD)
	s.rawFD = -1
	return err
}
