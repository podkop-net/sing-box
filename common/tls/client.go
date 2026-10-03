package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-box/common/badtls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func NewDialerFromOptions(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer, serverAddress string, options option.OutboundTLSOptions) (N.Dialer, error) {
	if !options.Enabled {
		return dialer, nil
	}
	config, err := NewClientWithOptions(ClientOptions{
		Context:       ctx,
		Logger:        logger,
		ServerAddress: serverAddress,
		Options:       options,
	})
	if err != nil {
		return nil, err
	}
	return NewDialer(dialer, config), nil
}

func NewClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return NewClientWithOptions(ClientOptions{
		Context:       ctx,
		Logger:        logger,
		ServerAddress: serverAddress,
		Options:       options,
	})
}

type ClientOptions struct {
	Context        context.Context
	Logger         logger.ContextLogger
	ServerAddress  string
	Options        option.OutboundTLSOptions
	KTLSCompatible bool
}

func NewClientWithOptions(options ClientOptions) (Config, error) {
	if !options.Options.Enabled {
		return nil, nil
	}
	if !options.KTLSCompatible {
		if options.Options.KernelTx {
			options.Logger.Warn("enabling kTLS TX in current scenarios will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_tx")
		}
	}
	if options.Options.KernelRx {
		options.Logger.Warn("enabling kTLS RX will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_rx")
	}
	if options.Options.Reality != nil && options.Options.Reality.Enabled {
		return NewRealityClient(options.Context, options.Logger, options.ServerAddress, options.Options)
	} else if options.Options.UTLS != nil && options.Options.UTLS.Enabled {
		return NewUTLSClient(options.Context, options.Logger, options.ServerAddress, options.Options)
	}
	return NewSTDClient(options.Context, options.Logger, options.ServerAddress, options.Options)
}

func ClientHandshake(ctx context.Context, conn net.Conn, config Config) (Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	tlsConn, err := aTLS.ClientHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}

// withReadWait gives a client connection the read waiter of badtls, as ClientHandshake
// does (podkop-engine): the dialer of the proxy protocols returned the bare connection,
// so the copy loop took a buffer before every blocking read and an idle proxied
// connection held it for as long as the server stayed silent. With the read waiter the
// buffer is taken only once a whole record has arrived. A connection badtls cannot handle
// is kept as it is, unlike in ClientHandshake: a change in the layout of crypto/tls or
// utls must cost the read waiter, not every TLS dial.
func withReadWait(tlsConn Conn) Conn {
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn
	}
	if err != os.ErrInvalid {
		readWaitFailure.Do(func() {
			log.StdLogger().Warn("TLS read waiter unavailable: ", err)
		})
	}
	return tlsConn
}

var readWaitFailure sync.Once

type Dialer interface {
	N.Dialer
	DialTLSContext(ctx context.Context, destination M.Socksaddr) (Conn, error)
}

type defaultDialer struct {
	dialer N.Dialer
	config Config
}

func NewDialer(dialer N.Dialer, config Config) Dialer {
	return &defaultDialer{dialer, config}
}

func (d *defaultDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	return d.DialTLSContext(ctx, destination)
}

func (d *defaultDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (d *defaultDialer) DialTLSContext(ctx context.Context, destination M.Socksaddr) (Conn, error) {
	return d.dialContext(ctx, destination, true)
}

func (d *defaultDialer) dialContext(ctx context.Context, destination M.Socksaddr, echRetry bool) (Conn, error) {
	conn, err := d.dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return nil, err
	}
	// The handshake is bounded as in ClientHandshake above (and by handshake_timeout in
	// 1.14, same default): a server that accepts the connection and never answers the
	// ClientHello kept a dial waiting for as long as its caller did, which for a proxied
	// connection has no deadline (podkop-engine).
	handshakeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	tlsConn, err := aTLS.ClientHandshake(handshakeCtx, conn, d.config)
	cancel()
	if err != nil {
		conn.Close()
		var echErr *tls.ECHRejectionError
		if echRetry && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			if echConfig, isECH := d.config.(ECHCapableConfig); isECH {
				echConfig.SetECHConfigList(echErr.RetryConfigList)
				return d.dialContext(ctx, destination, false)
			}
		}
		return nil, err
	}
	return withReadWait(tlsConn), nil
}

func (d *defaultDialer) Upstream() any {
	return d.dialer
}
