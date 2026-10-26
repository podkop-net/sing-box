//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// An outbound over QUIC with a uTLS fingerprint gets the TLS client QUIC can use (the
// fingerprint dropped): with it its every connection failed.
func TestQUICClientOptionsDropUTLS(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	options := option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
	}
	config, err := NewClient(context.Background(), logger, "example.org", options)
	require.NoError(t, err)
	_, err = config.STDConfig()
	require.Error(t, err, "uTLS has no form QUIC can use")

	quicOptions := QUICClientOptions(logger, options)
	require.Nil(t, quicOptions.UTLS)
	require.NotNil(t, options.UTLS, "the options of the caller were changed")
	config, err = NewClient(context.Background(), logger, "example.org", quicOptions)
	require.NoError(t, err)
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)
	require.Equal(t, "example.org", stdConfig.ServerName)

	plain := option.OutboundTLSOptions{Enabled: true, ServerName: "example.org"}
	require.Equal(t, plain, QUICClientOptions(logger, plain))
}
