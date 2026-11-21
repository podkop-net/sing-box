//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestUTLSClientCertificateServerName(t *testing.T) {
	t.Parallel()
	testCertificateServerName(t, &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"})
}

func TestUTLSClientPinnedAuthority(t *testing.T) {
	t.Parallel()
	testPinnedAuthority(t, &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"})
}

func TestRealityRefusesCertificateServerName(t *testing.T) {
	t.Parallel()
	_, err := NewClientWithOptions(ClientOptions{Context: context.Background(), Logger: logger.NOP(), Options: option.OutboundTLSOptions{
		Enabled:               true,
		ServerName:            "a.example",
		UTLS:                  &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:               &option.OutboundRealityOptions{Enabled: true, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		CertificateServerName: badoption.Listable[string]{"b.example"},
	}})
	require.ErrorContains(t, err, "certificate_server_name is unavailable in reality")
}
