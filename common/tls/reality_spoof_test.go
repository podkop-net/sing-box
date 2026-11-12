//go:build with_utls && linux

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tlsspoof"

	"github.com/stretchr/testify/require"
)

// A REALITY client takes the spoof options as the other TLS clients do, with their
// checks: the forged name must differ from the server name.
func TestRealityClientTakesSpoof(t *testing.T) {
	logger, _ := newWarnLogger(t)
	options := realityOptionsForTest("chrome", true)
	options.Spoof = "packagist.org"
	options.SpoofMethod = tlsspoof.MethodNameWrongMD5Sig
	config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
	require.NoError(t, err)
	reality, isReality := config.(*RealityClientConfig)
	require.True(t, isReality)
	require.Equal(t, "packagist.org", reality.uClient.spoof)
	require.Equal(t, tlsspoof.MethodWrongMD5Sig, reality.uClient.spoofMethod)

	options.Spoof = options.ServerName
	_, err = NewClient(context.Background(), logger, "192.0.2.1", options)
	require.ErrorContains(t, err, "must differ from `server_name`")

	options.Spoof = "packagist.org"
	options.SpoofMethod = "wrong-everything"
	_, err = NewClient(context.Background(), logger, "192.0.2.1", options)
	require.ErrorContains(t, err, "unknown method")
}
