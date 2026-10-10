package sharelink

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// VLESS Encryption: the setting of a link is passed as it is written, and with it the
// flow is taken where it is refused without.
func TestVLESSEncryption(t *testing.T) {
	t.Parallel()
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	setting := "mlkem768x25519plus.native.0rtt." + key
	vless := func(link string) option.VLESSOutboundOptions {
		outbound, _, err := Decode(link)
		require.NoError(t, err, link)
		return optionsOf[option.VLESSOutboundOptions](t, outbound)
	}
	// the link that came from the field: xhttp over REALITY
	options := vless(policyBase + "encryption=" + setting + "&security=reality&pbk=" + key + "&sid=ab&sni=s.example.org&fp=firefox&type=xhttp&mode=stream-up&path=%2Fapi")
	require.Equal(t, setting, options.Encryption)
	require.Equal(t, "xhttp", options.Transport.Type)
	// none and nothing are no encryption
	require.Empty(t, vless(policyBase+"encryption=none&security=tls").Encryption)
	require.Empty(t, vless(policyBase+"security=tls").Encryption)
	// the padding and several keys
	long := "mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.50-0-3333." + key + "." + key
	require.Equal(t, long, vless(policyBase+"encryption="+long).Encryption)
	// with the encryption the flow goes over a transport and without TLS, as in Xray
	for _, parameters := range []string{
		"&security=tls&type=xhttp&path=%2Fx",
		"&security=tls&type=ws&path=%2Fws",
		"&security=tls&type=grpc&serviceName=s",
		"&security=none&type=tcp",
		"&security=reality&pbk=" + key,
	} {
		options := vless(policyBase + "encryption=" + setting + "&flow=xtls-rprx-vision" + parameters)
		require.Equal(t, "xtls-rprx-vision", options.Flow, parameters)
		require.Equal(t, setting, options.Encryption, parameters)
	}
	// by its path too
	require.Equal(t, setting, vless(policyBase+"security=tls&sb.encryption="+setting).Encryption)

	// a setting Xray would not take is refused
	for _, bad := range []string{
		"mlkem768x25519plus.native.0rtt.KEY",
		"mlkem768x25519plus.native.0rtt",
		"mlkem768x25519plus.plain.0rtt." + key,
		"mlkem768x25519plus.native.2rtt." + key,
		"mlkem768x25519plus.native.0rtt." + key[:40],
	} {
		require.Equal(t, "vless-encryption", refusalID(t, policyBase+"encryption="+bad), bad)
	}
	// one set by its path as well
	require.Equal(t, "vless-encryption", refusalID(t, policyBase+"security=tls&sb.encryption=mlkem768x25519plus.native.0rtt.KEY"))
	require.Equal(t, "vless-encryption", refusalID(t, policyBase+"security=tls&sb.encryption=aes-128-gcm"))

	// what is said of a refused setting repeats nothing of the link: a second link glued
	// to the first one, a key where the mode belongs, a wrong padding
	for _, bad := range []string{
		"mlkem768x25519plus.native.0rttvless://" + testUUID + "@192.0.2.9:443?security=tls",
		"mlkem768x25519plus." + key + ".native.0rtt",
		"mlkem768x25519plus.native.1rtt.100-s3cret-5." + key,
	} {
		_, _, err := Decode(policyBase + "encryption=" + bad)
		require.Error(t, err, bad)
		for _, piece := range []string{key, testUUID, "192.0.2.9", "vless://", "s3cret"} {
			require.NotContains(t, err.Error(), piece, bad)
		}
	}
}
