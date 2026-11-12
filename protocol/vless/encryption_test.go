package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/vless/encryption"

	"github.com/stretchr/testify/require"
)

// silentServer accepts connections and never answers.
func silentServer(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return listener.Addr().String()
}

func encryptionDialer(t *testing.T) *vlessDialer {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	client, err := encryption.NewClient(encryption.Prefix + ".native.1rtt." + base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
	require.NoError(t, err)
	return &vlessDialer{encryption: client}
}

// A server that does not answer the handshake holds it no longer than the dial is waited
// for: the connection is closed with the context.
func TestEncryptEndsWithTheDial(t *testing.T) {
	t.Parallel()
	for name, end := range map[string]func(ctx context.Context) (context.Context, context.CancelFunc, error){
		"deadline": func(ctx context.Context) (context.Context, context.CancelFunc, error) {
			ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			return ctx, cancel, context.DeadlineExceeded
		},
		"cancel": func(ctx context.Context) (context.Context, context.CancelFunc, error) {
			ctx, cancel := context.WithCancel(ctx)
			time.AfterFunc(300*time.Millisecond, cancel)
			return ctx, cancel, context.Canceled
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, err := net.Dial("tcp", silentServer(t))
			require.NoError(t, err)
			defer conn.Close()
			ctx, cancel, expected := end(context.Background())
			defer cancel()
			startAt := time.Now()
			_, err = encryptionDialer(t).encrypt(ctx, conn)
			require.ErrorIs(t, err, expected)
			require.Less(t, time.Since(startAt), 5*time.Second)
			_, err = conn.Write([]byte("x"))
			require.Error(t, err, "the connection is closed")
		})
	}
}

// Without the setting the connection is passed as it is.
func TestEncryptWithoutSetting(t *testing.T) {
	t.Parallel()
	conn, err := net.Dial("tcp", silentServer(t))
	require.NoError(t, err)
	defer conn.Close()
	same, err := (&vlessDialer{}).encrypt(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, conn, same)
}
