package httpclient

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// The fallbacks of a client are the shared transports of the tags it names, in their order: of
// the default client, of a client named by tag, of inline options. A tag that names no client,
// or the client itself, is an error.
func TestResolveFallbacks(t *testing.T) {
	clients := []option.HTTPClient{
		{Tag: "lists", Fallback: badoption.Listable[string]{"via-b", "via-a"}},
		{Tag: "via-a"},
		{Tag: "via-b"},
		{Tag: "loop", Fallback: badoption.Listable[string]{"loop"}},
		{Tag: "lost", Fallback: badoption.Listable[string]{"nowhere"}},
	}
	manager := NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"), clients, "lists")
	for _, tag := range []string{"via-a", "via-b"} {
		manager.sharedTransports[tag] = &sharedManagedTransport{managed: &ManagedTransport{tag: tag}, shared: &sharedState{}}
	}
	tags := func(fallbacks []adapter.HTTPFallback) []string {
		var result []string
		for _, fallback := range fallbacks {
			result = append(result, fallback.Tag)
			require.Equal(t, fallback.Tag, fallback.Transport.(*sharedRef).managed.tag)
		}
		return result
	}
	fallbacks, err := manager.ResolveFallbacks(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"via-b", "via-a"}, tags(fallbacks))
	fallbacks, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Tag: "lists"})
	require.NoError(t, err)
	require.Equal(t, []string{"via-b", "via-a"}, tags(fallbacks))
	fallbacks, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Fallback: badoption.Listable[string]{"via-a"}})
	require.NoError(t, err)
	require.Equal(t, []string{"via-a"}, tags(fallbacks))
	fallbacks, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Tag: "via-a"})
	require.NoError(t, err)
	require.Empty(t, fallbacks)
	_, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Tag: "loop"})
	require.ErrorContains(t, err, "names the client itself")
	_, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Tag: "lost"})
	require.ErrorContains(t, err, "http_client not found: nowhere")
	_, err = manager.ResolveFallbacks(&option.HTTPClientOptions{Tag: "unknown"})
	require.ErrorContains(t, err, "http_client not found: unknown")
	// no client is defined: the default one has no fallbacks
	fallbacks, err = NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"), nil, "").ResolveFallbacks(nil)
	require.NoError(t, err)
	require.Empty(t, fallbacks)
}

// the option round-trips through JSON, by tag or inline
func TestFallbackOptionJSON(t *testing.T) {
	var client option.HTTPClient
	require.NoError(t, client.UnmarshalJSON([]byte(`{"tag":"lists","fallback":["via-a","via-b"]}`)))
	require.Equal(t, badoption.Listable[string]{"via-a", "via-b"}, client.Fallback)
	content, err := client.MarshalJSON()
	require.NoError(t, err)
	var again option.HTTPClient
	require.NoError(t, again.UnmarshalJSON(content))
	require.Equal(t, client.Fallback, again.Fallback)
}
