package rule

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// ruleSetFallback is a fallback client of the rule-set: its tag, for the log.
type ruleSetFallback struct {
	tag    string
	client *http.Client
}

// resolveFallbacks resolves the fallback clients of the http client the rule-set downloads with:
// none for the deprecated download_detour, nor with a manager that has no fallbacks.
func (s *RemoteRuleSet) resolveFallbacks() ([]adapter.HTTPFallback, error) {
	resolver, loaded := service.FromContext[adapter.HTTPClientManager](s.ctx).(adapter.HTTPClientFallbacks)
	if !loaded {
		return nil, nil
	}
	switch {
	case s.options.RemoteOptions.HTTPClient != nil && !s.options.RemoteOptions.HTTPClient.IsEmpty():
		return resolver.ResolveFallbacks(s.options.RemoteOptions.HTTPClient)
	case s.options.RemoteOptions.DownloadDetour != "": //nolint:staticcheck
		return nil, nil
	}
	return resolver.ResolveFallbacks(nil)
}
