package rule

import (
	"context"
	"net/http"
	"net/url"

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

// resolveDownloader resolves the downloader of the http client the rule-set downloads with, when
// that client has outbounds: none for the deprecated download_detour, nor with a manager that
// has no downloaders.
func (s *RemoteRuleSet) resolveDownloader() (adapter.HTTPDownloader, error) {
	downloaders, loaded := service.FromContext[adapter.HTTPClientManager](s.ctx).(adapter.HTTPDownloaders)
	if !loaded {
		return nil, nil
	}
	switch {
	case s.options.RemoteOptions.HTTPClient != nil && !s.options.RemoteOptions.HTTPClient.IsEmpty():
		return downloaders.ResolveDownloader(s.options.RemoteOptions.HTTPClient)
	case s.options.RemoteOptions.DownloadDetour != "": //nolint:staticcheck
		return nil, nil
	}
	return downloaders.ResolveDownloader(nil)
}

// fetchWays downloads the list through the ways of the downloader. A body that does not parse
// (a page of an ISP served with status 200) fails its way, and the other ways go on.
func (s *RemoteRuleSet) fetchWays(ctx context.Context, isStart bool) error {
	etag := s.lastEtag
	var host string
	if parsed, err := url.Parse(s.url); err == nil {
		host = parsed.Hostname()
	}
	way, err := s.downloader.Download(ctx, host, func(ctx context.Context, way string, client *http.Client, progress func(int)) (any, error) {
		return s.download(ctx, client, isStart, etag, progress)
	}, func(way string, result any) error {
		return s.apply(result.(*ruleSetFetched))
	})
	if err != nil {
		return err
	}
	s.logger.Debug("rule-set ", s.tag, " came through ", way)
	return nil
}
