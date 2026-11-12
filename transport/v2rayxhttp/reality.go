//go:build with_utls

package v2rayxhttp

import "github.com/sagernet/sing-box/common/tls"

func isReality(config tls.Config) bool {
	if kernelTLS, isKernelTLS := config.(*tls.KTLSClientConfig); isKernelTLS {
		config = kernelTLS.Config
	}
	_, isReality := config.(*tls.RealityClientConfig)
	return isReality
}
