//go:build with_utls

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
)

// quicSTDConfig carries over what NewUTLSClient sets for verifying the server;
// a field added there that takes part in the verification must be added here.
func (c *UTLSClientConfig) quicSTDConfig() (*STDConfig, error) {
	config := c.config
	stdConfig := &tls.Config{
		Time:                           config.Time,
		RootCAs:                        config.RootCAs,
		ServerName:                     config.ServerName,
		InsecureSkipVerify:             config.InsecureSkipVerify,
		VerifyPeerCertificate:          config.VerifyPeerCertificate,
		NextProtos:                     slices.Clone(config.NextProtos),
		MinVersion:                     config.MinVersion,
		MaxVersion:                     config.MaxVersion,
		CipherSuites:                   slices.Clone(config.CipherSuites),
		EncryptedClientHelloConfigList: slices.Clone(config.EncryptedClientHelloConfigList),
	}
	for _, certificate := range config.Certificates {
		stdConfig.Certificates = append(stdConfig.Certificates, tls.Certificate{
			Certificate:                 certificate.Certificate,
			PrivateKey:                  certificate.PrivateKey,
			OCSPStaple:                  certificate.OCSPStaple,
			SignedCertificateTimestamps: certificate.SignedCertificateTimestamps,
			Leaf:                        certificate.Leaf,
		})
	}
	if serverName := config.InsecureServerNameToVerify; serverName != "" && !config.InsecureSkipVerify {
		// disable_sni: uTLS checks the name through InsecureServerNameToVerify,
		// crypto/tls has no such field; check it the way STDClientConfig does.
		stdConfig.InsecureSkipVerify = true
		stdConfig.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				Roots:         stdConfig.RootCAs,
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, certificate := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(certificate)
			}
			if stdConfig.Time != nil {
				verifyOptions.CurrentTime = stdConfig.Time()
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
	}
	return stdConfig, nil
}
