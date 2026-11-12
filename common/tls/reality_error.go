package tls

import E "github.com/sagernet/sing/common/exceptions"

// ErrRealityVerification is the failure of a handshake with a REALITY server that did not prove to
// be it (podkop-engine): the certificate it answered with is not the one REALITY makes for this
// client, as with a wrong public key or short ID, another server at the address, or a server that
// takes this client for a stranger. The error of the handshake is it to errors.Is, has its text in
// front, and unwraps to what the handshake failed with, if it did.
var ErrRealityVerification = E.New("reality verification failed")

// realityVerifyError is a failure of that kind.
type realityVerifyError struct {
	// after the text of ErrRealityVerification: what may be the cause
	note  string
	cause error
}

func (e *realityVerifyError) Error() string {
	message := ErrRealityVerification.Error() + e.note
	if e.cause != nil {
		message += ": " + e.cause.Error()
	}
	return message
}

func (e *realityVerifyError) Is(target error) bool {
	return target == ErrRealityVerification
}

func (e *realityVerifyError) Unwrap() error {
	return e.cause
}
