package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// errDeviceRequestTimeout is the cause attached to a device request that did not
// complete within PANOS_REQUEST_TIMEOUT. It deliberately does not wrap
// context.DeadlineExceeded: waitJob (tools/device_tools.go:82) and logJobError
// (tools/log_tools.go:312) read a DeadlineExceeded with a live caller context as
// "the job wait ran out, the job is still running", which is not what a stalled
// device request means.
var errDeviceRequestTimeout = errors.New("device request timed out")

// deviceTLSConfig builds the TLS policy for device connections: verification on
// unless cfg.SkipVerify, trusting pool when it is non-nil (PANOS_CA_CERT) and the
// system roots otherwise.
func deviceTLSConfig(cfg *Config, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs: pool,
		//nolint:gosec // G402: mirrors the explicit PANOS_SKIP_VERIFY opt-in; LoadConfig rejects the CA+skip-verify combination, so this is false whenever a CA pool is in use
		InsecureSkipVerify: cfg.SkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}

// deviceTransport clones http.DefaultTransport, which keeps its proxy
// (NO_PROXY) and its dial, TLS-handshake and idle timeouts, and replaces the TLS
// config. It speaks HTTP/1.1 only: a timed-out HTTP/1.1 request closes its
// connection so the next request redials, whereas a timed-out HTTP/2 stream
// leaves a shared connection open, and net/http returns the deadline cause
// directly only on HTTP/1.1.
func deviceTransport(tc *tls.Config) (*http.Transport, error) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("cannot build device transport: http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}
	t := dt.Clone()
	t.TLSClientConfig = tc
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
	return t, nil
}

// newPangoTransport builds the transport handed to pango. pango's Client.Transport
// is a *http.Transport and Setup wraps it in its own http.Client (pango client.go:61,
// :287-297 @ efa4357), so a RoundTripper cannot be assigned to it directly. Instead
// the returned (outer) transport has deadlineTransport registered for "https" with
// (*http.Transport).RegisterProtocol; net/http consults a registered protocol
// before dialing (net/http transport.go:643-651, go1.27.4), and the HTTP/1-only
// Protocols setting keeps net/http from registering its own https handler over it
// (transport.go:465-468 and :476-478, http2.go:284-294). The wrapper delegates to a second
// transport that does the dialing, so every request pango sends, startup included,
// gets one whole-exchange deadline. Both transports take their TLS policy from
// deviceTLSConfig.
//
// "http" is registered to refuse: a redirect from https to plain http would
// otherwise bypass the wrapper and carry pango's API key header in the clear
// (net/http copies it to redirect hops, client.go:820-841).
func newPangoTransport(cfg *Config, pool *x509.CertPool) (*http.Transport, error) {
	inner, err := deviceTransport(deviceTLSConfig(cfg, pool))
	if err != nil {
		return nil, err
	}
	outer, err := deviceTransport(deviceTLSConfig(cfg, pool))
	if err != nil {
		return nil, err
	}
	// The fallback exists for Config literals in tests; LoadConfig always sets the
	// field. A zero value must never mean "expire immediately" or "no deadline".
	timeout := cmp.Or(cfg.RequestTimeout, defaultRequestTimeout)
	outer.RegisterProtocol("https", deadlineTransport{
		next:    inner,
		timeout: timeout,
		cause: fmt.Errorf("%w: no complete response within %s (PANOS_REQUEST_TIMEOUT); a write may still have been applied on the device",
			errDeviceRequestTimeout, timeout),
	})
	outer.RegisterProtocol("http", refusePlainHTTP{})
	return outer, nil
}

// deadlineTransport gives every request one deadline that covers connecting, the
// response headers and the body read. Its fields are set once at construction and
// RoundTrip keeps per-request state only, so it is safe for concurrent use.
type deadlineTransport struct {
	next    http.RoundTripper
	timeout time.Duration
	cause   error
}

// RoundTrip derives the request context with the cap and releases it when the
// response body is closed, not before: pango reads the body after Do returns, so
// a cancel on return would cut every read short.
//
// A context.DeadlineExceeded leaving here means the caller's own deadline fired
// (see errDeviceRequestTimeout), so errors are attributed in this order: the
// caller's context is done, pass the error through; the cap fired, return the
// cause; any other error that matches DeadlineExceeded (a dial or DNS timeout)
// is returned as text without the DeadlineExceeded chain; otherwise pass through.
//
// A 101 Switching Protocols answer is refused: net/http hands the connection to
// the caller on a protocol switch (net/http transport.go:2547-2574, go1.27.4),
// so the deadline would no longer reach the body.
func (d deadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeoutCause(req.Context(), d.timeout, d.cause)
	resp, err := d.next.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		switch {
		case req.Context().Err() != nil:
			return nil, err
		case errors.Is(context.Cause(ctx), d.cause):
			return nil, d.cause
		case errors.Is(err, context.DeadlineExceeded):
			return nil, errors.New("device request: " + err.Error())
		}
		return nil, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		cancel()
		return nil, errors.New("device answered 101 Switching Protocols to an XML API request")
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnClose releases the request context after the body is closed, so the
// HTTP/1.1 connection goes back to the pool before the context ends.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// refusePlainHTTP fails every plain-http request: device requests use https only.
type refusePlainHTTP struct{}

func (refusePlainHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, errors.New("refusing a plain-http device request: device requests use https only")
}
