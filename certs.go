package goproxy

import (
	"crypto/tls"
	"crypto/x509"
)

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

// CA certificate, loaded with tls.X509KeyPair()
var GoproxyCa tls.Certificate
