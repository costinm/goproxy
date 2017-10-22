package goproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func orFatal(msg string, err error, t *testing.T) {
	if err != nil {
		t.Fatal(msg, err)
	}
}

func init() {
	GoproxyCa, goproxyCaErr := tls.X509KeyPair(CA_CERT, CA_KEY)
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIICSjCCAbWgAwIBAgIBADALBgkqhkiG9w0BAQUwSjEjMCEGA1UEChMaZ2l0aHVi
LmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1Yi5jb20vZWxhemFy
bC9nb3Byb3h5MB4XDTAwMDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowSjEjMCEG
A1UEChMaZ2l0aHViLmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1
Yi5jb20vZWxhemFybC9nb3Byb3h5MIGdMAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEA
vz9BbCaJjxs73Tvcq3leP32hAGerQ1RgvlZ68Z4nZmoVHfl+2Nr/m0dmW+GdOfpT
cs/KzfJjYGr/84x524fiuR8GdZ0HOtXJzyF5seoWnbBIuyr1PbEpgRhGQMqqOUuj
YExeLbfNHPIoJ8XZ1Vzyv3YxjbmjWA+S/uOe9HWtDbMCAwEAAaNGMEQwDgYDVR0P
AQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8w
DAYDVR0RBAUwA4IBKjALBgkqhkiG9w0BAQUDgYEAIcL8huSmGMompNujsvePTUnM
oEUKtX4Eh/+s+DSfV/TyI0I+3GiPpLplEgFWuoBIJGios0r1dKh5N0TGjxX/RmGm
qo7E4jjJuo8Gs5U8/fgThZmshax2lwLtbRNwhvUVr65GdahLsZz8I+hySLuatVvR
qHHq/FQORIiNyNpq/Hg=
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC/P0FsJomPGzvdO9yreV4/faEAZ6tDVGC+VnrxnidmahUd+X7Y
2v+bR2Zb4Z05+lNyz8rN8mNgav/zjHnbh+K5HwZ1nQc61cnPIXmx6hadsEi7KvU9
sSmBGEZAyqo5S6NgTF4tt80c8ignxdnVXPK/djGNuaNYD5L+4570da0NswIDAQAB
AoGBALzIv1b4D7ARTR3NOr6V9wArjiOtMjUrdLhO+9vIp9IEA8ZsA9gjDlCEwbkP
VDnoLjnWfraff5Os6+3JjHy1fYpUiCdnk2XA6iJSL1XWKQZPt3wOunxP4lalDgED
QTRReFbA/y/Z4kSfTXpVj68ytcvSRW/N7q5/qRtbN9804jpBAkEA0s6lvH2btSLA
mcEdwhs7zAslLbdld7rvfUeP82gPPk0S6yUqTNyikqshM9AwAktHY7WvYdKl+ghZ
HTxKVC4DoQJBAOg/IAW5RbXknP+Lf7AVtBgw3E+Yfa3mcdLySe8hjxxyZq825Zmu
Rt5Qj4Lw6ifSFNy4kiiSpE/ZCukYvUXGENMCQFkPxSWlS6tzSzuqQxBGwTSrYMG3
wb6b06JyIXcMd6Qym9OMmBpw/J5KfnSNeDr/4uFVWQtTG5xO+pdHaX+3EQECQQDl
qcbY4iX1gWVfr2tNjajSYz751yoxVbkpiT9joiQLVXYFvpu+JYEfRzsjmWl0h2Lq
AftG8/xYmaEYcMZ6wSrRAkBUwiom98/8wZVlB6qbwhU1EKDFANvICGSWMIhPx3v7
MJqTIj4uJhte2/uyVvZ6DC6noWYgy+kLgqG0S97tUEG8
-----END RSA PRIVATE KEY-----`)

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h))
}

func getBrowser(args []string) string {
	for i, arg := range args {
		if arg == "-browser" && i+1 < len(arg) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-browser=") {
			return arg[len("-browser="):]
		}
	}
	return ""
}

func TestSingerTls(t *testing.T) {
	cert, err := signHost(GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal("singHost", err, t)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal("ParseCertificate", err, t)
	expected := "key verifies with Go"
	server := httptest.NewUnstartedServer(ConstantHanlder(expected))
	defer server.Close()
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert, GoproxyCa}}
	server.TLS.BuildNameToCertificate()
	server.StartTLS()
	certpool := x509.NewCertPool()
	certpool.AddCert(GoproxyCa.Leaf)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certpool},
	}
	asLocalhost := strings.Replace(server.URL, "127.0.0.1", "localhost", -1)
	req, err := http.NewRequest("GET", asLocalhost, nil)
	orFatal("NewRequest", err, t)
	resp, err := tr.RoundTrip(req)
	orFatal("RoundTrip", err, t)
	txt, err := ioutil.ReadAll(resp.Body)
	orFatal("ioutil.ReadAll", err, t)
	if string(txt) != expected {
		t.Errorf("Expected '%s' got '%s'", expected, string(txt))
	}
	browser := getBrowser(os.Args)
	if browser != "" {
		exec.Command(browser, asLocalhost).Run()
		time.Sleep(10 * time.Second)
	}
}

func TestSingerX509(t *testing.T) {
	cert, err := signHost(GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal("singHost", err, t)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal("ParseCertificate", err, t)
	certpool := x509.NewCertPool()
	certpool.AddCert(GoproxyCa.Leaf)
	orFatal("VerifyHostname", cert.Leaf.VerifyHostname("example.com"), t)
	orFatal("CheckSignatureFrom", cert.Leaf.CheckSignatureFrom(GoproxyCa.Leaf), t)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certpool,
	})
	orFatal("Verify", err, t)
}
