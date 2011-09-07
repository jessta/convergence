package main

/*
	recieve cert from connecting client
	fetch cert or fetch from db and check whether to renew
	compare sha1s
	
	
*/


import (
	"crypto/tls"
	"net"
	"fmt" 
	"crypto"
	"crypto/x509"
)

var config  = &tls.Config{
    // Rand provides the source of entropy for nonces and RSA blinding.
    // If Rand is nil, TLS uses the cryptographic random reader in package
    // crypto/rand.
    //Rand io.Reader
	nil,
    // Time returns the current time as the number of seconds since the epoch.
    // If Time is nil, TLS uses the system time.Seconds.
    //Time func() int64
	nil,
    // Certificates contains one or more certificate chains
    // to present to the other side of the connection.
    // Server configurations must include at least one certificate.
    //Certificates []Certificate
	nil,
    // RootCAs defines the set of root certificate authorities
    // that clients use when verifying server certificates.
    // If RootCAs is nil, TLS uses the host's root CA set.
    //RootCAs *x509.CertPool
nil,
    // NextProtos is a list of supported, application level protocols.
    //NextProtos []string
[]string{"http"},
    // ServerName is included in the client's handshake to support virtual
    // hosting.
    "github.com",

    // AuthenticateClient controls whether a server will request a certificate
    // from the client. It does not require that the client send a
    // certificate nor does it require that the certificate sent be
    // anything more than self-signed.
   false,

    // CipherSuites is a list of supported cipher suites. If CipherSuites
    // is nil, TLS uses a list of suites supported by the implementation.
    nil,
}
type Cert struct{
	cert *x509.Certificate
	sum []byte	
}

var certs = map[string]*Cert{}

func FetchCert(address string) *Cert{
	//is cert in db?
	cert,ok := certs[address]
	if ok {
		return cert
	}
	
	//fetch cert over network
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {panic(err)}
	netCon, err := net.DialTCP("tcp4", nil,addr)
	if err != nil {panic(err)}
	client := tls.Client(netCon,config)
	err = client.Handshake()
	if err != nil {panic(err)}
	state := client.ConnectionState()
	certRaw := state.PeerCertificates[0].Raw
	
	sha := crypto.Hash(crypto.SHA1).New()
	sha.Write(certRaw)
	
	client.Close()
	netCon.Close()
	certs[address] = &Cert{state.PeerCertificates[0],sha.Sum()}
	return certs[address]
}

func main(){
	c := FetchCert("github.com:443")
	fmt.Println(c.sum)

	c = FetchCert("github.com:443")
	fmt.Println(c.sum)
}