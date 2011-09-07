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
	"os"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/base64"
	"encoding/pem"
	"http"
	"path"
	"strings"
	"json"
	"bytes"
	"io/ioutil"
	"log"
	"time"
)

var PrivateKey *rsa.PrivateKey

/*func init(){
	/*dec := base64.NewDecoder(base64.StdEncoding,os.Stdin)
        certBytes,err := ioutil.ReadAll(dec)
        if err != nil {
                return nil, err
        }
	certs, err := x509.ParseCertificate(certBytes)
        if err != nil {
                return nil, err
        }
	PrivateKey = certs[0].PrivateKey


	PrivateKey =  rsa.GenerateKey(rand.Read, 1024)
}*/

var config = &tls.Config{
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

type Cert struct {
	cert *x509.Certificate
	sum  []byte
}

var certs = map[string]*Cert{}

func FetchCert(address string) (*Cert, os.Error) {
	//is cert in db?
	cert, ok := certs[address]
	if ok {
		return cert, nil
	}

	//fetch cert over network
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, err
	}
	netCon, err := net.DialTCP("tcp4", nil, addr)
	if err != nil {
		return nil, err
	}
	client := tls.Client(netCon, config)
	err = client.Handshake()
	if err != nil {
		return nil, err
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, os.NewError("no cert recieved from host")
	}
	certRaw := state.PeerCertificates[0].Raw

	sha := crypto.Hash(crypto.SHA1).New()
	sha.Write(certRaw)

	client.Close()
	netCon.Close()
	certs[address] = &Cert{state.PeerCertificates[0], sha.Sum()}
	return certs[address], nil
}

type Response struct {
	fingerprintList []fingerprint `json:"fingerprintList"`
	Signature       string        `json:"signature"`
}

type fingerprint struct {
	Timestamp   timestamp `json:"timestamp"`
	Fingerprint string    `json:"fingerprint"`
}

type timestamp struct {
	Start  int64 `json:"start"`
	Finish int64 `json:"finish"`
}

func (r Response) MarshalJSON() ([]byte, os.Error) {
	log.Println("marshalling response")
	buf := new(bytes.Buffer)
	buf.Write([]byte(`{"fingerprintList":`))
	fpList, err := json.Marshal(r.fingerprintList)
	if err != nil {
		panic(err)
	}

	buf.Write(fpList)
	buf.Write([]byte(`,"signature":"`))
	signature, err := signResponse(fpList)
	if err != nil {
		panic(err)
	}
	buf.Write([]byte(base64.StdEncoding.EncodeToString(signature)))
	buf.Write([]byte(`"}`))
	log.Println(string(buf.Bytes()))
	return buf.Bytes(), nil
}

func signResponse(response []byte) ([]byte, os.Error) {
	hash := crypto.Hash(crypto.SHA1).New()
	hash.Write(response)
	hashed := hash.Sum()

	return rsa.SignPKCS1v15(rand.Reader, PrivateKey, crypto.SHA1, hashed)
}

func main() {
	var err os.Error
	certBytes, err := ioutil.ReadFile("./key.pem")
	p, _ := pem.Decode(certBytes)
	certBytes = p.Bytes
	if err != nil {
		panic(err)
	}
	PrivateKey, err = x509.ParsePKCS1PrivateKey(certBytes)

	if err != nil {
		panic(err)
	}
	http.HandleFunc("/target/", handleTargetRequest)
	certFile := "./cert.pem"
	keyFile := "./key.pem"
	log.Println("listening.....")
	err = http.ListenAndServeTLS("127.0.0.1:443", certFile, keyFile, nil)
	if err != nil {
		panic(err)
	}
}

func handleTargetRequest(w http.ResponseWriter, r *http.Request) {
	///target/github.com+443?fingerprint=CE6799252CAC78127D94B5622C31C516A6347353
	log.Println("handling connection", r.RawURL)
	log.Println(r.URL.Path)
	url := path.Clean(r.URL.Path)
	target := url[strings.LastIndex(url, "/")+1:]
	a := strings.Split(target, "+")
	host, port := a[0], a[1]
	err := r.ParseForm()
	if err != nil {
		w.Write([]byte("problem parsing"))
		return
	}
	log.Println(r.Form)
	fingerprints, ok := r.Form["fingerprint"]
	if !ok {
		//missing finger print
		w.Write([]byte("needs a fingerprint"))
		return
	}
	theirFP := fingerprints[0]
	log.Println("fetching cert")
	c, err := FetchCert(host + ":" + port)
	if err != nil {
		panic(err)
	}
	myFP := hex.EncodeToString(c.sum)
	myFP = strings.ToUpper(myFP)
	buf := make([]int, 0, len(myFP))
	colon := false
	for i, r := range myFP {
		buf = append(buf, r)
		if colon {
			buf = append(buf, ':')
			colon = false
		} else {

			if i < len(myFP)-2 {
				colon = true
			}
		}
	}
	myFP = string(buf)

	if myFP != theirFP {
		// maybe I'm out of date?
		//fetch new and try again.
		println("They don't match!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}
	log.Println(host, ":", port, ":", theirFP)
	c, err = FetchCert(host + ":" + port)
	d := Response{
		fingerprintList: []fingerprint{
			fingerprint{Timestamp: timestamp{
				time.Seconds() - 1,
				time.Seconds(),
			},
				Fingerprint: myFP}}}
	response, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	log.Println(response)
	w.Write(response)

	fmt.Println(hex.EncodeToString(c.sum))

}
