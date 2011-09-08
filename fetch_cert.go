package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"

	"encoding/hex"
	"encoding/base64"
	"encoding/pem"

	"io/ioutil"

	"http"
	"path"
	"strings"
	"json"
	"bytes"
	"log"
	"time"
	"sync"
	"net"
	"fmt"
	"crypto"
	"os"
	"flag"
)

var PrivateKey *rsa.PrivateKey


type Cert struct {
	cert *x509.Certificate
	sum  []byte
}

type SyncCertMap struct {
	certs map[string]*Cert
	*sync.Mutex
}

var certs = SyncCertMap{map[string]*Cert{},new(sync.Mutex)}

func FetchCert(address string) (*Cert, os.Error) {
	//is cert in db?
	certs.Lock()
	cert, ok := certs.certs[address]
	certs.Unlock()

	if ok {
		return cert, nil
	}

	//fetch cert over network
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	netCon, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	host := strings.Split(address,":")[0]

	config := &tls.Config{nil,nil,nil,nil,[]string{"http"},host,false,nil}

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

	certs.Lock()
	cert, ok = certs.certs[address]
	if ok {
		certs.Unlock()
		return cert, nil
	}
	c := &Cert{state.PeerCertificates[0], sha.Sum()}
	certs.certs[address] = c

	certs.Unlock()
	return c, nil
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
	
	buf := new(bytes.Buffer)
	buf.Write([]byte(`{"fingerprintList":`))
	fpList, err := json.Marshal(r.fingerprintList)
	if err != nil {
		return nil, err
	}

	buf.Write(fpList)
	buf.Write([]byte(`,"signature":"`))
	signature, err := signResponse(fpList)
	if err != nil {
		return nil,err
	}
	buf.Write([]byte(base64.StdEncoding.EncodeToString(signature)))
	buf.Write([]byte(`"}`))

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

	var keyFile  string
	var certFile string
	var addr string
	flag.StringVar(&keyFile, "keyfile", "./key.pem","file name of key file")
	flag.StringVar(&certFile, "certfile", "./cert.pem","file name of cert file")
	flag.StringVar(&addr, "addr", "0.0.0.0:443","address to listen on")

	flag.Parse()

	certBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatalln("error reading keyfile: ",err)
	}
	p, _ := pem.Decode(certBytes)
	if p == nil {
		log.Fatalln("invalid key file")
	}
	certBytes = p.Bytes
	
	PrivateKey, err = x509.ParsePKCS1PrivateKey(certBytes)

	if err != nil {
		log.Fatalln("invalid key file: ", err)
	}

	http.HandleFunc("/target/", handleTargetRequest)

	log.Println("listening.....")
	err = http.ListenAndServeTLS(addr, certFile, keyFile, nil)
	if err != nil {
		log.Fatalln("error listening: ",err)
	}
}

func handleTargetRequest(w http.ResponseWriter, r *http.Request) {
	///target/github.com+443?fingerprint=CE6799252CAC78127D94B5622C31C516A6347353
	log.Println("handling connection", r.RawURL)
	log.Println(r.URL.Path)
	url := path.Clean(r.URL.Path)
	target := url[strings.LastIndex(url, "/")+1:]
	a := strings.Split(target, "+")
	if len(a) != 2 {
		if len(a) == 0 {
			http.Error(w, "needs host", http.StatusBadRequest)
		}
		if len(a) == 1 {
			http.Error(w, "needs port", http.StatusBadRequest)
		}
		if len(a) > 2 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		return
	}
	host, port := a[0], a[1]
	err := r.ParseForm()

	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fingerprints, ok := r.Form["fingerprint"]

	if !ok {
		//missing finger print
		http.Error(w, "needs a fingerprint", http.StatusBadRequest)
		return
	}

	theirFP := fingerprints[0]
	
	c, err := FetchCert(host + ":" + port)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error",http.StatusInternalServerError)
		return
	}

	myFP := hex.EncodeToString(c.sum)
	myFP = FingerPrintStr(myFP).String()

	if myFP != theirFP {
		// maybe I'm out of date?
		w.WriteHeader(http.StatusConflict)
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
		log.Println(err)
		http.Error(w, "Internal Server Error",http.StatusInternalServerError)
	}
	w.Write(response)

	fmt.Println(hex.EncodeToString(c.sum))

}

type FingerPrintStr string

func (f FingerPrintStr) String() string {
	str := strings.ToUpper(string(f))
	buf := make([]int, 0, len(str))
	colon := false
	for i, r := range str {
		buf = append(buf, r)
		if colon {
			buf = append(buf, ':')
			colon = false
		} else {

			if i < len(f)-2 {
				colon = true
			}
		}
	}
	return string(buf)
}


