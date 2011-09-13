package convergence
/*
tls implementation that verifies certs using the convergence notary system
*/
import (
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"path"
	"log"
	"http"
	"strings"
	"json"
	"bytes"
	"fmt"
	"net"
	"crypto"
	"time"
	"os"
)

type BasicVerifier struct{}

type Verifier interface {
	Check(address string, fingerprint string)(fp string, err os.Error)
}

type Cert struct {
	cert *x509.Certificate
	fingerprint []byte
}

type Notary struct {
	address string
	Cert
}

type Server struct {
	key *rsa.PrivateKey
	Verifier	
}

type Client struct {
	notaries []*Notary
	Threshold int
}

func (c *Client) AddNotary(address string, cert *x509.Certificate){
	c.notaries = append(c.notaries, NewNotary(address,cert))
	fmt.Println(c.notaries[len(c.notaries)-1])
}

func (c *Client) Dial(netstring, address string) (net.Conn, os.Error) {
	//connect to address using tls
	//check cert against notaries
	//
	log.Println("dialing ",address)
	addr, err := net.ResolveTCPAddr(netstring, address)
	if err != nil {
		return nil, err
	}
	netCon, err := net.DialTCP(netstring, nil, addr)
	if err != nil {
		return nil, err
	}
	host := strings.Split(address,":")[0]
	log.Println(host)
	
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
	sum := sha.Sum()
	FP := hex.EncodeToString(sum)
	FP = fingerPrintStr(FP).String()
	agree := 0
	for i:= range c.notaries {
 		res,ok, err := c.notaries[i].Check(address, FP)
		if err != nil {
			log.Println("trouble with notary:",c.notaries[i].address," ",err)
			continue			
		}
		if !ok {
			log.Printf("%v\n",res)
			continue
		}
		agree++
		//log.Println(res.FingerprintList[0])
	}
	if agree < c.Threshold {
		netCon.Close()
		return nil, os.NewError(fmt.Sprintf("only %d out of %d notaries agreed on certificate (needs %d)",agree,len(c.notaries),c.Threshold))
	}
	return netCon,nil
}


func NewServer(privateKey *rsa.PrivateKey) *Server{
	return &Server{privateKey, BasicVerifier{}}
}

func NewNotary(address string, cert *x509.Certificate) *Notary{
	sha := crypto.Hash(crypto.SHA1).New()
	sha.Write(cert.Raw)
	return &Notary{address,Cert{cert,sha.Sum()}}
}

type NotaryRequest struct {
	Address string
	Fingerprint string
}

type NotaryError struct {
	notary Notary
	err os.Error
}

type NotaryResponse struct {
	notary *Notary
	privateKey *rsa.PrivateKey
	FingerprintList []fingerprint `json:"fingerprintList"`
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

func (r NotaryResponse) VerifySig()(valid bool){
	fpList, err := json.Marshal(r.FingerprintList)
	if err != nil {
		return false
	}
	hash := crypto.Hash(crypto.SHA1).New()
	hash.Write(fpList)
	hashed := hash.Sum()
	sig,err := base64.StdEncoding. DecodeString(r.Signature)
	if err != nil {
		return false
	}
	err = rsa.VerifyPKCS1v15(r.notary.cert.PublicKey.(*rsa.PublicKey), crypto.SHA1, hashed , sig ) 
	if err == nil {
		return true
	}
	return false
}

func (r NotaryResponse) MarshalJSON() ([]byte, os.Error) {
	
	buf := new(bytes.Buffer)
	buf.Write([]byte(`{"fingerprintList":`))
	fpList, err := json.Marshal(r.FingerprintList)
	if err != nil {
		return nil, err
	}

	buf.Write(fpList)
	buf.Write([]byte(`,"signature":"`))
	signature, err := r.signResponse(fpList)
	if err != nil {
		return nil,err
	}
	buf.Write([]byte(base64.StdEncoding.EncodeToString(signature)))
	buf.Write([]byte(`"}`))

	return buf.Bytes(), nil
}

func (r NotaryResponse) signResponse(response []byte) ([]byte, os.Error) {
	hash := crypto.Hash(crypto.SHA1).New()
	hash.Write(response)
	hashed := hash.Sum()

	return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA1, hashed)
}

func fetchCert(address string) (*Cert, os.Error) {
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

	c := &Cert{state.PeerCertificates[0], sha.Sum()}
	return c, nil
}

func (n *Notary) Check(address string, fingerprint string) (NotaryResponse, bool, os.Error){
	addr, err := net.ResolveTCPAddr("tcp", n.address)
	if err != nil {
		return NotaryResponse{},false, err
	}
	netCon, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return NotaryResponse{},false, err
	}
	defer netCon.Close()


	a:= strings.Split(address,":")
	host,port := a[0],a[1]
	config := &tls.Config{nil,nil,nil,nil,[]string{"http"},host,false,nil}

	client := tls.Client(netCon, config)
	err = client.Handshake()
	if err != nil {
		return NotaryResponse{},false, err
	}
	httpClient := http.NewClientConn(client, nil)
	url := fmt.Sprintf("http://%s/target/%s+%s",n.address,host,port)
	post := fmt.Sprintf("fingerprint=%s",fingerprint)
	//log.Println(post)
	request,err := http.NewRequest("POST",url, strings.NewReader(post))
	//log.Printf("%v",request)
	if err != nil {
		return NotaryResponse{},false,err
	}	
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	defer response.Body.Close()
	if err != nil {
		return NotaryResponse{},false,err
	}
	if  response.StatusCode != http.StatusOK {
		//log.Println(response.Status)
		return NotaryResponse{},false,err
	}
	nResponse := NotaryResponse{}
	err = json.NewDecoder(response.Body).Decode(&nResponse)

	if err != nil {
		return NotaryResponse{},false,err
	}

	nResponse.notary = n

	if !nResponse.VerifySig(){
		 return NotaryResponse{},false,err
	}
	
	for i := range nResponse.FingerprintList {
		if nResponse.FingerprintList[i].Fingerprint == fingerprint {
			return nResponse,true, nil
		}
	}
	return nResponse,false, os.NewError("fingerprint didn't match")
}

func (BasicVerifier) Check(address string, fingerprint string)(fp string, err os.Error){
	cert,err := fetchCert(address)
	if err != nil {
		return "",err
	}
	
	myFP := hex.EncodeToString(cert.fingerprint)
	myFP = fingerPrintStr(myFP).String()
	return myFP,nil

}

func Get(Url string) (r *http.Response, err os.Error) {
	return nil,nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request){
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
	
	myFP, err := s.Check(host + ":" + port,theirFP)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error",http.StatusInternalServerError)
		return
	}


	if myFP != theirFP {
		// maybe I'm out of date?
		w.WriteHeader(http.StatusConflict)
	}

	log.Println(host, ":", port, ":", theirFP)

	d := NotaryResponse{
		privateKey: s.key,
		FingerprintList: []fingerprint{
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

	//fmt.Println(hex.EncodeToString(cert.sum))

}

type fingerPrintStr string

func (f fingerPrintStr) String() string {
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
