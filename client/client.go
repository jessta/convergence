package main

import (
	"github.com/jessta/convergence"
	"log"
	//"http"
	"crypto/x509"
	//"bufio"
	"encoding/pem"
	"io/ioutil"
	//"bytes"
)

func main() {
	c := new(convergence.Client)
	certBytes, err := ioutil.ReadFile("../cert.pem")
	if err != nil {
		log.Fatalln("error reading certfile: ", err)
	}
	p, _ := pem.Decode(certBytes)
	if p == nil {
		log.Fatalln("invalid key file")
	}
	certBytes = p.Bytes

	cert, err := x509.ParseCertificates(certBytes)
	if err != nil {
		log.Fatalln("trouble parsing cert: ", err)
	}

	/*certBytes, err = ioutil.ReadFile("vtcybersecurity.pem")
	if err != nil {
		log.Fatalln("error reading certfile: ", err)
	}
	p, _ = pem.Decode(certBytes)
	if p == nil {
		log.Fatalln("invalid key file for notary.sigbus.net")
	}
	certBytes = p.Bytes

	vtc, err := x509.ParseCertificates(certBytes)
	if err != nil {
		log.Fatalln("trouble parsing cert: ", err)
	}*/

	c.AddNotary("127.0.0.1:443", cert[0])
	//c.AddNotary("notary.sigbus.net:81", vtc[0])

	c.Threshold = 1

	conn, err := c.Dial("tcp", "github.com:443")
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		log.Fatalln("trouble dialing: ", err.Error())
	}

}
