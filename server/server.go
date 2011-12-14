package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/jessta/convergence"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	var err error

	var keyFile string
	var certFile string
	var addr string
	var proxyAddr string
	flag.StringVar(&keyFile, "keyfile", "./key.pem", "file name of key file")
	flag.StringVar(&certFile, "certfile", "./cert.pem", "file name of cert file")
	flag.StringVar(&addr, "addr", "0.0.0.0:443", "address to listen on")
	flag.StringVar(&proxyAddr, "proxyAddr", "0.0.0.0:80", "address for proxy to listen on")

	flag.Parse()

	certBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatalln("error reading keyfile: ", err)
	}
	p, _ := pem.Decode(certBytes)
	if p == nil {
		log.Fatalln("invalid key file")
	}
	certBytes = p.Bytes

	privateKey, err := x509.ParsePKCS1PrivateKey(certBytes)

	if err != nil {
		log.Fatalln("invalid key file: ", err)
	}

	s := convergence.NewServer(privateKey, nil)

	http.Handle("/target/", s)

	log.Println("Proxy listening...")
	go convergence.ProxyListenAndServe(proxyAddr)

	log.Println("listening.....")
	err = http.ListenAndServeTLS(addr, certFile, keyFile, nil)
	if err != nil {
		log.Fatalln("error listening: ", err)
	}
}
