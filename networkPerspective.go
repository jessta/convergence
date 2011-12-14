package convergence

import (
	"crypto"

	"crypto/tls"
	"encoding/hex"
	"errors" /*
		Package to verify a cert using a different network perspective
	*/"log"
	"net"
	"strings"
	"time"
)

type BasicVerifier struct {
	store Store
}

func (b BasicVerifier) NewBasicVerifier(store Store) Verifier {
	return BasicVerifier{store: store}
}

func (b BasicVerifier) Check(address string, fingerprint string) (fp string, err error) {
	storedprint, err := b.store.Get(address)
	if err == nil {
		seen, ok := storedprint.(SeenCert)
		if ok {
			if seen.fingerprint == fingerprint {
				seen.lastSeen = time.Now()
				err = b.store.Put(address, seen)
				if err != nil {
					log.Println("couldn't update seenCert for host:" + address + ":" + err.Error())
				}
				return seen.fingerprint, nil
			}
		} else {
			log.Println("value in store wasn't a seenCert for key: " + address)
		}
	}

	cert, err := fetchCert(address)
	if err != nil {
		return "", err
	}

	myFP := hex.EncodeToString(cert.fingerprint)
	myFP = fingerPrintStr(myFP).String()
	seenTime := time.Now()
	err = b.store.Put(address, SeenCert{host: address, fingerprint: myFP, firstSeen: seenTime, lastSeen: seenTime})
	if err != nil {
		log.Println("couldn't store seenCert for host:" + address + ":" + err.Error())
	}

	return myFP, nil

}

func fetchCert(address string) (*cert, error) {
	//fetch cert over network
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	netCon, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	host := strings.Split(address, ":")[0]

	config := &tls.Config{
		Rand:               nil,
		Time:               nil,
		Certificates:       nil,
		NameToCertificate:  nil,
		RootCAs:            nil,
		NextProtos:         []string{"http"},
		ServerName:         host,
		AuthenticateClient: false,
		InsecureSkipVerify: true,
		CipherSuites:       nil,
	}
	client := tls.Client(netCon, config)
	err = client.Handshake()
	if err != nil {
		return nil, err
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no cert recieved from host")
	}
	certRaw := state.PeerCertificates[0].Raw

	sha := crypto.Hash(crypto.SHA1).New()
	sha.Write(certRaw)

	client.Close()
	netCon.Close()

	c := &cert{state.PeerCertificates[0], sha.Sum(nil)}
	return c, nil
}
