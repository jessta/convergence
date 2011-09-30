package convergence
/*
	Package to verify a cert using a different network perspective
*/
import (
	"os"
	"encoding/hex"
	"net"
	"crypto/tls"
	"crypto"
	"strings"
)

type BasicVerifier struct{}

func (BasicVerifier) Check(address string, fingerprint string) (fp string, err os.Error) {
	cert, err := fetchCert(address)
	if err != nil {
		return "", err
	}

	myFP := hex.EncodeToString(cert.fingerprint)
	myFP = fingerPrintStr(myFP).String()
	return myFP, nil

}

func fetchCert(address string) (*cert, os.Error) {
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

	config := &tls.Config{nil, nil, nil, nil, []string{"http"}, host, false, nil}

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

	c := &cert{state.PeerCertificates[0], sha.Sum()}
	return c, nil
}

