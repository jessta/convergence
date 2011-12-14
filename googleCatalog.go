package convergence
/*
	Package to verify a cert using google's cert catalog
*/
import (
	"errors"
	"net"
	"strings"
	//	"time"
)

const GOOGLE_CATALOG = "certs.googlednstest.com"

type GoogleCatalogVerifier struct{}

func (GoogleCatalogVerifier) Check(address string, fingerprint string) (fp string, err error) {
	fp = strings.ToLower(fingerprint)

	txts, err := net.LookupTXT(fp + "." + GOOGLE_CATALOG)
	if err != nil {
		return "", err
	}

	if len(txts) > 0 {
		return fingerprint, nil
	}

	//ok, google has seen this one. But how long ago?*/

	//t := time.Now().UTC().Unix()
	//currentDay := t / int64(60*60*24)

	return "", errors.New("google catalog didn't contain ")
}
