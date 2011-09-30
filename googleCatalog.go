package convergence
/*
	Package to verify a cert using google's cert catalog
*/
import (
	"net"
	"os"
	"strings"
)

const GOOGLE_CATALOG = "certs.googlednstest.com"

type GoogleCatalogVerifier struct{}

func (GoogleCatalogVerifier) Check(address string, fingerprint string) (fp string, err os.Error) {
	fp = strings.ToLower(fingerprint)

	txts, err := net.LookupTXT(fp + "." + GOOGLE_CATALOG)
	if err != nil {
		return "", err
	}

	//ok, google has seen this one. But 
	/*t := time.UTC().Seconds()
	currentDay := t/int64(60*60*24)*/
	if len(txts) > 0 {
		return fingerprint, nil
	}

	return "", os.NewError("google catalog didn't contain ")
}

