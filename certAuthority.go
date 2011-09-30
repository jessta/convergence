package convergence
/*
	Package to verify a cert using the cert authority system
*/
import (
	"os"
)

type CertAuthVerifier struct{}

func (CertAuthVerifier) Check(address string, fingerprint string) (fp string, err os.Error) {
	return "", nil
}

