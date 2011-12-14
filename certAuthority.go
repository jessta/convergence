package convergence
/*
	Package to verify a cert using the cert authority system
*/

type CertAuthVerifier struct{}

func (CertAuthVerifier) Check(address string, fingerprint string) (fp string, err error) {
	return "", nil
}
