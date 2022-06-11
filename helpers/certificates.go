package helpers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func loadPublicKey(certFilePath string) *rsa.PublicKey {
	certificate, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certificate)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)
}

//Load Private Key from file
func loadPrivateKey(keyFilePath string) *rsa.PrivateKey {
	keyPem, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyPem)
	priv, err := x509.ParsePKCS1PrivateKey((*block).Bytes)
	if err != nil {
		panic(err)
	}
	return priv
}
