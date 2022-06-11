package helpers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type EncryptedResponse struct {
	EncData string
}

func parseEncryptedResponse(encryptedPayload string) EncryptedResponse {
	var encryptedResponse EncryptedResponse
	err := json.Unmarshal([]byte(encryptedPayload), &encryptedResponse)

	if err != nil {
		panic(err)
	}
	return encryptedResponse
}

func InvokeAPI(apiUrl, httpMethod, payload, caCertificateFile, clientCertificateFile, clientCertificateKeyFile, mleClientPrivateKeyPath string) string {
	//Load CA Cert
	clientCACert, err := ioutil.ReadFile(caCertificateFile)
	if err != nil {
		panic(err)
	}

	//Load Client Key Pair
	clientKeyPair, err := tls.LoadX509KeyPair(clientCertificateFile, clientCertificateKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	clientCertPool, _ := x509.SystemCertPool()
	if clientCertPool == nil {
		clientCertPool = x509.NewCertPool()
	}

	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      clientCertPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	var request *http.Request = nil
	if payload != "" {
		// log.Println("Request Payload: ", payload)
		request, err = http.NewRequest(httpMethod, apiUrl, bytes.NewBuffer([]byte(payload)))
	} else {
		request, err = http.NewRequest(httpMethod, apiUrl, nil)
	}

	if err != nil {
		panic(err)
	}
	request.SetBasicAuth(os.Getenv("USER_ID"), os.Getenv("PASSWORD"))
	request.Header.Set("keyId", os.Getenv("KEY_ID"))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	log.Println("Invoking API:", httpMethod, apiUrl)
	resp, err := client.Do(request)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	log.Println("Http Status :", resp.Status)
	// log.Println("Response Headers:", resp.Header)

	encryptedResponsePayload := string(body)
	// log.Println("Response Payload: ", encryptedResponsePayload)

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
		panic(errors.New("error when invoking visa api. " + decryptedData))
	}

	// log.Println("Response Body:", encryptedResponsePayload)
	decryptedData := decryptJWE(encryptedResponsePayload, mleClientPrivateKeyPath)
	return decryptedData
}
