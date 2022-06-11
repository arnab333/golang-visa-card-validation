package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/arnab333/golang-visa-card-validation/helpers"
	"github.com/joho/godotenv"
)

const baseUrl = "https://sandbox.api.visa.com"

var (
	// THIS IS EXAMPLE ONLY how will user_id and password look like
	// userId = "1WM2TT4IHPXC8DQ5I3CH21n1rEBGK-Eyv_oLdzE2VZpDqRn_U";
	// password = "19JRVdej9";
	// username = "<YOUR USER ID>"
	// password = "<YOUR PASSWORD>"

	// THIS IS EXAMPLE ONLY how will cert and key look like
	// clientCertificateFile = 'cert.pem'
	// clientCertificateKeyFile = 'key_83d11ea6-a22d-4e52-b310-e0558816727d.pem'
	// caCertificateFile = 'ca_bundle.pem'

	clientCertificateFile    = "<YOUR MUTUAL SSL CLIENT CERTIFICATE PATH>"
	clientCertificateKeyFile = "<YOUR MUTUAL SSL PRIVATE KEY PATH>"
	caCertificateFile        = "<YOUR MUTUAL SSL CA PATH>"

	// MLE KEY
	//#########
	//# THIS IS EXAMPLE ONLY how will myKey_ID, server_cert and private_key look like
	//# mleClientPrivateKeyPath = 'key_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
	//# mleServerPublicCertificatePath = 'server_cert_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
	//# keyId = '7f591161-6b5f-4136-80b8-2ae8a44ad9eb'

	mleClientPrivateKeyPath        = "<YOUR MLE CLIENT PRIVATE KEY PATH>"
	mleServerPublicCertificatePath = "<YOUR MLE SERVER CERTIFICATE PATH>"
	keyId                          = "<YOUR KEY ID>"
)

type RequestHeaderPayload struct {
	RequestMessageId string `json:"requestMessageId"`
	MessageDateTime  string `json:"messageDateTime"`
}

type CardNumber []string

type RequestDataPayload struct {
	PANs  CardNumber `json:"pANs"`
	Group string     `json:"group"`
}

type VisaPayload struct {
	RequestHeader RequestHeaderPayload `json:"requestHeader"`
	RequestData   RequestDataPayload   `json:"requestData"`
}

func main() {
	dirname, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	keyId = os.Getenv("KEY_ID")
	cofdsEndPoint := baseUrl + "/cofds-web/v1/datainfo"

	clientCertificateFile = dirname + "/cert/cert.pem"
	clientCertificateKeyFile = dirname + "/cert/privateKey.pem"
	caCertificateFile = dirname + "/cert/VDPCA-SBX.pem"
	mleClientPrivateKeyPath = dirname + "/cert/client_cert.pem"
	mleServerPublicCertificatePath = dirname + "/cert/server_cert.pem"

	payload := `{
		"requestHeader": {
			"requestMessageId": "6da6b8b024532a2e0eacb1af58581",
			"messageDateTime": "2019-02-35 05:25:12.327"
		},
		"requestData": {
			"pANs": [
				"4072208010000000"
			],
			"group": "STANDARD"
		}
	}`

	encData := map[string]string{"encData": helpers.CreateJWE(payload, keyId, mleServerPublicCertificatePath)}

	encryptedPayload, _ := json.Marshal(encData)
	responsePayload := helpers.InvokeAPI(cofdsEndPoint, http.MethodPost, string(encryptedPayload), caCertificateFile, clientCertificateFile, clientCertificateKeyFile, mleClientPrivateKeyPath)
	log.Println("OCT Response Data: ", responsePayload)

}
