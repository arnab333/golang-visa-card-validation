package helpers

import (
	"gopkg.in/square/go-jose.v2"
)

func CreateJWE(payload string, keyId string, mleServerPublicCertificatePath string) string {
	// Instantiate an encrypter using RSA-OAEP-256 with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := loadPublicKey(mleServerPublicCertificatePath)
	opts := new(jose.EncrypterOptions)

	iat := currentMillis()

	opts.WithHeader("kid", keyId)
	opts.WithHeader("iat", iat)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: publicKey}, opts)
	if err != nil {
		panic(err)
	}

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	object, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the compact serialization format.
	serialized, err := object.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return serialized
}

func decryptJWE(encryptedPayload string, mleClientPrivateKeyPath string) string {

	encryptedData := parseEncryptedResponse(encryptedPayload)

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseEncrypted(encryptedData.EncData)
	if err != nil {
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate the the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	privateKey := loadPrivateKey(mleClientPrivateKeyPath)
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}

	return string(decrypted)
}
