package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"io"
	"log"

	"github.com/google/go-tpm/tpmutil"
)

func main() {

	rwc, err := tpmutil.OpenTPM("/dev/tpm0")
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM: %v", err)
		}
	}()

	//getEK(rwc)

	/*	akHandle := generateAK(rwc)

		retrievedAK, err := client.NewCachedKey(rwc, tpm2.HandleOwner, client.AKTemplateRSA(), akHandle)
		defer retrievedAK.Close()
		if err != nil {
			log.Fatalf(err.Error())
		}
		log.Printf("------ Retrieved AK --------")
		log.Printf(encodePublicKeyToPEM(retrievedAK.PublicKey()))*/

	/*	log.Printf("------ Signature Verification with AK --------")
		signature := signDataWithAK(akHandle, "hello world", rwc)
		verifySignature(retrievedAK.PublicKey().(*rsa.PublicKey), "hello world", signature)*/

	log.Printf("------ Encrypting challenge using EK --------")
	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	defer ekk.Close()
	ciphertext := encryptWithEK(ekk.PublicKey().(*rsa.PublicKey), []byte("secret challenge"))
	decryptedData := decryptWithEK(ekk.Handle(), rwc, ciphertext)

	if string(decryptedData) == "secret challenge" {
		log.Printf("------ Successfully decrypted challenge using EK: %s --------", string(decryptedData))
	}
}

// Encrypts data with the provided public key derived from the ephemeral key (EK)
func encryptWithEK(publicEK *rsa.PublicKey, plaintext []byte) []byte {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicEK, plaintext, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt with EK: %v", err)
	}
	return encryptedData
}

func signDataWithAK(ekHandle tpmutil.Handle, message string, rwc io.ReadWriter) string {
	AK, err := client.NewCachedKey(rwc, tpm2.HandleOwner, client.AKTemplateRSA(), ekHandle)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	AKsignedData, err := AK.SignData([]byte(message))
	if err != nil {
		log.Fatalf("Error signing data %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(AKsignedData)
	return signatureB64
}

func decryptWithEK(ekHandle tpmutil.Handle, rwc io.ReadWriter, encryptedData []byte) []byte {
	EK, err := client.NewCachedKey(rwc, tpm2.HandleOwner, client.DefaultEKTemplateRSA(), ekHandle)
	if err != nil {
		log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
	}
	defer EK.Close()

	decryptedData, err := tpm2.RSADecrypt(rwc, EK.Handle(), "", encryptedData, &tpm2.AsymScheme{
		Alg:  tpm2.AlgOAEP,
		Hash: tpm2.AlgSHA256,
	}, "")
	if err != nil {
		log.Fatalf("Failed to decrypt using EK: %v", err)
	}
	return decryptedData
}

func verifySignature(rsaPubKey *rsa.PublicKey, message, signature string) {
	hashed := sha256.Sum256([]byte(message))
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Fatalf("Error decoding signature: %v", err)
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		log.Fatalf("Error verifying signature: %v", err)
	}
	log.Printf("Signature verified")
}

// Helper function to encode the public key to PEM format (for printing)
func encodePublicKeyToPEM(pubKey crypto.PublicKey) string {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", // Use "PUBLIC KEY" for X.509 encoded keys
		Bytes: pubASN1,
	})
	return string(pubPEM)
}

func getEK(rwc io.ReadWriter) tpmutil.Handle {
	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	defer ekk.Close()
	cert := ekk.Cert()
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	log.Printf("---------------- Endorsement Key Certificate ----------------")
	fmt.Printf("%s\n", pemCert)
	log.Printf("---------------- Endorsement Key ----------------")
	log.Printf(encodePublicKeyToPEM(ekk.PublicKey()))

	return ekk.Handle()
}

func generateAK(rwc io.ReadWriter) tpmutil.Handle {
	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ak.Close()

	log.Printf("---------------- Attestation Key ----------------")
	log.Printf(encodePublicKeyToPEM(ak.PublicKey()))

	return ak.Handle()
}
