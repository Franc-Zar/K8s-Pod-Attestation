package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	_ "github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"log"
)

type ImportBlobJSON struct {
	Duplicate     string `json:"duplicate"`
	EncryptedSeed string `json:"encrypted_seed"`
	PublicArea    string `json:"public_area"`
}

func main() {

	rwc, err := simulator.GetWithFixedSeedInsecure(1073741825) // tpmutil.OpenTPM("/dev/tpm0")
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM: %v", err)
		}
	}()

	//getEK(rwc)

	akHandle := generateAK(rwc)

	retrievedAK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), akHandle)
	defer retrievedAK.Close()
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Printf("------ Retrieved AK --------")
	log.Printf(encodePublicKeyToPEM(retrievedAK.PublicKey()))

	log.Printf("------ Signature Verification with AK --------")
	signature := signDataWithAK(akHandle, "hello world", rwc)
	verifySignature(retrievedAK.PublicKey().(*rsa.PublicKey), "hello world", signature)

	log.Printf("------ Encrypting challenge using EK --------")
	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}
	defer ekk.Close()
	ciphertext := encryptWithEK(ekk.PublicKey().(*rsa.PublicKey), []byte("secret challenge"))

	log.Printf("------ Decrypting challenge using EK --------")
	decryptedData := decryptWithEK(rwc, ciphertext)
	if string(decryptedData) == "secret challenge" {
		log.Printf("------ Successfully decrypted challenge using EK: %s --------", string(decryptedData))
	}

	log.Printf("------ Attestation using AK --------")
	attestationProcess(rwc, akHandle)

}

func attestationProcess(rwc io.ReadWriter, akHandle tpmutil.Handle) {
	attestationNonce := []byte("attestation_nonce")
	AK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), akHandle)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer AK.Close()
	attestation, err := AK.Attest(client.AttestOpts{Nonce: attestationNonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	attestationJSON, err := json.Marshal(attestation)
	if err != nil {
		log.Fatalf("Failed to parse attestation result as json")
	}

	log.Printf("Attestation output: %s", attestationJSON)

	state, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: attestationNonce, TrustedAKs: []crypto.PublicKey{AK.PublicKey()}})
	if err != nil {
		log.Fatalf("failed to read PCRs: %v", err)
	}
	fmt.Println(state)
}

// Encrypts data with the provided public key derived from the ephemeral key (EK)
func encryptWithEK(publicEK *rsa.PublicKey, plaintext []byte) ImportBlobJSON {
	// Create the ImportBlob using the public EK
	importBlob, err := server.CreateImportBlob(publicEK, plaintext, nil)
	if err != nil {
		log.Fatalf("failed to create import blob: %v", err)
	}

	jsonResult := ImportBlobJSON{
		Duplicate:     base64.StdEncoding.EncodeToString(importBlob.Duplicate),
		EncryptedSeed: base64.StdEncoding.EncodeToString(importBlob.EncryptedSeed),
		PublicArea:    base64.StdEncoding.EncodeToString(importBlob.PublicArea),
	}

	return jsonResult
}

func decryptWithEK(rwc io.ReadWriter, encryptedData ImportBlobJSON) []byte {
	// Base64 decode the received data
	duplicate, err := base64.StdEncoding.DecodeString(encryptedData.Duplicate)
	if err != nil {
		log.Fatalf("error decoding base64 data: %v", err)
	}

	encryptedSeed, err := base64.StdEncoding.DecodeString(encryptedData.EncryptedSeed)
	if err != nil {
		log.Fatalf("error decoding base64 data: %v", err)
	}

	publicArea, err := base64.StdEncoding.DecodeString(encryptedData.PublicArea)
	if err != nil {
		log.Fatalf("error decoding base64 data: %v", err)
	}

	blob := &pb.ImportBlob{
		Duplicate:     duplicate,
		EncryptedSeed: encryptedSeed,
		PublicArea:    publicArea,
		Pcrs:          nil,
	}

	// Retrieve the TPM's endorsement key (EK)
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	// Decrypt the ImportBlob using the TPM EK
	output, err := ek.Import(blob)
	if err != nil {
		log.Fatalf("failed to import blob: %v", err)
	}

	return output
}

func signDataWithAK(akHandle tpmutil.Handle, message string, rwc io.ReadWriter) string {
	AK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), akHandle)
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
