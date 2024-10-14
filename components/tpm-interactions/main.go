package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
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

type InputQuote struct {
	Quote  string `json:"quote"`
	RawSig string `json:"raw_sig"`
	PCRs   PCRSet `json:"pcrs"`
}

type IMAPodEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

// PCRSet represents the PCR values and the hash algorithm used
type PCRSet struct {
	Hash int               `json:"hash"`
	PCRs map[string]string `json:"pcrs"`
}

// Concatenate PCR values based on input
func concatenatePCRValues(pcrs map[string]string) ([]byte, error) {
	var buffer bytes.Buffer

	for i := 0; i < len(pcrs); i++ {
		pcrBase64, exists := pcrs[fmt.Sprintf("%d", i)]
		if !exists {
			return nil, fmt.Errorf("missing PCR value for index %d", i)
		}

		// Decode Base64-encoded PCR value
		pcrBytes, err := base64.StdEncoding.DecodeString(pcrBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PCR value: %v", err)
		}

		// Concatenate PCR values
		buffer.Write(pcrBytes)
	}

	return buffer.Bytes(), nil
}

// Compute the digest over PCR values and nonce
func computeDigest(pcrBytes, nonce []byte, hashAlgorithm int) ([]byte, error) {
	// Concatenate PCR bytes and nonce
	var buffer bytes.Buffer
	buffer.Write(pcrBytes)
	buffer.Write(nonce)

	// Compute the hash based on the algorithm (hashAlgorithm = 11 means SHA256)
	switch hashAlgorithm {
	case 11: // SHA256
		hash := sha256.New()
		hash.Write(buffer.Bytes())
		return hash.Sum(nil), nil
	case 4: // SHA1
		hash := sha1.New()
		hash.Write(buffer.Bytes())
		return hash.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %d", hashAlgorithm)
	}
}

/*
func main() {

	rwc, err := simulator.GetWithFixedSeedInsecure(1073741825) //tpmutil.OpenTPM("/dev/tpm0")
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

	//log.Printf("------ Signature Verification with AK --------")
	//signature := signDataWithAK(akHandle, "hello world", rwc)
	//verifySignature(retrievedAK.PublicKey().(*rsa.PublicKey), []byte("hello world"), signature)

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
	//attestationProcess(rwc, akHandle)

	//log.Printf("------ Validation of quote --------")
	//validateQuote(rwc, akHandle)

	osName, err := GetOSDescription()
	if err != nil {
		log.Fatalf("failed to get OS info")
	}
	log.Printf(osName)

	if !checkPodUUIDMatch("/kubepods/burstable/pod5c6ae4d3-475b-4897-b1e4-eb6367716cbd/5aeab4fc9a54050cab3f08b5e6e9b9566116e47716cb4a657b909a1e6a0ce188", "5c6ae4d3-475b-4897-b1e4-eb6367716cbd") {
		log.Fatalf("uuid not matching")
	}
	log.Printf("uuid match")
}
*/

// extractSHADigest extracts the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractSHADigest(input string) (string, error) {
	// Define a regular expression to match the prefix "sha<number>:"
	re := regexp.MustCompile(`^sha[0-9]+:`)

	if re.MatchString(input) {
		// Remove the matching prefix and return the remaining part (hex digest)
		return re.ReplaceAllString(input, ""), nil
	}
	return "", fmt.Errorf("input does not have a valid sha<algo>: prefix")
}

func verifyIMAhash(pcr10 string) {
	// Open the file
	IMAMeasurementLog, err := os.Open("./ascii_runtime_measurements")
	if err != nil {
		log.Fatalf("failed to open IMA measurement log: %v", err)
	}
	defer IMAMeasurementLog.Close()

	// Read the file content
	fileContent, err := io.ReadAll(IMAMeasurementLog)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}

	// Convert the decoded log to a string and split it into lines
	logLines := strings.Split(string(fileContent), "\n")

	previousHash := make([]byte, 20)
	// Iterate through each line and extract relevant fields
	for idx, IMALine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(IMALine)

		templateHashField := IMAFields[1]

		// Use the helper function to extend the PCR with the current template hash
		newHash, err := extendIMAEntries(previousHash, templateHashField)
		if err != nil {
			fmt.Printf("Error computing hash at index %d: %v\n", idx, err)
			continue
		}

		// Update the previous hash for the next iteration
		previousHash = newHash
	}

	// Convert the final hash to a hex string for comparison
	cumulativeHashIMAHex := hex.EncodeToString(previousHash)
	if cumulativeHashIMAHex != pcr10 {
		log.Fatalf("IMA Verification failed: computed hash %s", cumulativeHashIMAHex)
	}
	log.Printf("IMA Verification successful: %s = %s", cumulativeHashIMAHex, pcr10)
}

// Helper function to compute the new hash by concatenating previous hash and template hash
func extendIMAEntries(previousHash []byte, templateHash string) ([]byte, error) {
	// Create a new SHA-1 hash
	hash := sha1.New()

	// Decode the template hash from hexadecimal
	templateHashBytes, err := hex.DecodeString(templateHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode template hash: %v", err)
	}

	// Concatenate previous hash and the new template hash
	dataToHash := append(previousHash, templateHashBytes...)

	// Compute the new hash
	hash.Write(dataToHash)
	return hash.Sum(nil), nil
}

func IMAAnalysys(podUID string) {
	// Open the file
	IMAMeasurementLog, err := os.Open("./ascii_runtime_measurements_sha256")
	if err != nil {
		log.Fatalf("failed to open IMA measurement log: %v", err)
	}
	defer IMAMeasurementLog.Close()

	// Read the file content
	fileContent, err := io.ReadAll(IMAMeasurementLog)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}

	// Convert the decoded log to a string and split it into lines
	logLines := strings.Split(string(fileContent), "\n")

	// Use a map to ensure unique entries
	uniqueEntries := make(map[string]IMAPodEntry)

	// Iterate through each line and extract relevant fields
	for _, IMALine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(IMALine)
		if len(IMAFields) < 7 {
			log.Fatalf("IMA measurement log integrity check failed: found entry not compliant with template: %s", IMALine)
		}
		depField := IMAFields[3]
		// Extract the cgroup path (fifth element)
		cgroupPathField := IMAFields[4]

		if !strings.Contains(depField, "containerd") {
			continue
		}

		// Check if the cgroup path contains the podUID
		if checkPodUIDMatch(cgroupPathField, podUID) {
			// Extract the file hash and file path (sixth and seventh elements)
			fileHash, err := extractSHADigest(IMAFields[5])
			if err != nil {
				log.Fatalf("failed to decode file hash field: %v", err)
			}
			filePath := IMAFields[6]

			// Create a unique key by combining filePath and fileHash
			entryKey := fmt.Sprintf("%s:%s", filePath, fileHash)

			// Add the entry to the map if it doesn't exist
			if _, exists := uniqueEntries[entryKey]; !exists {
				uniqueEntries[entryKey] = IMAPodEntry{
					FilePath: filePath,
					FileHash: fileHash,
				}
			}
		}
	}

	// Convert the unique entries back to a slice
	IMAPodEntries := make([]IMAPodEntry, 0, len(uniqueEntries))
	for _, entry := range uniqueEntries {
		IMAPodEntries = append(IMAPodEntries, entry)
	}

	// Marshal the unique entries into JSON
	podEntriesJSON, err := json.Marshal(IMAPodEntries)
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Printf(string(podEntriesJSON))

	podWhitelistCheckRequest := PodWhitelistCheckRequest{
		PodImageName: "redis:latest",
		PodFiles:     IMAPodEntries,
		HashAlg:      "SHA256",
	}

	resp := verifyPodFilesIntegrity(podWhitelistCheckRequest)

	if resp != nil {
		log.Fatalf("failed to verify integrity of pod files")
	}
	log.Printf("all files of Pod are allowed and respect the whitelist")
}

type PodWhitelistCheckRequest struct {
	PodImageName string        `json:"podImageName"`
	PodFiles     []IMAPodEntry `json:"podFiles"`
	HashAlg      string        `json:"hashAlg"` // Include the hash algorithm in the request
}

func verifyPodFilesIntegrity(checkRequest PodWhitelistCheckRequest) error {
	whitelistProviderWorkerValidateURL := "http://localhost:9090/whitelist/pod/check"

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(whitelistProviderWorkerValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Whitelist check request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Whitelists Provider failed to process check request: %s (status: %d)", string(body), resp.StatusCode)
	}

	return nil
}

func checkPodUIDMatch(path, podUID string) bool {
	var regexPattern string
	// Replace dashes in podUID with underscores
	adjustedPodUID := strings.ReplaceAll(podUID, "-", "_")

	// Regex pattern to match the pod UID in the path
	regexPattern = fmt.Sprintf(`kubepods[^\/]*-pod%s\.slice`, regexp.QuoteMeta(adjustedPodUID))

	// Compile the regex
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}

	// Check if the path contains the pod UID
	return r.MatchString(path)
}

func main() {
	//IMAAnalysys("eee87997-2192-4e41-927c-65e71a312518")
	verifyIMAhash("61f0b0d5021a930151775140e900ea55f98110d0")
}

// Custom function that checks if PCRstoQuote contains any element from bootReservedPCRs
// and returns the boolean and the list of matching PCRs
func containsAndReturnPCR(PCRstoQuote []int, bootReservedPCRs []int) (bool, []int) {
	var foundPCRs []int
	for _, pcr := range PCRstoQuote {
		if slices.Contains(bootReservedPCRs, pcr) {
			foundPCRs = append(foundPCRs, pcr)
		}
	}
	if len(foundPCRs) == 0 {
		return false, nil // No matching PCRs found
	}
	return true, foundPCRs
}

func validateQuote(rwc io.ReadWriter, akHandle tpmutil.Handle) {
	nonce := []byte("noncenon")

	bootReservedPCRs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	PCRstoQuote := []int{0, 1, 25}

	// Custom function to return both found status and the PCR value
	PCRsContainsBootReserved, foundPCR := containsAndReturnPCR(PCRstoQuote, bootReservedPCRs)

	if PCRsContainsBootReserved {
		log.Fatalf("Cannot perform quote on provided PCR set %v: boot reserved PCRs where included %v", foundPCR, bootReservedPCRs)
	}

	selectedPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7},
	}

	AK, err := client.NewCachedKey(rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), akHandle)
	if err != nil {
		log.Fatalf("ERROR:  could not get EndorsementKeyRSA: %v", err)
	}

	quote, err := AK.Quote(selectedPCRs, nonce)
	if err != nil {
		log.Fatalf("failed to create quote: %v", err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		log.Fatalf("Failed to parse attestation result as json")
	}

	// Parse input JSON
	var input InputQuote
	err = json.Unmarshal(quoteJSON, &input)
	if err != nil {
		log.Fatalf("Failed to unmarshal input JSON: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteBytes, err := base64.StdEncoding.DecodeString(input.Quote)
	if err != nil {
		log.Fatalf("Failed to decode quote: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteSig, err := base64.StdEncoding.DecodeString(input.RawSig)
	if err != nil {
		log.Fatalf("Failed to decode quote: %v", err)
	}

	sig, err := tpm2legacy.DecodeSignature(bytes.NewBuffer(quoteSig))

	// Verify the signature
	verifySignature(AK.PublicKey().(*rsa.PublicKey), quoteBytes, sig.RSA.Signature)

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2legacy.DecodeAttestationData(quoteBytes)
	if err != nil {
		log.Fatalf("decoding attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2legacy.TagAttestQuote {
		log.Fatalf("expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		log.Fatalf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, nonce) == 0 {
		log.Fatalf("quote extraData %v did not match expected extraData %v", attestationData.ExtraData, nonce)
	}

	inputPCRs, err := convertPCRs(input.PCRs.PCRs)
	if err != nil {
		log.Fatalf("failed to convert PCRs from received quote")
	}

	quotePCRs := &pb.PCRs{
		Hash: pb.HashAlgo(input.PCRs.Hash),
		Pcrs: inputPCRs,
	}

	pcrHashAlgo, err := convertToCryptoHash(quotePCRs.GetHash())
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = validatePCRDigest(attestedQuoteInfo, quotePCRs, pcrHashAlgo)
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Printf(hex.EncodeToString(attestedQuoteInfo.PCRDigest))
	log.Printf(quotePCRs.Hash.String())

	log.Printf("Quote valid")
}

// GetOSDescription runs "lsb_release -a" and returns the Description field content
func GetOSDescription() (string, error) {
	// Run the lsb_release -a command
	cmd := exec.Command("lsb_release", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out

	// Execute the command
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to run lsb_release: %v", err)
	}

	// Parse the output
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		// Look for the line that starts with "Description:"
		if strings.HasPrefix(line, "Description:") {
			// Return the content after "Description:"
			return strings.TrimSpace(strings.TrimPrefix(line, "Description:")), nil
		}
	}

	return "", fmt.Errorf("Description field not found")
}

func convertToCryptoHash(algo pb.HashAlgo) (crypto.Hash, error) {
	switch algo {
	case 4:
		return crypto.SHA1, nil
	case 11:
		return crypto.SHA256, nil
	case 12:
		return crypto.SHA384, nil
	case 13:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
}

func convertPCRs(input map[string]string) (map[uint32][]byte, error) {
	converted := make(map[uint32][]byte)

	// Iterate over the input map
	for key, value := range input {
		// Convert string key to uint32
		keyUint32, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to convert key '%s' to uint32: %v", key, err)
		}

		// Decode base64-encoded value
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 value for key '%s': %v", key, err)
		}

		// Add the converted key-value pair to the new map
		converted[uint32(keyUint32)] = valueBytes
	}

	return converted, nil
}

func validatePCRDigest(quoteInfo *tpm2legacy.QuoteInfo, pcrs *pb.PCRs, hash crypto.Hash) error {
	if !SamePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := PCRDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil
}

// PCRDigest computes the digest of the Pcrs. Note that the digest hash
// algorithm may differ from the PCRs' hash (which denotes the PCR bank).
func PCRDigest(p *pb.PCRs, hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := uint32(0); i < 24; i++ {
		if pcrValue, exists := p.GetPcrs()[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

// SamePCRSelection checks if the Pcrs has the same PCRSelection as the
// provided given tpm2.PCRSelection (including the hash algorithm).
func SamePCRSelection(p *pb.PCRs, sel tpm2legacy.PCRSelection) bool {
	if tpm2legacy.Algorithm(p.GetHash()) != sel.Hash {
		return false
	}
	if len(p.GetPcrs()) != len(sel.PCRs) {
		return false
	}
	for _, pcr := range sel.PCRs {
		if _, ok := p.Pcrs[uint32(pcr)]; !ok {
			return false
		}
	}
	return true
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

func verifySignature(rsaPubKey *rsa.PublicKey, message []byte, signature tpmutil.U16Bytes) {
	hashed := sha256.Sum256(message)
	//sigBytes, err := base64.StdEncoding.DecodeString(signature)
	//if err != nil {
	//	log.Fatalf("Error decoding signature: %v", err)
	//}

	err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], signature)
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
