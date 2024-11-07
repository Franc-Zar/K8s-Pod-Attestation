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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"io/ioutil"
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
	signature := signDataWithAK(akHandle, "hello world", rwc)
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

// LoadCertificateFromPEM loads a certificate from a PEM string
func LoadCertificateFromPEM(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// VerifyCertificateChain verifies the provided certificate chain from PEM strings
func VerifyCertificateChain(providedCertPEM, intermediateCertPEM, rootCertPEM string) error {
	cert, err := LoadCertificateFromPEM(providedCertPEM)
	if err != nil {
		return fmt.Errorf("error loading provided certificate: %v", err)
	}

	intermediateCert, err := LoadCertificateFromPEM(intermediateCertPEM)
	if err != nil {
		return fmt.Errorf("error loading intermediate CA certificate: %v", err)
	}

	rootCert, err := LoadCertificateFromPEM(rootCertPEM)
	if err != nil {
		return fmt.Errorf("error loading root CA certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = HandleTPMSubjectAltName(cert)
	if err != nil {
		return err
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}
	return nil
}

func copyFileToTemp(srcFilePath string) (string, error) {
	// Open the source file
	srcFile, err := os.Open(srcFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %v", err)
	}
	defer srcFile.Close()

	// Create a temporary file
	tmpFile, err := ioutil.TempFile(os.TempDir(), "quotedIMA")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Copy the contents from the source file to the temp file
	_, err = io.Copy(tmpFile, srcFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy file: %v", err)
	}

	// Return the name of the temporary file
	return tmpFile.Name(), nil
}

// HandleTPMSubjectAltName processes the subjectAltName extension to mark it as handled
func HandleTPMSubjectAltName(cert *x509.Certificate) (*x509ext.SubjectAltName, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // OID for subjectAltName
			subjectAltName, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			//TPMManufacturer := subjectAltName.DirectoryNames[0].Names[0]
			//TPMModel := subjectAltName.DirectoryNames[0].Names[1]
			//TPMVersion := subjectAltName.DirectoryNames[0].Names[2]

			// Remove from UnhandledCriticalExtensions if it's the SAN extension
			for i, unhandledExt := range cert.UnhandledCriticalExtensions {
				if unhandledExt.Equal(ext.Id) {
					// Remove the SAN extension from UnhandledCriticalExtensions
					cert.UnhandledCriticalExtensions = append(cert.UnhandledCriticalExtensions[:i], cert.UnhandledCriticalExtensions[i+1:]...)
					break
				}
			}
			return subjectAltName, nil
		}
	}
	return nil, fmt.Errorf("SAN extension not found")
}

// extractSHADigest extracts the algorithm (e.g., "sha256") and the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractSHADigest(input string) (string, string, error) {
	// Define a regular expression to match the prefix "sha<number>:" followed by the hex digest
	re := regexp.MustCompile(`^sha[0-9]+:`)

	// Check if the input matches the expected format
	if matches := re.FindStringSubmatch(input); matches != nil {
		fileHashElements := strings.Split(input, ":")

		return fileHashElements[0], fileHashElements[1], nil
	}

	return "", "", fmt.Errorf("input does not have a valid sha<algo>:<hex_digest> format")
}

func verifyIMAHash(pcr10 string, tmpIMA string) {
	// Open the file
	IMAMeasurementLog, err := os.Open(tmpIMA)
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
	if len(logLines) > 0 && logLines[len(logLines)-1] == "" {
		logLines = logLines[:len(logLines)-1] // Remove the last empty line --> each entry adds a \n so last line will add an empty line
	}

	previousHash := make([]byte, 32)
	// Iterate through each line and extract relevant fields
	for idx, IMALine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(IMALine)

		templateHashField := IMAFields[1]
		depField := IMAFields[3]
		cgroupField := IMAFields[4]
		fileHashField := IMAFields[5]
		filePathField := IMAFields[6]

		hashAlgo, fileHash, err := extractSHADigest(fileHashField)
		if err != nil {
			log.Fatalf("error")
		}

		extendValue := validateIMAEntry(templateHashField, depField, cgroupField, hashAlgo, fileHash, filePathField)

		// Use the helper function to extend the PCR with the current template hash
		extendedHash, err := extendIMAEntries(previousHash, extendValue)
		if err != nil {
			fmt.Printf("Error computing hash at index %d: %v\n", idx, err)
			continue
		}

		// Update the previous hash for the next iteration
		previousHash = extendedHash
		if hex.EncodeToString(extendedHash) == pcr10 {
			log.Printf("IMA Verification successful: %s = %s", hex.EncodeToString(extendedHash), pcr10)
			return
		}
	}
	log.Fatalf("IMA Verification failed: %s != %s", hex.EncodeToString(previousHash), pcr10)
}

// Helper function to compute the new hash by concatenating previous hash and template hash
func extendIMAEntries(previousHash []byte, templateHash string) ([]byte, error) {
	// Create a new SHA-256 hash
	hash := sha256.New()

	// Decode the template hash from hexadecimal
	templateHashBytes, err := hex.DecodeString(templateHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode template hash: %v", err)
	}
	// Concatenate previous hash and the new template hash
	dataToHash := append(previousHash, templateHashBytes...)
	// Compute the new hash
	hash.Write(dataToHash)
	result := hash.Sum(nil)
	log.Printf(hex.EncodeToString(result))
	return result, nil
}

func IMAAnalysis(podUID string) {
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
			_, fileHash, err := extractSHADigest(IMAFields[5])
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

// Function to pack IMA path (similar to pack_ima_path in Python)
func packIMAPath(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack length (4 bytes)
	length := uint32(len(path) + 1) // length + 1 for NULL_BYTE
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return nil, fmt.Errorf("failed to pack length: %v", err)
	}

	// Pack path (len(path) bytes)
	if _, err := buf.Write(path); err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := binary.Write(buf, binary.LittleEndian, NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	return buf.Bytes(), nil
}

// Constants
const COLON_BYTE = byte(58) // ASCII code for ":"
const NULL_BYTE = byte(0)

// Function to pack IMA hash
func packIMAHash(hashAlg string, fileHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack total length (algorithm + 2 extra bytes + hash length)
	totalLen := uint32(len(hashAlg) + 2 + len(fileHash))
	if err := binary.Write(buf, binary.LittleEndian, totalLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}

	// Pack algorithm
	if _, err := buf.Write([]byte(hashAlg)); err != nil {
		return nil, fmt.Errorf("failed to pack algorithm: %v", err)
	}

	// Pack COLON_BYTE (1 byte)
	if err := buf.WriteByte(COLON_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack COLON_BYTE: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := buf.WriteByte(NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	// Pack fileHash (len(fileHash) bytes)
	if _, err := buf.Write(fileHash); err != nil {
		return nil, fmt.Errorf("failed to pack fileHash: %v", err)
	}

	return buf.Bytes(), nil
}

func validateIMAEntry(IMATemplateHash, depField, cgroupField, hashAlg, fileHash, filePathField string) string {
	packedDep, err := packIMAPath([]byte(depField))
	if err != nil {
		log.Fatalf("err")
	}
	packedCgroup, err := packIMAPath([]byte(cgroupField))
	if err != nil {
		log.Fatalf("err")
	}
	decodedFileHash, err := hex.DecodeString(fileHash)
	if err != nil {
		log.Fatalf("err")
	}
	packedFileHash, err := packIMAHash(hashAlg, decodedFileHash)
	if err != nil {
		log.Fatalf("err")
	}
	packedFilePath, err := packIMAPath([]byte(filePathField))
	if err != nil {
		log.Fatalf("err")
	}

	IMAEntrySha1, IMAEntrySha256, err := computeIMAEntryHashes(packedDep, packedCgroup, packedFileHash, packedFilePath)
	if err != nil {
		log.Fatalf("err")
	}

	if IMAEntrySha1 != IMATemplateHash {
		log.Fatalf("IMA Entry invalid")
	}
	return IMAEntrySha256
}

func computeIMAEntryHashes(packedDep, packedCgroup, packedFileHash, packedFilePath []byte) (string, string, error) {
	packedTemplateEntry := append(packedDep, packedCgroup...)
	packedTemplateEntry = append(packedTemplateEntry, packedFileHash...)
	packedTemplateEntry = append(packedTemplateEntry, packedFilePath...)
	sha1Hash := sha1.Sum(packedTemplateEntry)
	sha256Hash := sha256.Sum256(packedTemplateEntry)

	return hex.EncodeToString(sha1Hash[:]), hex.EncodeToString(sha256Hash[:]), nil

}

func main() {
	log.Printf(strings.ToLower("SHA256"))
	rwc, err := simulator.GetWithFixedSeedInsecure(1073741825) //tpmutil.OpenTPM("/dev/tpm0")
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("\ncan't close TPM: %v", err)
		}
	}()

	// agent
	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ak.Close()
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ek.Close()

	if err != nil {
		log.Fatalf(err.Error())
	}
	akNameData, err := ak.Name().Encode()
	if err != nil {
		log.Fatalf("failed to encode AIK Name data")
	}
	akPublicArea, err := ak.PublicArea().Encode()
	if err != nil {
		log.Fatalf("failed to encode AIK public area")
	}
	ekPublic := ek.PublicKey()
	// --> send

	// worker handler
	retrievedName, err := tpm2legacy.DecodeName(bytes.NewBuffer(akNameData))
	if err != nil {
		log.Fatalf("Failed to decode received AIK Name")
	}

	if retrievedName.Digest == nil {
		log.Fatalf("name was not a digest")
	}

	h, err := retrievedName.Digest.Alg.Hash()
	if err != nil {
		log.Fatalf("failed to get name hash: %v", err)
	}

	pubHash := h.New()
	pubHash.Write(akPublicArea)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(retrievedName.Digest.Value, pubDigest) {
		log.Fatalf("name was not for public blob")
	}

	retrievedAKPublicArea, err := tpm2legacy.DecodePublic(akPublicArea)
	if err != nil {
		log.Fatalf("Failed to decode received AIK Public Area")
	}

	if !retrievedAKPublicArea.MatchesTemplate(client.AKTemplateRSA()) {
		log.Fatalf("provided AIK does not match AIK Template")
	}

	// The shared secret and symmetric block size for the credential blob
	secret := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb")
	symBlockSize := 16

	// Re-generate the credential blob and encrypted secret based on AK public info
	credBlob, encSecret, err := credactivation.Generate(retrievedName.Digest, ekPublic, symBlockSize, secret)
	if err != nil {
		log.Fatalf("failed to generate credential blob: %v", err)
	}

	// Initiate a session for PolicySecret, specific for endorsement
	session, _, err := tpm2legacy.StartAuthSession(
		rwc,
		tpm2legacy.HandleNull,
		tpm2legacy.HandleNull,
		make([]byte, 16), // Nonce caller
		nil,              // Encrypted salt
		tpm2legacy.SessionPolicy,
		tpm2legacy.AlgNull,
		tpm2legacy.AlgSHA256,
	)
	if err != nil {
		log.Fatalf("creating auth session failed: %v", err)
	}

	// Set PolicySecret on the endorsement handle, enabling EK use
	auth := tpm2legacy.AuthCommand{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession}
	if _, _, err := tpm2legacy.PolicySecret(rwc, tpm2legacy.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		log.Fatalf("policy secret failed: %v", err)
	}

	// Create authorization commands, linking session and password auth
	auths := []tpm2legacy.AuthCommand{
		{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession},
		{Session: session, Attributes: tpm2legacy.AttrContinueSession},
	}

	// Attempt to activate the credential
	out, err := tpm2legacy.ActivateCredentialUsingAuth(rwc, auths, ak.Handle(), ek.Handle(), credBlob[2:], encSecret[2:])
	if err != nil {
		log.Fatalf("activate credential failed: %v", err)
	}

	fmt.Printf("Activation output: %s\n", out)
}

/*
func main() {
	//IMAAnalysys("eee87997-2192-4e41-927c-65e71a312518")
	//verifyIMAHash("61f0b0d5021a930151775140e900ea55f98110d0")

		tpmCert := "-----BEGIN CERTIFICATE-----\nMIIElTCCA32gAwIBAgIEFMzNOTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC\nREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwR\nT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkg\nUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMB4XDTE2MDEwMTEzMTAyMloXDTMxMDEw\nMTEzMTAyMlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAISFY3i9\nWciX46z/ALiAKejoHbxDOTyldeUPYwNVxU9rOEuWl9EvB+cn//ecWPeVXjj1rqYP\nwZztCDPORjHa93JnW+z75brKmtekC1O8R9ii8oAyEHmwvvgxHd8oOLqHBfTvodn2\n1pE6gxbeZCETU6FcpqVMHJJQBpNocX7nOX/2QqJW10MkUN+b8EodEv7xJ5dFV7B6\nkG9UowP1hqgSngG4gOrm3wAfXREsU0ne9KYTSZwXWb6JErIM0OqY/1Uv4fNmd5BQ\nUJwXQK4WKfQlT5++d2oJHpYkF99CHM4l/JlSg1+apZ80cGfNA9nhuk/E89lrc7MM\nITuVMCij4Mu9XqMCAwEAAaOCAZEwggGNMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEF\nBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDMv\nT3B0aWdhUnNhTWZyQ0EwMDMuY3J0MA4GA1UdDwEB/wQEAwIAIDBRBgNVHREBAf8E\nRzBFpEMwQTEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDETMBEGBWeBBQICDAhTTEIg\nOTY2NTESMBAGBWeBBQIDDAdpZDowNTI4MAwGA1UdEwEB/wQCMAAwUAYDVR0fBEkw\nRzBFoEOgQYY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0Ew\nMDMvT3B0aWdhUnNhTWZyQ0EwMDMuY3JsMBUGA1UdIAQOMAwwCgYIKoIUAEQBFAEw\nHwYDVR0jBBgwFoAUQLhoK40YRQorBoSdm1zZb0zd9L4wEAYDVR0lBAkwBwYFZ4EF\nCAEwIQYDVR0JBBowGDAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDANBgkqhkiG9w0B\nAQsFAAOCAQEApynlEZGc4caT7bQJjhrvOtv4RFu3FNA9hgsF+2BGltsumqo9n3nU\nGoGt65A5mJAMCY1gGF1knvUFq8ey+UuIFw3QulHGENOiRu0aT3x9W7c6BxQIDFFC\nPtA+Qvvg+HJJ6XjihQRc3DU01HZm3xD//fGIDuYasZwBd2g/Ejedp2tKBl2M98FO\n48mbZ4WtaPrEALn3UQMf27pWqe2hUKFSKDEurijnchsdmRjTmUEWM1/9GFkh6IrT\nYvRBngNqOffJ+If+PI3x2GXkGnzsA6IxroEY9CwOhmNp+6xbAgqUedd5fWMLBN3Q\nMjHSp1Sl8wp00xRztfh0diBdicy3Hbn03g==\n-----END CERTIFICATE-----"
		intermediateCert := "-----BEGIN CERTIFICATE-----\nMIIFszCCA5ugAwIBAgIEasM5FDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJE\nRTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJP\nUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkg\nUlNBIFJvb3QgQ0EwHhcNMTQxMTI0MTUzNzE2WhcNMzQxMTI0MTUzNzE2WjCBgzEL\nMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEa\nMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9Q\nVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuUD5SLLVYRmuxDjT3cWQbRTywTWUVFE3EupJQZjJ\n9mvFc2KcjpQv6rpdaT4JC33P1M9iJgrHwYO0AZlGl2FcFpSNkc/3CWoMTT9rOdwS\n/MxlNSkxwTz6IAYUYh7+pd7T49NpRRGZ1dOMfyOxWgA4C0g3EP/ciIvA2cCZ95Hf\nARD9NhuG2DAEYGNRSHY2d/Oxu+7ytzkGFFj0h1jnvGNJpWNCf3CG8aNc5gJAduMr\nWcaMHb+6fWEysg++F2FLav813+/61FqvSrUMsQg0lpE16KBA5QC2Wcr/kLZGVVGc\nuALtgJ/bnd8XgEv7W8WG+jyblUe+hkZWmxYluHS3yJeRbwIDAQABo4IBODCCATQw\nVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vcGtpLmluZmluZW9u\nLmNvbS9PcHRpZ2FSc2FSb290Q0EvT3B0aWdhUnNhUm9vdENBLmNydDAdBgNVHQ4E\nFgQUQLhoK40YRQorBoSdm1zZb0zd9L4wDgYDVR0PAQH/BAQDAgAGMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL3BraS5pbmZpbmVv\nbi5jb20vT3B0aWdhUnNhUm9vdENBL09wdGlnYVJzYVJvb3RDQS5jcmwwFQYDVR0g\nBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBTcu1ar8Rj8ppp1ERBlhBKe1UGS\nuTAQBgNVHSUECTAHBgVngQUIATANBgkqhkiG9w0BAQsFAAOCAgEAeUzrsGq3oQOT\nmF7g71TtMMndwPxgZvaB4bAc7dNettn5Yc1usikERfvJu4/iBs/Tdl6z6TokO+6V\nJuBb6PDV7f5MFfffeThraPCTeDcyYBzQRGnoCxc8Kf81ZJT04ef8CQkkfuZHW1pO\n+HHM1ZfFfNdNTay1h83x1lg1U0KnlmJ5KCVFiB94owr9t5cUoiSbAsPcpqCrWczo\nRsg1aTpokwI8Y45lqgt0SxEmQw2PIAEjHG2GQcLBDeI0c7cK5OMEjSMXStJHmNbp\nu4RHXzd+47nCD2kGV8Bx5QnK8qDVAFAe/UTDQi5mTtDFRL36Nns7jz8USemu+bw9\nl24PN73rKcB2wNF2/oFTLPHkdYfTKYGXG1g2ZkDcTAENSOq3fcTfAuyHQozBwYHG\nGGyyPHy6KvLkqMQuqeDv0QxGOtE+6cedFMP2D9bMaujR389mSm7DE6YyNQClRW7w\nJ1+rNYuN2vErvB96ir1zljXq0yMxrm5nTeiAT4p5eoFqoeSYDbFljt/f+PebREiO\nnJIy4fdvKlHAf70gPdYpYipc4oTZxLeWjDQxRFFBDFrnLdlPSg6zSL2Q3ANAEI3y\nMtHaEaU0wbaBvezyzMUHI5nLnYFL+QRP4N2OFNI/ejBaEpmIXzf6+/eF40MNLHuR\n9/B93Q+hpw8O6XZ7qx697I+5+smLlPQ=\n-----END CERTIFICATE-----\n"
		rootCert := "-----BEGIN CERTIFICATE-----\nMIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh\nMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\nR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB\nIFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD\nVQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD\nVQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH\nQShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn\n25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr\nR3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS\nJRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT\nZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl\n8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2\n7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1\nbdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d\ncAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS\nghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu\n81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV\nHQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN\nUltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M\nBdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y\nrkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ\ngGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y\nnp8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2\nDvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr\nla5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf\nRdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR\npubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv\nJpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM\n6sJa8iBpdRjZrBp5sJBI\n-----END CERTIFICATE-----\n"
		err := VerifyCertificateChain(tpmCert, intermediateCert, rootCert)
		if err != nil {
			log.Fatalf("Certificate is not valid: %v", err)
		}
		log.Printf("Valid certificate tpm")

		rwc, err := tpmutil.OpenTPM("/dev/tpm0") //simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			log.Fatalf("can't open TPM: %v", err)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				log.Fatalf("\ncan't close TPM: %v", err)
			}
		}()

		akHandle := generateAK(rwc)

		pcrValue, err := tpm2legacy.ReadPCR(rwc, 10, tpm2legacy.AlgSHA256)
		if err != nil {
			log.Fatalf("failed to read PCR: %v", err)
		}
		log.Printf("PCR 10 VALUE: %x", pcrValue)
		validateQuote(rwc, akHandle)


	// Inputs
	dep := "/home/nuc/.goland/jbr/lib/jspawnhelper:/home/nuc/.goland/bin/goland:/usr/bin/plasmashell:/usr/lib/systemd/systemd:/usr/lib/systemd/systemd:swapper/0"
	cgroup := "/user.slice/user-1000.slice/user@1000.service/app.slice"
	alg := "sha256"
	hash, _ := hex.DecodeString("da4ef819e3035ee115f29c5103a74a94eba38cca4ca578329aeb5635b2f6264b")
	file := "/usr/local/go/bin/gofmt"
	desiredSha1 := "4b7a3cf367357ef25ee648a92c9431637bfa42c9"

	// Pack the paths and the hash
	packedDep, _ := packIMAPath([]byte(dep))
	packedCgroup, _ := packIMAPath([]byte(cgroup))
	packedFileHash, _ := packIMAHash(alg, hash)
	packedFilePath, _ := packIMAPath([]byte(file))

	// Concatenate all packed data
	packedTemplateEntry := append(append(append(packedDep, packedCgroup...), packedFileHash...), packedFilePath...)

	// Compute SHA-1 hash
	sha1Hash := sha1.Sum(packedTemplateEntry)

	// Print the result as hex
	fmt.Printf("SHA-1 Hash: %x\n", sha1Hash)
	fmt.Printf("desired SHA-1 Hash: %s\n", desiredSha1)
}
*/

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

	selectedPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: []int{10},
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
	tmpFileName, err := copyFileToTemp("/sys/kernel/security/integrity/ima/ascii_runtime_measurements")
	if err != nil {
		log.Fatalf(err.Error())
	}

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

	verifyIMAHash(hex.EncodeToString(quotePCRs.GetPcrs()[10]), tmpFileName)
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
	return ak.Handle()
}

func generateEK(rwc io.ReadWriter) tpmutil.Handle {
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatalf("ERROR:  could not get AttestationKeyRSA: %v", err)
	}
	defer ek.Close()
	return ek.Handle()
}
