package main

import (
	"context"
	"errors"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ContainerDependencyWhitelist struct {
	FilePath     string              `json:"filePath" bson:"filePath"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ContainerRuntimeWhitelist struct {
	ContainerRuntimeName string                         `json:"containerRuntimeName" bson:"containerRuntimeName"`
	ValidFiles           []ContainerDependencyWhitelist `json:"validFiles" json:"validFiles"`
}

type ContainerRuntimeCheckRequest struct {
	ContainerRuntimeName         string     `json:"containerRuntimeName"`
	ContainerRuntimeDependencies []IMAEntry `json:"containerRuntimeDependencies"`
	HashAlg                      string     `json:"hashAlg"` // Include the hash algorithm in the request
}

// OsWhitelist represents the structure of our stored document in MongoDB.
// It categorizes valid digests by hash algorithm.
type OsWhitelist struct {
	OSName       string              `json:"osName" bson:"osName"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

// WorkerWhitelistCheckRequest defines the structure of the request to check a whitelist.
type WorkerWhitelistCheckRequest struct {
	OSName        string `json:"osName"`
	BootAggregate string `json:"bootAggregate"`
	HashAlg       string `json:"hashAlg"` // Include the hash algorithm in the request
}

type PodFileWhitelist struct {
	FilePath     string              `json:"filePath" bson:"filePath"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ImageWhitelist struct {
	ImageName   string             `json:"imageName" bson:"imageName"`
	ImageDigest string             `json:"imageDigest" bson:"imageDigest"`
	ValidFiles  []PodFileWhitelist `json:"validFiles" json:"validFiles"`
}

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type PodWhitelistCheckRequest struct {
	PodImageName   string     `json:"podImageName"`
	PodImageDigest string     `json:"podImageDigest"`
	PodFiles       []IMAEntry `json:"podFiles"`
	HashAlg        string     `json:"hashAlg"` // Include the hash algorithm in the request
}

// MongoDB client and global variables
var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color

	workerWhitelist           *mongo.Collection
	podWhitelist              *mongo.Collection
	containerRuntimeWhitelist *mongo.Collection
	whitelistPORT             string
	whitelistURI              string
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
	whitelistURI = getEnv("WHITELIST_DB_URI", "mongodb://localhost:27017")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
}

// appendToWorkerWhitelist handles the addition of a new valid OsWhitelist.
func appendToWorkerWhitelist(c *gin.Context) {
	var newOsWhitelist OsWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(&newOsWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Check if the OSName already exists in the WorkerWhitelist
	var existingOsWhitelist OsWhitelist
	err := workerWhitelist.FindOne(context.TODO(), bson.M{"osName": newOsWhitelist.OSName}).Decode(&existingOsWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Worker whitelist"})
		return
	}

	if existingOsWhitelist.OSName == newOsWhitelist.OSName {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "OS whitelist already exists"})
		return
	}

	// Insert the new OS whitelist
	_, err = workerWhitelist.InsertOne(context.TODO(), newOsWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to append new valid OS list to Worker whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OS whitelist added successfully"})
	return
}

// checkWorkerWhitelist verifies if a given OS and digest match the stored worker whitelist.
func checkWorkerWhitelist(c *gin.Context) {
	var checkRequest WorkerWhitelistCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Query MongoDB for the document matching the requested OS name
	var osWhitelist OsWhitelist
	err := workerWhitelist.FindOne(context.TODO(), bson.M{"osName": checkRequest.OSName}).Decode(&osWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "OS whitelist not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query worker whitelist"})
		}
		return
	}

	// Check if the digest matches within the specified hash algorithm category
	digests, exists := osWhitelist.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "No digests found for the specified hash algorithm"})
		return
	}

	for _, digest := range digests {
		if digest == checkRequest.BootAggregate {
			c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Boot Aggregate matches the stored whitelist"})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Boot Aggregate does not match the stored whitelist"})
	return
}

// deleteFromWorkerWhitelist deletes a worker whitelist record based on the provided OSName.
func deleteFromWorkerWhitelist(c *gin.Context) {
	osName, err := url.QueryUnescape(c.Query("osName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid osName"})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := workerWhitelist.DeleteOne(context.TODO(), bson.M{"osName": osName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to delete the worker whitelist record"})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Worker whitelist record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Worker whitelist record deleted successfully"})
}

// dropWorkerWhitelist drops the workerWhitelist collection from the MongoDB database.
func dropWorkerWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := workerWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to drop Worker whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Worker whitelist dropped successfully"})
	return
}

// initializeMongoDB connects to the MongoDB database and sets the workerWhitelist collection.
func initializeMongoDB() {
	clientOptions := options.Client().ApplyURI(whitelistURI)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB client: %v", err)
	}

	// Access the database and workerWhitelist collection
	workerWhitelist = client.Database("whitelists").Collection("worker_whitelist")
	podWhitelist = client.Database("whitelists").Collection("pod_whitelist")
	containerRuntimeWhitelist = client.Database("whitelists").Collection("container_runtime_whitelist")
	return
}

// appendToContainerRuntimeWhitelist handles the addition of a new valid ContainerRuntimeWhitelist.
func appendToContainerRuntimeWhitelist(c *gin.Context) {
	var newContainerRuntimeWhitelist ContainerRuntimeWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(&newContainerRuntimeWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Check if the Container Runtime already exists in the Container Runtime whitelist
	var existingContainerRuntimeWhitelist ContainerRuntimeWhitelist
	err := containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"containerRuntimeName": newContainerRuntimeWhitelist.ContainerRuntimeName}).Decode(&existingContainerRuntimeWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Container Runtime whitelist"})
		return
	}

	if existingContainerRuntimeWhitelist.ContainerRuntimeName == newContainerRuntimeWhitelist.ContainerRuntimeName {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "Container Runtime whitelist already exists"})
		return
	}

	// Insert the new OS whitelist
	_, err = containerRuntimeWhitelist.InsertOne(context.TODO(), newContainerRuntimeWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to append new valid Container Runtime list to Container Runtime whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Container Runtime whitelist added successfully"})
	return
}

// checkContainerRuntimeWhitelist verifies if a given Container Runtime and digest match the stored Container Runtime whitelist.
func checkContainerRuntimeWhitelist(c *gin.Context) {
	var checkRequest ContainerRuntimeCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Query MongoDB for the document matching the requested Container Runtime name
	var existingContainerRuntimeWhitelist ContainerRuntimeWhitelist
	err := containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"containerRuntimeName": checkRequest.ContainerRuntimeName}).Decode(&existingContainerRuntimeWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Container Runtime whitelist not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Container Runtime whitelist"})
		}
		return
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, containerRuntimeDependency := range checkRequest.ContainerRuntimeDependencies {
		found := false
		for _, validFile := range existingContainerRuntimeWhitelist.ValidFiles {
			// Check if the file paths match
			if containerRuntimeDependency.FilePath == validFile.FilePath {
				digests, exists := validFile.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
				if !exists {
					c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "No digests found for the specified hash algorithm"})
					return
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range digests {
					if digest == containerRuntimeDependency.FileHash {
						found = true
						break
					}
				}
				if found {
					break // Move on to the next container runtime dependency file once a match is found
				}
			}
		}

		// If no match is found for the current container dependency file
		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "File hash does not match the stored whitelist"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "All Container Runtime depdencency files match the stored whitelist"})
	return
}

// deleteFromContainerRuntimeWhitelist deletes a worker whitelist record based on the provided containerRuntimeName.
func deleteFromContainerRuntimeWhitelist(c *gin.Context) {
	containerRuntimeName, err := url.QueryUnescape(c.Query("containerRuntimeName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid containerRuntimeName"})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := containerRuntimeWhitelist.DeleteOne(context.TODO(), bson.M{"containerRuntimeName": containerRuntimeName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to delete the Container Runtime whitelist record"})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Container Runtime whitelist record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Container Runtime whitelist record deleted successfully"})
}

// dropContainerRuntimeWhitelist drops the containerRuntimeWhitelist collection from the MongoDB database.
func dropContainerRuntimeWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := containerRuntimeWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to drop Container Runtime whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Container Runtime whitelist dropped successfully"})
	return
}

// dropPodWhitelist drops the podWhitelist collection from the MongoDB database.
func dropPodWhitelist(c *gin.Context) {
	// Drop the podWhitelist collection
	err := podWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to drop Pod whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Pod whitelist dropped successfully"})
	return
}

// appendNewImageToPodWhitelist adds a new ImageWhitelist with valid files to the pod whitelist if it doesn't exist
func appendNewImageToPodWhitelist(c *gin.Context) {
	var imageWhitelist ImageWhitelist

	// Bind JSON input to the ImageWhitelist struct
	if err := c.ShouldBindJSON(&imageWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Query to check if the imageName already exists
	filter := bson.M{"imageName": imageWhitelist.ImageName}
	var existing ImageWhitelist
	err := podWhitelist.FindOne(context.TODO(), filter).Decode(&existing)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// If the image does not exist, insert it
			_, err := podWhitelist.InsertOne(context.TODO(), imageWhitelist)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to append new image whitelist"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "success", "message": "New image whitelist added successfully"})
			return
		} else {
			// If any other error occurs during query
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Pod whitelist"})
			return
		}
	}

	// If the image already exists, return a conflict message
	c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "Image whitelist already exists"})
}

// appendFilesToExistingImageWhitelistByImageName adds new valid files to an existing ImageWhitelist for the given imageName.
func appendFilesToExistingImageWhitelistByImageName(c *gin.Context) {
	var appendRequest struct {
		ImageName string           `json:"imageName"`
		NewFiles  PodFileWhitelist `json:"newFiles"`
	}

	// Bind JSON input to the list of new valid files
	if err := c.ShouldBindJSON(&appendRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Check if the image whitelist exists
	filter := bson.M{"imageName": appendRequest.ImageName}
	update := bson.M{"$addToSet": bson.M{"validFiles": bson.M{"$each": appendRequest.NewFiles}}}

	// Update the existing ImageWhitelist with new valid files
	_, err := podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to append files: no whitelist for Pod image:" + appendRequest.ImageName})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Files added to Pod image: " + appendRequest.ImageName + " whitelist successfully"})
}

// checkPodWhitelist verifies if the given pod's files match the stored whitelist for the pod's image.
func checkPodWhitelist(c *gin.Context) {
	var checkRequest PodWhitelistCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request body"})
		return
	}

	// Query MongoDB for matching pod image
	var imageWhitelist ImageWhitelist
	err := podWhitelist.FindOne(context.TODO(), bson.M{"imageName": checkRequest.PodImageName}).Decode(&imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pod image not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Pod whitelist"})
		}
		return
	}

	if imageWhitelist.ImageDigest != checkRequest.PodImageDigest {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Provided Pod image digest does not match stored image digest"})
		return
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, podFile := range checkRequest.PodFiles {
		found := false
		for _, validFile := range imageWhitelist.ValidFiles {
			// Check if the file paths match
			if podFile.FilePath == validFile.FilePath {
				digests, exists := validFile.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
				if !exists {
					c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "No digests found for the specified hash algorithm"})
					return
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range digests {
					if digest == podFile.FileHash {
						found = true
						break
					}
				}
				if found {
					break // Move on to the next pod file once a match is found
				}
			}
		}

		// If no match is found for the current pod file
		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "File hash does not match the stored whitelist"})
			return
		}
	}

	// If all pod files match
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "All pod files match the stored whitelist"})
}

// deleteFileFromPodWhitelist deletes a file and its digests under a given imageName and filePath in the pod whitelist.
func deleteFileOfImageFromPodWhitelist(c *gin.Context) {
	imageName, err := url.QueryUnescape(c.Query("imageName"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Invalid imageName"})
		return
	}
	filePath, err := url.QueryUnescape(c.Query("filePath"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Invalid filePath"})
		return
	}

	// Query MongoDB for the pod image whitelist by imageName
	filter := bson.M{"imageName": imageName}
	var imageWhitelist ImageWhitelist
	err = podWhitelist.FindOne(context.TODO(), filter).Decode(&imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pod image not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to query Pod whitelist"})
		}
		return
	}

	// Search for the file by filePath and remove it along with its digests
	var updatedValidFiles []PodFileWhitelist
	fileFound := false

	for _, validFile := range imageWhitelist.ValidFiles {
		if validFile.FilePath == filePath {
			fileFound = true
			// Skip adding this file to updatedValidFiles to effectively remove it
			continue
		}
		updatedValidFiles = append(updatedValidFiles, validFile)
	}

	if !fileFound {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "File path not found in the whitelist"})
		return
	}

	// Update MongoDB with the modified whitelist (remove the file)
	update := bson.M{"$set": bson.M{"validfiles": updatedValidFiles}} // fixed the field name here
	_, err = podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to update Pod whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "File and associated digests removed from the whitelist"})
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	initializeMongoDB()

	// Initialize Gin router
	r := gin.Default()

	// Worker whitelist
	r.POST("/whitelist/worker/os/check", checkWorkerWhitelist)
	r.POST("/whitelist/worker/os/add", appendToWorkerWhitelist)
	r.DELETE("/whitelist/worker/os/delete", deleteFromWorkerWhitelist)
	r.DELETE("/whitelist/worker/drop", dropWorkerWhitelist)

	// Pod whitelist
	r.POST("/whitelist/pod/image/check", checkPodWhitelist)
	r.POST("/whitelist/pod/image/add", appendNewImageToPodWhitelist)
	r.POST("/whitelist/pod/image/file/add", appendFilesToExistingImageWhitelistByImageName)
	r.DELETE("/whitelist/pod/image/file/delete", deleteFileOfImageFromPodWhitelist)
	r.DELETE("/whitelist/pod/drop", dropPodWhitelist)

	// Container Runtime whitelist
	r.POST("/whitelist/container/runtime/check", checkContainerRuntimeWhitelist)
	r.POST("/whitelist/container/runtime/add", appendToContainerRuntimeWhitelist)
	r.DELETE("/whitelist/container/runtime/delete", deleteFromContainerRuntimeWhitelist)
	r.DELETE("/whitelist/container/runtime/drop", dropContainerRuntimeWhitelist)

	// Start the server
	if err := r.Run(":" + whitelistPORT); err != nil {
		log.Fatalf("Failed to run the server: %v", err)
	}
}
