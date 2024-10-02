package main

import (
	"fmt"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Function to pull or build the image
func pullOrBuildImage(cmd, image string) (string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("error creating Docker client: %v", err)
	}

	var rootfs string

	if cmd == "pull" {
		// Pull the image
		resp, err := cli.ImagePull(context.Background(), image)
		if err != nil {
			return "", fmt.Errorf("error pulling image: %v", err)
		}
		defer resp.Close()
		io.Copy(os.Stdout, resp)
		rootfs = image
	} else if cmd == "build" {
		// Build the image
		fmt.Println("Build functionality not yet implemented")
		// Implement Docker build logic here
	} else {
		return "", fmt.Errorf("Command %s not supported", cmd)
	}

	return rootfs, nil
}

// Function to get the layers of the image
func getDockerImageLayers(imageName string) ([]string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("error creating Docker client: %v", err)
	}

	imageInspect, _, err := cli.ImageInspectWithRaw(context.Background(), imageName)
	if err != nil {
		return nil, fmt.Errorf("error inspecting image: %v", err)
	}

	return imageInspect.RootFS.Layers, nil
}

// Function to create a whitelist by walking through the layer's file system
func computeWhitelist(whitelist map[string]string, path string) {
	// Here you would implement hashing, file processing, etc.
	// For now, we'll just log the files being added to the whitelist
	whitelist[path] = "computed_hash_here"
	fmt.Printf("File added to whitelist: %s\n", path)
}

// Function to walk through layers and process files
func processLayer(dir string, whitelist map[string]string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, symlinks, devices, etc.
		if !info.Mode().IsRegular() {
			return nil
		}

		// Compute the whitelist for each file
		computeWhitelist(whitelist, path)

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking through layer: %v", err)
	}

	return nil
}

// Main function to create image whitelists
func createImageWhitelists(cmd, image string) error {
	removeExistingContainers()
	removeExistingVolumes()
	removeExistingImages()

	rootfs, err := pullOrBuildImage(cmd, image)
	if err != nil {
		return err
	}

	// Get layers of the Docker image
	layers, err := getDockerImageLayers(image)
	if err != nil {
		return fmt.Errorf("error getting layers: %v", err)
	}

	// Initialize the whitelist structure
	whitelist := make(map[string]string)

	// Process each layer directory and add to whitelist
	for _, layer := range layers {
		layerDir := fmt.Sprintf("/var/lib/docker/overlay2/%s/diff", layer)
		err := processLayer(layerDir, whitelist)
		if err != nil {
			return fmt.Errorf("error processing layer %s: %v", layer, err)
		}
	}

	fmt.Println("Whitelist creation complete")

	return nil
}

// Function to remove existing containers
func removeExistingContainers() {
	// Get list of all containers
	out, err := exec.Command("docker", "ps", "-a", "-q").Output()
	if err != nil {
		log.Fatalf("Error listing containers: %v", err)
	}
	containers := string(out)

	// Remove each container
	for _, container := range strings.Fields(containers) {
		cmd := exec.Command("docker", "rm", "-f", container)
		err := cmd.Run()
		if err != nil {
			log.Printf("Error removing container %s: %v", container, err)
		} else {
			log.Printf("Removed container %s", container)
		}
	}
}

// Function to remove existing volumes
func removeExistingVolumes() {
	// Get list of all volumes
	out, err := exec.Command("docker", "volume", "ls", "-q").Output()
	if err != nil {
		log.Fatalf("Error listing volumes: %v", err)
	}
	volumes := string(out)

	// Remove each volume
	for _, volume := range strings.Fields(volumes) {
		cmd := exec.Command("docker", "volume", "rm", "-f", volume)
		err := cmd.Run()
		if err != nil {
			log.Printf("Error removing volume %s: %v", volume, err)
		} else {
			log.Printf("Removed volume %s", volume)
		}
	}
}

// Function to remove existing images
func removeExistingImages() {
	// Get list of all images
	out, err := exec.Command("docker", "images", "-a", "-q").Output()
	if err != nil {
		log.Fatalf("Error listing images: %v", err)
	}
	images := string(out)

	// Remove each image
	for _, image := range strings.Fields(images) {
		cmd := exec.Command("docker", "rmi", "-f", image)
		err := cmd.Run()
		if err != nil {
			log.Printf("Error removing image %s: %v", image, err)
		} else {
			log.Printf("Removed image %s", image)
		}
	}
}

func main() {
	// Example usage: pass the image name to create image whitelists
	cmd := "pull"
	imageName := "alpine:latest"

	err := createImageWhitelists(cmd, imageName)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
