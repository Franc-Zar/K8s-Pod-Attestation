package main

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	red                  *color.Color
	green                *color.Color
	yellow               *color.Color
	blue                 *color.Color
	dynamicClient        dynamic.Interface
	clientset            *kubernetes.Clientset
	attestationNamespace string
)

func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	blue = color.New(color.FgBlue)
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	attestationNamespace = getEnv("attestation_namespace", "default")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACE" {
			fmt.Printf(yellow.Sprintf("[%s] '%s' environment variable missing: setting default value\n", time.Now().Format("02-01-2006 15:04:05"), key))
		}
		return defaultValue
	}
	return value
}

// configureKubernetesClient initializes the Kubernetes client.
func configureKubernetesClient() {
	var err error
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}
	}
	dynamicClient = dynamic.NewForConfigOrDie(config)
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}

func watchAgentCRDChanges(stopCh chan os.Signal) {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	crdGVR := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}

	// Start watching for changes to the CRD
	watcher, err := dynamicClient.Resource(crdGVR).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	defer watcher.Stop()

	// Process events from the watcher
	for {
		select {
		case event := <-watcher.ResultChan():
			switch event.Type {
			case watch.Added:
				fmt.Printf(green.Sprintf("[%s] Agent CRD Added:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			case watch.Modified:
				fmt.Printf(blue.Sprintf("[%s] Agent CRD Modified:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
				checkPodStatus(event.Object)
			case watch.Deleted:
				fmt.Printf(yellow.Sprintf("[%s] Agent CRD Deleted:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			case watch.Error:
				fmt.Printf(red.Sprintf("[%s] Error:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(event.Object)))
			}
		case <-stopCh:
			return
		}
	}
}

func formatAgentCRD(obj interface{}) map[string]interface{} {
	agentCRD, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}

	spec, specExists := agentCRD["spec"].(map[string]interface{})
	if !specExists {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}
	return spec
}

func deletePod(podName string) error {
	err := dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}).Namespace(attestationNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error deleting pod %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return err
	}
	fmt.Printf(yellow.Sprintf("[%s] Pod %s deleted successfully\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return nil
}

func checkPodStatus(obj interface{}) {
	spec := formatAgentCRD(obj)

	podStatusInterface, exists := spec["podStatus"]
	if !exists {
		fmt.Println(red.Println("Error: Missing 'podStatus' field in Agent CRD"))
		return
	}

	podStatus, ok := podStatusInterface.([]interface{})
	if !ok {
		fmt.Println(red.Println("Error: Unable to parse 'podStatus' field in Agent CRD"))
		return
	}

	for _, ps := range podStatus {
		pod := ps.(map[string]interface{})
		podName, ok := pod["podName"].(string)
		if !ok {
			fmt.Println(red.Println("Error: Unable to parse 'podName' field in podStatus"))
			continue
		}
		status, ok := pod["status"].(string)
		if !ok {
			fmt.Println(red.Println("Error: Unable to parse 'status' field in podStatus"))
			continue
		}

		if status == "Untrusted" {
			fmt.Printf(yellow.Sprintf("[%s] Detected Untrusted Pod: %s\n", time.Now().Format("02-01-2006 15:04:05"), podName))
			err := deletePod(podName)
			if err != nil {
				fmt.Printf(red.Sprintf("Error deleting pod: %v\n", err))
			}
		}
	}
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	stopCh := setupSignalHandler()

	watchAgentCRDChanges(stopCh)

	// Keep the application running until terminated
	fmt.Printf(green.Sprintf("Watching Agent CRD changes...\n\n"))
	<-stopCh
}
