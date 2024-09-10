package main

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"k8s.io/client-go/util/homedir"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Global Kubernetes clientset variable
var clientset *kubernetes.Clientset
var dynamicClient dynamic.Interface

var attestationNamespace string

var (
	red    *color.Color
	green  *color.Color
	yellow *color.Color
)

// CRDGroupVersion defines the group version used for the CRD
const CRDGroupVersion = "example.com/v1"

// AgentCoreImage defines the image used for the agent core deployment
const AgentCoreImage = "franczar/k8s-attestation-agent-core:latest"

func main() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)

	var err error
	// Initialize Kubernetes client
	clientset, dynamicClient, err = getKubernetesClient()
	if err != nil {
		panic(err)
	}

	attestationNamespace = os.Getenv("attestation_namespace")
	if attestationNamespace == "" {
		fmt.Printf(yellow.Sprintf("[%s] 'attestation_namespace' environment variable missing: setting 'default' value\n", time.Now().Format("02-01-2006 15:04:05")))
		attestationNamespace = "default"
	}

	// Create Agent CRD in the cluster
	deployAgentCRD()

	// Watch for node events
	watchNodes()
}

func getKubernetesClient() (*kubernetes.Clientset, dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, err
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	return clientset, dynamicClient, nil
}

func watchNodes() {
	watcher, err := clientset.CoreV1().Nodes().Watch(context.Background(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}
	defer watcher.Stop()

	for {
		select {
		case event := <-watcher.ResultChan():
			node, ok := event.Object.(*corev1.Node)
			if !ok {
				continue
			}

			switch event.Type {
			case watch.Deleted:
				if !nodeIsControlPlane(node) {
					fmt.Printf(yellow.Sprintf("[%s] Node %s deleted from the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
					deleteAgentCRDInstance(node.Name)
					deleteAgentCore(node.Name)
				}

			case watch.Added:
				if !nodeIsControlPlane(node) {
					fmt.Printf(green.Sprintf("[%s] Node %s joined the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))
					createAgentCRDInstance(node.Name)
					deployAgentCore(node.Name)
				}
			}
		}
	}
}

func nodeIsControlPlane(node *corev1.Node) bool {
	_, exists := node.Labels["node-role.kubernetes.io/control-plane"]
	return exists
}

func deleteAgentCRDInstance(nodeName string) {
	fileName := filepath.Join("deployed-crds", fmt.Sprintf("agent-%s.yaml", nodeName))

	// Apply YAML file using kubectl apply command
	cmd := exec.Command("kubectl", "delete", "-f", fileName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(red.Sprintf("Error deleting YAML file: %v\n", err))
		fmt.Println(red.Println(string(output)))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Agent CRD instance deleted: %s\n", time.Now().Format("02-01-2006 15:04:05"), fileName))

	err = os.Remove(fileName)
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("Error deleting file: %v\n", err)
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Agent CRD instance YAML deleted: %s\n", time.Now().Format("02-01-2006 15:04:05"), fileName))
}

func createAgentCRDInstance(nodeName string) {
	// Get the list of pods running on the specified node and attestation namespace
	pods, err := clientset.CoreV1().Pods(attestationNamespace).List(context.TODO(), v1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("Error getting pods on node %s: %v\n", nodeName, err))
		return
	}

	// Initialize YAML content with agent details
	yamlContent := fmt.Sprintf(`
apiVersion: %s
kind: Agent
metadata:
  name: agent-%s
  namespace: kube-system
spec:
  agentName: agent-%s
  agentStatus: Ready
  nodeStatus: Trusted
  enabled: true
  podStatus:
`, CRDGroupVersion, nodeName, nodeName)

	// Add pod status entries to YAML content
	for _, pod := range pods.Items {
		podName := pod.Name
		// Skip pods with name prefixed with "agent-core-"
		if strings.HasPrefix(podName, "agent-core-") {
			continue
		}
		// Append pod status entry to YAML content
		yamlContent += fmt.Sprintf(`
  - podName: "%s"
    status: "Trusted"
    reason: "Pod attestation successful"
    lastCheck: %s
`, podName, time.Now().Format("2006-01-02T15:04:05Z07:00"))
	}

	// Create the directory if it doesn't exist
	dir := filepath.Join("deployed-crds")
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Printf(red.Sprintf("Error creating directory: %v\n", err))
		return
	}

	// Write YAML content to a file
	fileName := filepath.Join(dir, fmt.Sprintf("agent-%s.yaml", nodeName))
	err = ioutil.WriteFile(fileName, []byte(yamlContent), 0644)
	if err != nil {
		fmt.Printf(red.Sprintf("Error writing to file: %v\n", err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD instance created: %s\n", time.Now().Format("02-01-2006 15:04:05"), fileName))

	// Apply YAML file using kubectl apply command
	cmd := exec.Command("kubectl", "apply", "-f", fileName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(red.Sprintf("Error applying YAML file: %v\n", err))
		fmt.Println(red.Sprintln(string(output)))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD instance applied: %s\n", time.Now().Format("02-01-2006 15:04:05"), fileName))
}

func deployAgentCRD() {
	yamlContent := `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: agents.example.com
spec:
  group: example.com
  names:
    kind: Agent
    listKind: AgentList
    plural: agents
    singular: agent
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                agentName:
                  type: string
                agentStatus:
                  type: string
                nodeStatus:
                  type: string
                enabled:
                  type: boolean
                podStatus:
                  type: array
                  items:
                    type: object
                    properties:
                      podName:
                        type: string
                      status:
                        type: string
                      reason:
                        type: string
                      lastCheck:
                        type: string
                        format: date-time
`

	tempFileName := "/tmp/crd.yaml"
	err := ioutil.WriteFile(tempFileName, []byte(yamlContent), 0644)
	if err != nil {
		fmt.Printf(red.Sprintf("Error writing to file: %v\n", err))
		return
	}
	defer func() {
		err := os.Remove(tempFileName)
		if err != nil && !os.IsNotExist(err) {
			fmt.Printf(red.Sprintf("Error cleaning up temporary file: %v\n", err))
		}
	}()

	cmd := exec.Command("kubectl", "apply", "-f", tempFileName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(red.Sprintf("Error applying YAML file: %v\n", err))
		fmt.Println(red.Println(string(output)))
		return
	}

	fmt.Printf(green.Sprintf("[%s] CRD 'agents.example.com' created successfully\n", time.Now().Format("02-01-2006 15:04:05")))
}

func deployAgentCore(nodeName string) {
	replicas := int32(1)

	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "agent-core-" + nodeName,
			Namespace: "kube-system",
			Labels: map[string]string{
				"app": "agent-core",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "agent-core",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Labels: map[string]string{
						"app": "agent-core",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"kubernetes.io/hostname": nodeName,
					},
					Containers: []corev1.Container{
						{
							Name:  "agent-core-container",
							Image: AgentCoreImage,
						},
					},
				},
			},
		},
	}

	_, err := clientset.AppsV1().Deployments("kube-system").Create(context.Background(), deployment, v1.CreateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error deploying Agent Core: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent Core deployed on node %s \n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
}

func deleteAgentCore(nodeName string) {
	deploymentName := "agent-core-" + nodeName

	err := clientset.AppsV1().Deployments("kube-system").Delete(context.Background(), deploymentName, v1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error deleting Agent Core: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(yellow.Sprintf("[%s] Agent Core deleted\n", time.Now().Format("02-01-2006 15:04:05")))
}
