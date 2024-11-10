#!/bin/bash

# Check if the first argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <apply|delete>"
  exit 1
fi

# Get the command based on the flag passed
COMMAND="$1"

# Define the namespace
NAMESPACE="attestation-system"

# Create or delete the namespace based on the command
if [ "$COMMAND" == "apply" ]; then
  echo "Ensuring namespace '$NAMESPACE' exists..."
  kubectl get namespace "$NAMESPACE" > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    kubectl create namespace "$NAMESPACE"
    if [ $? -ne 0 ]; then
      echo "Failed to create namespace '$NAMESPACE'. Exiting."
      exit 1
    fi
  fi
elif [ "$COMMAND" == "delete" ]; then
  echo "Deleting namespace '$NAMESPACE'..."
  kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
  if [ $? -ne 0 ]; then
    echo "Failed to delete namespace '$NAMESPACE'. Exiting."
    exit 1
  fi
fi

# List of YAML files to apply/delete
YAML_FILES=(
  "attestation-secrets.yaml"
  "cluster-status-controller.yaml"
  "pod-handler-service.yaml"
  "pod-watcher.yaml"
  "registrar-service.yaml"
  "verifier.yaml"
  "whitelist-provider-service.yaml"
  "worker-handler.yaml"
)

# Check if the command is valid
if [ "$COMMAND" == "apply" ] || [ "$COMMAND" == "delete" ]; then
  for file in "${YAML_FILES[@]}"; do
    echo "Running: kubectl $COMMAND -f $file"
    kubectl $COMMAND -f "$file" -n "$NAMESPACE"
    if [ $? -ne 0 ]; then
      echo "Error applying/deleting $file"
      exit 1
    fi
  done
else
  echo "Invalid command. Use 'apply' or 'delete'."
  exit 1
fi

echo "Operation '$COMMAND' completed successfully."
