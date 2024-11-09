#!/bin/bash

# Check if the first argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <apply|delete>"
  exit 1
fi

# Get the command based on the flag passed
COMMAND="$1"

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
    kubectl $COMMAND -f "$file"
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
