#!/bin/bash

# LocalStack Pro Pods - Save and Load Infrastructure State

ENDPOINT_URL=http://localhost:4566
POD_NAME="tonkitlab-borrow-dev"

case "$1" in
    "save")
        echo "Saving LocalStack state to Pod: $POD_NAME"
        curl -X POST "$ENDPOINT_URL/_localstack/pods/$POD_NAME"
        echo "State saved successfully!"
        ;;
    "load")
        echo "Loading LocalStack state from Pod: $POD_NAME"
        curl -X GET "$ENDPOINT_URL/_localstack/pods/$POD_NAME/load"
        echo "State loaded successfully!"
        ;;
    "list")
        echo "Available Pods:"
        curl -X GET "$ENDPOINT_URL/_localstack/pods" | jq .
        ;;
    "delete")
        echo "Deleting Pod: $POD_NAME"
        curl -X DELETE "$ENDPOINT_URL/_localstack/pods/$POD_NAME"
        echo "Pod deleted successfully!"
        ;;
    *)
        echo "Usage: $0 {save|load|list|delete}"
        echo ""
        echo "Commands:"
        echo "  save   - Save current LocalStack state to a Pod"
        echo "  load   - Load LocalStack state from a Pod"
        echo "  list   - List all available Pods"
        echo "  delete - Delete the specified Pod"
        exit 1
        ;;
esac
