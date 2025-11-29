#!/bin/bash

# --- Configuration ---
REGISTRY="registry.k8s.energyhack.cz"
USERNAME="maksym.koval"
# WARNING: Storing passwords in plain text is a security risk. 
# Consider using environment variables or a secrets manager in production.
PASSWORD="KsVpgRQsXea3CSyCDulU" 
PROJECT="nuclear-elephants/galactic-energy-exchange"
PLATFORMS=${PLATFORMS:-"linux/amd64,linux/arm64"} # Set to "linux/amd64" to force only AMD64

# Accepts version as the first argument, defaults to "v1" if not provided
TAG=${1:-"v1"} 

FULL_IMAGE_NAME="$REGISTRY/$PROJECT:$TAG"

# --- Automation ---

echo "--- Starting Deployment for $FULL_IMAGE_NAME ---"

# 1. Docker Login
# We use --password-stdin to pipe the password directly, bypassing the interactive prompt.
# We use 'sudo' here so the credentials are saved for the root user (needed for the push later).
echo "1. Logging in..."
echo "$PASSWORD" | sudo docker login "$REGISTRY" -u "$USERNAME" --password-stdin

# Check if login succeeded
if [ $? -ne 0 ]; then
    echo "Error: Docker login failed."
    exit 1
fi

# 2. Ensure buildx builder (needed for multi-arch)
echo "2. Ensuring buildx builder..."
if ! sudo docker buildx inspect multiarch-builder >/dev/null 2>&1; then
    sudo docker buildx create --name multiarch-builder --use
else
    sudo docker buildx use multiarch-builder
fi

# 3. Docker Build + Push (multi-arch)
echo "3. Building and pushing image for platforms: $PLATFORMS ..."
sudo docker buildx build --platform "$PLATFORMS" -t "$FULL_IMAGE_NAME" --push .

# Check if build+push succeeded
if [ $? -ne 0 ]; then
    echo "Error: Docker build/push failed."
    exit 1
fi

echo "--- Success! Deployed $FULL_IMAGE_NAME ---"
