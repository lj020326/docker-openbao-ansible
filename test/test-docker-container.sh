#!/bin/bash

# Exit on error
set -e

# Define constants
OPENBAO_UID=1102
OPENBAO_GID=1102

DOCKER_REGISTRY="lj020326"
DOCKER_REGISTRY_TEST="media.johnson.int:5000"
DOCKER_IMAGE_NAME="${DOCKER_REGISTRY}/openbao-ansible:latest"

BASE_DIR="/home/container-user/docker/openbao"
DATA_DIR="${BASE_DIR}/home/file"
LOGS_DIR="${BASE_DIR}/home/logs"
CONFIG_DIR="${BASE_DIR}/home/custom_config"
SECRETS_DIR="${BASE_DIR}/secrets"
ANSIBLE_VAULT_PASSWORD_FILE="${SECRETS_DIR}/ansible_vault_password"
COMPOSE_FILE="docker-compose.yml"
INIT_FILE="init.txt.decrypted"

# Generate a secure Ansible Vault password if not provided
if [ ! -f "$ANSIBLE_VAULT_PASSWORD_FILE" ]; then
    echo "Generating new Ansible Vault password..."
    mkdir -p "$SECRETS_DIR"
    openssl rand -base64 32 > "$ANSIBLE_VAULT_PASSWORD_FILE"
fi

# Create directories for persistent storage and secrets
echo "Creating directories for OpenBao..."
mkdir -p "$DATA_DIR" "$LOGS_DIR" "$CONFIG_DIR" "$SECRETS_DIR"

# Set proper permissions (no chown, assuming host user matches openbao UID/GID)
chmod -R u+rwX "$DATA_DIR" "$LOGS_DIR" "$CONFIG_DIR"
chmod 600 "$ANSIBLE_VAULT_PASSWORD_FILE"

# Create docker-compose.yml
echo "Creating docker-compose.yml..."
cat > "$COMPOSE_FILE" << EOF
networks:
  docker_net:
    driver: bridge
services:
  openbao:
    image: ${DOCKER_IMAGE_NAME}
    container_name: docker-openbao-1
    ports:
      - "8200:8200"
    volumes:
      - /home/container-user/docker/openbao/home/file:/vault/file
      - /home/container-user/docker/openbao/home/logs:/vault/logs
      - /home/container-user/docker/openbao/home/custom_config:/vault/custom_config
      - /home/container-user/docker/openbao/secrets:/run/secrets
      - /etc/passwd:/etc/passwd:ro
    environment:
      - VAULT_ADDR=http://127.0.0.1:8200
      - ANSIBLE_VAULT_PASSWORD=/run/secrets/ansible_vault_password
    user: ${OPENBAO_UID}:${OPENBAO_GID}
    healthcheck:
      test: ["CMD-SHELL", "VAULT_ADDR=http://127.0.0.1:8200 vault status > /vault/logs/healthcheck_output 2>&1; grep -q 'Sealed.*false' /vault/logs/healthcheck_output"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 300s
    networks:
      - docker_net
EOF

# Create OpenBao configuration file
echo "Creating OpenBao configuration file..."
cat > "${CONFIG_DIR}/local.json" << 'EOF'
{
  "storage": {
    "file": {
      "path": "/vault/file"
    }
  },
  "listener": {
    "tcp": {
      "address": "0.0.0.0:8200",
      "tls_disable": true
    }
  },
  "api_addr": "http://127.0.0.1:8200",
  "default_lease_ttl": "168h",
  "max_lease_ttl": "720h",
  "ui": true,
  "log_level": "debug"
}
EOF

# Set permissions for configuration file
chmod 644 "${CONFIG_DIR}/local.json"

# Pull the latest image
echo "Pulling latest openbao-ansible image..."
docker pull ${DOCKER_IMAGE_NAME}

# Start the container
echo "Starting OpenBao container..."
docker compose -f "$COMPOSE_FILE" up -d openbao

# Wait for OpenBao to be ready
echo "Waiting for OpenBao to be ready..."
MAX_WAIT=300
WAIT_INTERVAL=10
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' docker-openbao-1 2>/dev/null)
    if [ "$CONTAINER_STATUS" = "running" ]; then
        HEALTH_STATUS=$(docker inspect -f '{{.State.Health.Status}}' docker-openbao-1 2>/dev/null)
        echo "OpenBao container status: $CONTAINER_STATUS, health status: $HEALTH_STATUS"
        if [ "$HEALTH_STATUS" = "healthy" ]; then
            echo "OpenBao container is healthy and ready!"
            break
        fi
        # Check vault status
        STATUS_OUTPUT=$(docker compose exec -T openbao vault status 2>&1)
        if echo "$STATUS_OUTPUT" | grep -q "Sealed.*false"; then
            echo "OpenBao server is responsive and unsealed!"
            break
        elif echo "$STATUS_OUTPUT" | grep -q "Sealed"; then
            echo "OpenBao server is responsive but sealed. Waiting for auto-unseal..."
        else
            echo "Vault status output: $STATUS_OUTPUT"
        fi
    else
        echo "OpenBao container status: $CONTAINER_STATUS. Waiting ${WAIT_INTERVAL}s..."
    fi
    sleep $WAIT_INTERVAL
    ELAPSED=$((ELAPSED + WAIT_INTERVAL))
done

# Check if container is running and healthy
if [ "$(docker inspect -f '{{.State.Running}}' docker-openbao-1 2>/dev/null)" = "true" ] && \
   [ "$(docker inspect -f '{{.State.Health.Status}}' docker-openbao-1 2>/dev/null)" = "healthy" ]; then
    echo "OpenBao container is running and healthy."

    # Check if OpenBao is initialized
    STATUS=$(docker compose exec -T openbao vault status 2>&1)
    if echo "$STATUS" | grep -q "Initialized.*true"; then
        echo "OpenBao is initialized."
        if echo "$STATUS" | grep -q "Sealed.*false"; then
            echo "OpenBao is unsealed."
        else
            echo "Error: OpenBao is sealed after startup. Check logs for auto-unseal issues."
            docker logs docker-openbao-1
            exit 1
        fi
    else
        echo "Error: OpenBao is not initialized. Check logs for initialization issues."
        docker logs docker-openbao-1
        exit 1
    fi

    # Retrieve and decrypt init.txt to extract root token
    echo "Retrieving root token from encrypted init.txt..."
    docker compose exec -T openbao sh -c "cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/logs/init.txt.decrypted --vault-password-file=/dev/stdin"
    if [ $? -eq 0 ]; then
        ROOT_TOKEN=$(docker compose exec -T openbao sh -c "grep 'Initial Root Token' /vault/logs/init.txt.decrypted | awk '{print \$NF}'")
        if [ -z "$ROOT_TOKEN" ]; then
            echo "Error: Failed to extract root token from init.txt."
            docker compose exec -T openbao cat /vault/logs/init.txt.decrypted
            docker logs docker-openbao-1
            exit 1
        fi
        # Clean up decrypted file
        docker compose exec -T openbao rm /vault/logs/init.txt.decrypted
    else
        echo "Error: Failed to decrypt init.txt."
        docker logs docker-openbao-1
        exit 1
    fi

    # Create admin token
    echo "Creating admin token..."
    docker compose exec -T openbao vault login "$ROOT_TOKEN" >/dev/null
    docker compose exec -T openbao vault policy write admin - <<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
    ADMIN_TOKEN=$(docker compose exec -T openbao vault token create -policy=admin -format=json | grep '"token":' | awk -F'"' '{print $4}')
    if [ -z "$ADMIN_TOKEN" ]; then
        echo "Error: Failed to create admin token."
        docker logs docker-openbao-1
        exit 1
    fi

    # Test vault functionality
    echo "Testing vault functionality with admin token..."
    docker compose exec -T openbao vault login "$ADMIN_TOKEN" >/dev/null
    docker compose exec -T openbao vault kv put secret/test key=value >/dev/null
    TEST_OUTPUT=$(docker compose exec -T openbao vault kv get -field=key secret/test)
    if [ "$TEST_OUTPUT" = "value" ]; then
        echo "Vault test successful: Secret written and read correctly."
    else
        echo "Error: Vault test failed. Expected 'value', got '$TEST_OUTPUT'."
        docker logs docker-openbao-1
        exit 1
    fi

    echo "OpenBao setup complete!"
    echo "Admin Token: $ADMIN_TOKEN"
    echo "Access OpenBao at: http://localhost:8200"
    echo "Root Token: (Stored securely in encrypted /vault/custom_config/init.txt)"
    echo "Note: Store the admin token securely and avoid using the root token for regular operations."
else
    echo "Error: OpenBao container failed to start or is not healthy after ${MAX_WAIT}s."
    docker logs docker-openbao-1
    exit 1
fi
