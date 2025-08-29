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
COMPOSE_FILE="docker-compose.yml"
INIT_FILE="init.txt.decrypted"
STACK_NAME="openbao"

# Check if running in Swarm mode
SWARM_MODE=$(docker info --format '{{.Swarm.LocalNodeState}}')
if [ "$SWARM_MODE" != "active" ]; then
    echo "Error: Docker Swarm mode is required for external secrets. Initializing Swarm..."
    docker swarm init
    if [ $? -ne 0 ]; then
        echo "Error: Failed to initialize Docker Swarm."
        exit 1
    fi
fi

# Create external secrets if not present
echo "Checking for external secrets..."
for secret in ansible_vault_password ansible_ssh_password ansible_ssh_private_key ansible_ssh_username; do
    if ! docker secret ls --format '{{.Name}}' | grep -q "^${secret}$"; then
        echo "Creating external secret ${secret}..."
        if [ "$secret" = "ansible_vault_password" ]; then
            NEW_PASSWORD=$(openssl rand -base64 32)
            echo "$NEW_PASSWORD" | docker secret create "${secret}" -
            # Re-encrypt existing init.txt if it exists
            if [ -f "${CONFIG_DIR}/init.txt" ]; then
                echo "Re-encrypting existing init.txt with new password..."
                docker run --rm -v "${CONFIG_DIR}:/vault/custom_config" -v "${BASE_DIR}/secrets:/run/secrets" ${DOCKER_IMAGE_NAME} sh -c "cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/custom_config/init.txt.decrypted --vault-password-file=/dev/stdin && echo '$NEW_PASSWORD' | ansible-vault encrypt /vault/custom_config/init.txt.decrypted --output=/vault/custom_config/init.txt --vault-password-file=/dev/stdin && rm /vault/custom_config/init.txt.decrypted" \
                    -e ANSIBLE_VAULT_PASSWORD=/run/secrets/ansible_vault_password
            fi
        else
            echo "Error: Secret ${secret} not found and no default value provided. Please create it manually."
            exit 1
        fi
    fi
done

# Create directories for persistent storage
echo "Creating directories for OpenBao..."
mkdir -p "$DATA_DIR" "$LOGS_DIR" "$CONFIG_DIR"

# Set proper permissions (no chown, assuming host user matches openbao UID/GID)
chmod -R u+rwX "$DATA_DIR" "$LOGS_DIR" "$CONFIG_DIR"

# Create docker-compose.yml
echo "Creating docker-compose.yml..."
cat > "$COMPOSE_FILE" << EOF
networks:
  net:
    attachable: true
    ipam:
      config:
      - subnet: 192.168.10.0/24
  socket_proxy:
    attachable: true
    ipam:
      config:
      - subnet: 192.168.11.0/24
  traefik_public:
    external: true
secrets:
  ansible_ssh_password:
    external: true
  ansible_ssh_private_key:
    external: true
  ansible_ssh_username:
    external: true
  ansible_vault_password:
    external: true
services:
  openbao:
    image: ${DOCKER_IMAGE_NAME}
    user: ${OPENBAO_UID}:${OPENBAO_GID}
    environment:
      - VAULT_ADDR=http://127.0.0.1:8200
      - OPENBAO_HOME_DIR=/vault
      - OPENBAO_CONFIG_DIR=/vault/custom_config
      - OPENBAO_INIT_FILE=/vault/custom_config/init.txt
      - ANSIBLE_VAULT_PASSWORD=dksec://ansible_vault_password
      - ENV_SECRETS_DEBUG=false
    secrets:
      - ansible_vault_password
    cap_add:
      - IPC_LOCK
      - DAC_OVERRIDE
    networks:
      - traefik_public
      - net
    ports:
      - target: 8200
        published: 8200
        protocol: tcp
        mode: host
    healthcheck:
      test: ["CMD-SHELL", "VAULT_ADDR=http://127.0.0.1:8200 vault status > /vault/logs/healthcheck_output 2>&1; grep -q 'Sealed.*false' /vault/logs/healthcheck_output"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 300s
    deploy:
      mode: replicated
      replicas: 1
      restart_policy:
        condition: on-failure
        max_attempts: 3
      update_config:
        delay: 10s
        order: stop-first
        parallelism: 1
      labels:
        - traefik.enable=true
        - traefik.http.routers.openbao.entrypoints=https
        - traefik.http.routers.openbao.rule=Host(\`openbao.admin.johnson.int\`)
        - traefik.http.routers.openbao.service=openbao-svc
        - traefik.http.services.openbao-svc.loadbalancer.server.port=8200
    volumes:
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
      - ${BASE_DIR}/passwd:/etc/passwd:ro
      - ${BASE_DIR}/group:/etc/group:ro
      - ${BASE_DIR}/home:/vault
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

# Deploy the stack
echo "Deploying OpenBao stack..."
docker stack deploy -c "$COMPOSE_FILE" ${STACK_NAME}

# Wait for OpenBao to be ready
echo "Waiting for OpenBao to be ready..."
MAX_WAIT=300
WAIT_INTERVAL=10
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    SERVICE_STATUS=$(docker service ls --filter name=${STACK_NAME}_openbao --format '{{.Replicas}}' 2>/dev/null)
    if [ -n "$SERVICE_STATUS" ] && [ "$SERVICE_STATUS" != "0/1" ]; then
        CONTAINER_ID=$(docker ps -q --filter "label=com.docker.stack.namespace=${STACK_NAME}" --filter "name=${STACK_NAME}_openbao")
        if [ -n "$CONTAINER_ID" ]; then
            HEALTH_STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER_ID" 2>/dev/null)
            echo "OpenBao service status: $SERVICE_STATUS, container health status: $HEALTH_STATUS"
            if [ "$HEALTH_STATUS" = "healthy" ]; then
                echo "OpenBao container is healthy and ready!"
                break
            fi
            # Check vault status
            STATUS_OUTPUT=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault status 2>&1)
            if echo "$STATUS_OUTPUT" | grep -q "Sealed.*false"; then
                echo "OpenBao server is responsive and unsealed!"
                break
            elif echo "$STATUS_OUTPUT" | grep -q "Sealed"; then
                echo "OpenBao server is responsive but sealed. Waiting for auto-unseal..."
            else
                echo "Vault status output: $STATUS_OUTPUT"
            fi
        else
            echo "OpenBao container not yet running. Waiting ${WAIT_INTERVAL}s..."
        fi
    else
        echo "OpenBao service not yet running. Waiting ${WAIT_INTERVAL}s..."
    fi
    sleep $WAIT_INTERVAL
    ELAPSED=$((ELAPSED + WAIT_INTERVAL))
done

# Check if service is running and healthy
CONTAINER_ID=$(docker ps -q --filter "label=com.docker.stack.namespace=${STACK_NAME}" --filter "name=${STACK_NAME}_openbao")
if [ -n "$CONTAINER_ID" ] && [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID" 2>/dev/null)" = "true" ] && \
   [ "$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER_ID" 2>/dev/null)" = "healthy" ]; then
    echo "OpenBao container is running and healthy."

    # Check if OpenBao is initialized
    STATUS=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault status 2>&1)
    if echo "$STATUS" | grep -q "Initialized.*true"; then
        echo "OpenBao is initialized."
        if echo "$STATUS" | grep -q "Sealed.*false"; then
            echo "OpenBao is unsealed."
        else
            echo "Error: OpenBao is sealed after startup. Check logs for auto-unseal issues."
            docker logs "$CONTAINER_ID"
            exit 1
        fi
    else
        echo "Error: OpenBao is not initialized. Check logs for initialization issues."
        docker logs "$CONTAINER_ID"
        exit 1
    fi

    # Retrieve and decrypt init.txt to extract root token
    echo "Retrieving root token from encrypted init.txt..."
    docker exec -e ANSIBLE_VAULT_PASSWORD=dksec://ansible_vault_password "$CONTAINER_ID" sh -c "cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/logs/init.txt.decrypted --vault-password-file=/dev/stdin"
    if [ $? -eq 0 ]; then
        ROOT_TOKEN=$(docker exec "$CONTAINER_ID" sh -c "grep 'Initial Root Token' /vault/logs/init.txt.decrypted | awk '{print \$NF}'")
        if [ -z "$ROOT_TOKEN" ]; then
            echo "Error: Failed to extract root token from init.txt."
            docker exec "$CONTAINER_ID" cat /vault/logs/init.txt.decrypted
            docker logs "$CONTAINER_ID"
            exit 1
        fi
        # Clean up decrypted file
        docker exec "$CONTAINER_ID" rm /vault/logs/init.txt.decrypted
    else
        echo "Error: Failed to decrypt init.txt."
        docker logs "$CONTAINER_ID"
        exit 1
    fi

    # Create admin token
    echo "Creating admin token..."
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault login "$ROOT_TOKEN" >/dev/null
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault policy write admin - <<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
    ADMIN_TOKEN=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault token create -policy=admin -format=json | grep '"token":' | awk -F'"' '{print $4}')
    if [ -z "$ADMIN_TOKEN" ]; then
        echo "Error: Failed to create admin token."
        docker logs "$CONTAINER_ID"
        exit 1
    fi

    # Test vault functionality
    echo "Testing vault functionality with admin token..."
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault login "$ADMIN_TOKEN" >/dev/null
    docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault kv put secret/test key=value >/dev/null
    TEST_OUTPUT=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$CONTAINER_ID" vault kv get -field=key secret/test)
    if [ "$TEST_OUTPUT" = "value" ]; then
        echo "Vault test successful: Secret written and read correctly."
    else
        echo "Error: Vault test failed. Expected 'value', got '$TEST_OUTPUT'."
        docker logs "$CONTAINER_ID"
        exit 1
    fi

    echo "OpenBao setup complete!"
    echo "Admin Token: $ADMIN_TOKEN"
    echo "Access OpenBao at: http://localhost:8200 or https://openbao.admin.johnson.int"
    echo "Root Token: (Stored securely in encrypted /vault/custom_config/init.txt)"
    echo "Note: Store the admin token securely and avoid using the root token for regular operations."
else
    echo "Error: OpenBao container failed to start or is not healthy after ${MAX_WAIT}s."
    docker logs "$CONTAINER_ID"
    exit 1
fi
