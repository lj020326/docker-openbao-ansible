#!/bin/bash

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

DOCKER_BUILD_DIR="${PROJECT_DIR}/image"
DOCKER_TEST_DIR="${PROJECT_DIR}/test"
BUILD_COMPOSE_FILE="${DOCKER_BUILD_DIR}/docker-compose.build.yml"
DOCKER_COMPOSE_TARGET_FILE="${SCRIPT_DIR}/docker-compose.test.yml"

# --- Global Flags ---
FAIL_FAST=0
SKIP_BUILD=0
KEEP_TMP_FILES=0
GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE=0
TARGET_TEST="" # NEW: Holds the function name or index (1-based) of the test to run

# --- Configuration ---
# Define tests as array for easy extension (name, command)
TESTS=(
    "Initial Container Startup and State Management" "test_initialization"
    "Setup Validation" "test_setup_validation"
    "Auto-Unseal and Container Resilience" "test_auto_unseal"
    "Data Integrity and Accessibility" "test_data_integrity"
    "External Service Connectivity" "test_external_connectivity"
    "Idempotent Initial Startup" "test_idempotent_initial_startup"
    "Idempotent Removal Restart" "test_idempotent_removal_restart"
    "Idempotent Modification Restart" "test_idempotent_modification_restart"
)

## Use the `OPENBAO_TEST_BUILD_ID` (e.g., '2025094321') in CICD pipelines for specific build
OPENBAO_TEST_SERVICE_NAME="openbao-test"
OPENBAO_TEST_BUILD_ID="test"
OPENBAO_TEST_RESULTS_DIR=".test-results"
#OPENBAO_TEST_IMAGE_TAG="${OPENBAO_TEST_BUILD_ID}"
#OPENBAO_TEST_IMAGE="${OPENBAO_TEST_IMAGE_NAME}:${OPENBAO_TEST_IMAGE_TAG}"
#OPENBAO_TEST_CONTAINER_NAME="${OPENBAO_TEST_IMAGE_NAME//[\/.]\//-}-${OPENBAO_TEST_BUILD_ID//[\/.]\//-}"
#OPENBAO_TEST_PROJECT_NAME="${OPENBAO_TEST_IMAGE_NAME//[\/.]\//-}-${OPENBAO_TEST_BUILD_ID//[\/.]\//-}"
#OPENBAO_TEST_DIR=".test/${OPENBAO_TEST_BUILD_ID}"
#OPENBAO_TEST_JSON_REPORT_FILE="${OPENBAO_TEST_RESULTS_DIR}/test-report.${OPENBAO_TEST_BUILD_ID}.json"
#OPENBAO_TEST_JUNIT_REPORT_FILE="${OPENBAO_TEST_RESULTS_DIR}/junit-report.${OPENBAO_TEST_BUILD_ID}.xml"

OPENBAO_USER="openbao"
OPENBAO_CONTAINER_HOME_DIR="/vault"
#OPENBAO_CONTAINER_HOME_DIR="/openbao"
OPENBAO_TEST_IMAGE_NAME="openbao-ansible"
TEST_RESULTS=()
ANSIBLE_VAULT_PASSWORD="securepassword123"
VAULT_ADDR="http://127.0.0.1:8200"

## derived vars
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# --- End Configuration ---

# --- Utility Functions ---

# Function to run docker compose commands with a consistent project and file configuration
function run_docker_compose() {
    docker compose --project-name "${OPENBAO_TEST_PROJECT_NAME}" -f "${DOCKER_COMPOSE_TARGET_FILE}" --env-file "${OPENBAO_TEST_TEST_ENV_FILE}" "$@"
}

function docker_compose_down() {
  if ! run_docker_compose down "${OPENBAO_TEST_SERVICE_NAME}"; then
      log_error "Failed to stop container with docker compose."
      exit 1
  fi
}

function docker_compose_up() {
  if ! run_docker_compose up -d "${OPENBAO_TEST_SERVICE_NAME}"; then
      log_error "Failed to start container with docker compose."
      exit 1
  fi
}

# Function to restart container
function docker_compose_restart() {
  if ! run_docker_compose restart "${OPENBAO_TEST_SERVICE_NAME}"; then
      log_error "Failed to restart container."
      exit 1
  fi
}

# Function to execute commands in docker container with a consistent project and file configuration
function exec_in_container() {
  run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" "$@"
}

function log_info() {
    echo "INFO: $1" >&2
}

function log_error() {
    echo "ERROR: $1" >&2
}

function log_step() {
    echo "--- $1 ---" >&2
}

function abort() {
  log_error "$@"
  exit 1
}

function shell_join() {
  local arg
  printf "%s" "$1"
  shift
  for arg in "$@"
  do
    printf " "
    printf "%s" "${arg// /\ }"
  done
}

function execute() {
  log_info "${*}"
  if ! "$@"
  then
    abort "$(printf "Failed during: %s" "$(shell_join "$@")")"
  fi
}

function execute_eval_command() {
  local RUN_COMMAND="${*}"

  log_info "${RUN_COMMAND}"
  COMMAND_RESULT=$(eval "${RUN_COMMAND}")
#  COMMAND_RESULT=$(eval "${RUN_COMMAND} > /dev/null 2>&1")
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    if [[ $COMMAND_RESULT != "" ]]; then
      log_info "${COMMAND_RESULT}"
    fi
  else
    log_error "RETURN_STATUS => (${RETURN_STATUS})"
#    echo "${COMMAND_RESULT}"
    abort "$(printf "Failed during: %s" "${COMMAND_RESULT}")"
  fi
}

# --- Test Utilities ---
function check_existing_mounts() {
    log_info "Checking for containers with pre-existing mounts to ${FULL_OPENBAO_TEST_HOME_DIR}..."
    local MOUNTED_CONTAINERS=""

    # Get a list of all running container IDs
    local RUNNING_CONTAINERS
    RUNNING_CONTAINERS=$(docker ps -q)

    # If there are running containers, inspect them for the mount
    if [ -n "$RUNNING_CONTAINERS" ]; then
        MOUNTED_CONTAINERS=$(docker inspect -f '{{.Name}} {{range .Mounts}}{{.Source}}{{end}}' $RUNNING_CONTAINERS | grep "${FULL_OPENBAO_TEST_HOME_DIR}" | awk '{print $1}')
    fi

    if [ -n "${MOUNTED_CONTAINERS}" ]; then
        log_error "ERROR: Found containers with existing mounts to the test directory ${FULL_OPENBAO_TEST_HOME_DIR}:"
        echo "${MOUNTED_CONTAINERS}" | while read -r line ; do
            log_error "  - ${line}"
        done
        return 1
    fi
    log_info "No conflicting mounts found."
    return 0
}

# Helper to reset the test directory and prepare for a clean run
function reset_test_dir() {
    log_info "Resetting test directory: ${OPENBAO_TEST_DIR}"
    rm -rf "${OPENBAO_TEST_DIR}"
    mkdir -p "${OPENBAO_TEST_DIR}/secrets"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/config"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/file"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/logs"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/plugins"
}

# Helper to build the Docker image
function build_image() {
    log_info "Building Docker image: ${OPENBAO_TEST_IMAGE}"
    ## the OPENBAO_TEST_IMAGE (includes the OPENBAO_TEST_IMAGE_TAG) in CICD pipelines can be specific to a build
    if ! env OPENBAO_BUILD_IMAGE="${OPENBAO_TEST_IMAGE}" docker compose --project-name "${OPENBAO_TEST_PROJECT_NAME}" -f "${BUILD_COMPOSE_FILE}" build; then
        log_error "Docker build failed."
        exit 1
    fi
    log_info "Docker image built successfully."
}

# Helper to generate necessary files for the test
function generate_test_files() {
    log_info "Generating docker-compose test file and environment files..."
    FULL_SCRIPT_DIR=$(full_path "${SCRIPT_DIR}")
    FULL_DOCKER_BUILD_DIR=$(full_path "${DOCKER_BUILD_DIR}")
    FULL_OPENBAO_TEST_HOME_DIR=$(full_path "${OPENBAO_TEST_HOME_DIR}")
    FULL_OPENBAO_TEST_DIR=$(full_path "${OPENBAO_TEST_DIR}")
    FULL_OPENBAO_TEST_PASSWD_FILE=$(full_path "${OPENBAO_TEST_PASSWD_FILE}")
    FULL_OPENBAO_TEST_GROUP_FILE=$(full_path "${OPENBAO_TEST_GROUP_FILE}")
    FULL_OPENBAO_TEST_ENV_FILE=$(full_path "${OPENBAO_TEST_ENV_FILE}")
    FULL_OPENBAO_TEST_TEST_ENV_FILE=$(full_path "${OPENBAO_TEST_TEST_ENV_FILE}")

    generate_openbao_test_passwd_file
    generate_openbao_test_group_file
    generate_openbao_test_env_file
    generate_openbao_test_test_env_file
    generate_openbao_config
}

function generate_openbao_test_passwd_file() {
    log_info "Generating passwd file..."
    echo "${OPENBAO_USER}:x:$(id -u):$(id -g):OpenBao User:/vault:/bin/sh" > "${OPENBAO_TEST_PASSWD_FILE}"
}

function generate_openbao_test_group_file() {
    log_info "Generating group file..."
    echo "${OPENBAO_USER}:x:$(id -g):" > "${OPENBAO_TEST_GROUP_FILE}"
}

function generate_openbao_test_env_file() {
    log_info "Generating OpenBao environment file..."
    local content="
OPENBAO_RUN_SETUP=true
OPENBAO_AUTO_UNSEAL=true
VAULT_ADDR=http://127.0.0.1:8200
ANSIBLE_VAULT_PASSWORD=dksec://ansible_vault_password
OPENBAO_TEST_HOME_DIR=${OPENBAO_CONTAINER_HOME_DIR}
ENTRYPOINT_LOG_LEVEL=DEBUG
"
    echo "$content" > "${OPENBAO_TEST_ENV_FILE}"
    log_info "Generated ${OPENBAO_TEST_ENV_FILE} with OPENBAO_RUN_SETUP set to true."
}

function generate_openbao_test_test_env_file() {
    log_info "Generating test environment file..."
    local content="
OPENBAO_TEST_IMAGE=${OPENBAO_TEST_IMAGE}
OPENBAO_TEST_CONTAINER_NAME=${OPENBAO_TEST_CONTAINER_NAME}
OPENBAO_TEST_PROJECT_NAME=${OPENBAO_TEST_PROJECT_NAME}
OPENBAO_TEST_DIR=${FULL_OPENBAO_TEST_DIR}
OPENBAO_CONTAINER_HOME_DIR=${OPENBAO_CONTAINER_HOME_DIR}
UID=${HOST_UID}
GID=${HOST_GID}
"
    echo "$content" > "${OPENBAO_TEST_TEST_ENV_FILE}"
    log_info "Generated ${OPENBAO_TEST_TEST_ENV_FILE}"
}

function generate_openbao_config() {
    log_info "Generating OpenBao config file..."
    cat <<EOF > "${OPENBAO_TEST_CONFIG_FILE}"
{
  "api_addr": "http://127.0.0.1:8200",
  "log_file": "${OPENBAO_CONTAINER_HOME_DIR}/logs/openbao.log",
  "storage": {
    "file": {
      "path": "${OPENBAO_CONTAINER_HOME_DIR}/file"
    }
  },
  "listener": {
    "tcp": {
      "address": "0.0.0.0:8200",
      "tls_disable": true
    }
  },
  "seal": {
    "shamir": {}
  },
  "default_lease_ttl": "87600h",
  "max_lease_ttl": "876000h",
  "ui": true
}
EOF

    chmod 644 "${OPENBAO_TEST_CONFIG_FILE}"
    log_info "Generated ${OPENBAO_TEST_CONFIG_FILE}"

    cp -p "${DOCKER_TEST_DIR}/openbao_config.yml" "${OPENBAO_TEST_SETUP_CONFIG_FILE}"
    log_info "Generated ${OPENBAO_TEST_SETUP_CONFIG_FILE}"
}

# --- Utility Functions ---
function wait_for_container_health() {
    log_info "Waiting for container to report health..."
    local HEALTH_STATUS=""
#    local MAX_ATTEMPTS=30
    local MAX_ATTEMPTS=10
    local ATTEMPT=0
    local SLEEP_TIME=5

    local CONTAINER_ID=$(run_docker_compose ps -q "${OPENBAO_TEST_SERVICE_NAME}")
    local CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "${CONTAINER_ID}")
    log_info "Container ID ${CONTAINER_ID} => CONTAINER_NAME=${CONTAINER_NAME}"

    # Wait for the container to become healthy, with a timeout
    while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
        local RUN_STATUS=$(docker inspect --format='{{.State.Status}}' "${CONTAINER_ID}")

        if [ "${RUN_STATUS}" != "running" ]; then
            log_error "Container ID status expected running but found [$RUN_STATUS]."
#            run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
            return 1
        fi
        # Use docker inspect to check the health status of the container
        HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_ID}")
        if [ -z "$HEALTH_STATUS" ]; then
            log_info "No healthcheck output available."
            sleep 1
            ATTEMPT=$((ATTEMPT + 1))
            continue
        fi

        log_info "Health check attempt $((ATTEMPT + 1)): RUN_STATUS = ${RUN_STATUS}, HEALTH_STATUS = ${HEALTH_STATUS}"
        if [ "$HEALTH_STATUS" == "healthy" ]; then
            log_info "Container is healthy."
            return 0
        fi
        # Log the healthcheck output for debugging
        log_info "Logging vault initialization status..."
        exec_in_container sh -c "bao status 2>&1 | tee -a ${OPENBAO_CONTAINER_HOME_DIR}/logs/healthcheck_output" || log_info "Vault status update failed."

        sleep "${SLEEP_TIME}"
        ATTEMPT=$((ATTEMPT + 1))
    done

    log_error "Container did not become healthy within $MAX_ATTEMPTS retries."
#    log_info "Container logs:"
#    run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
##    docker logs "${CONTAINER_ID}" || true
    return 1
}

function full_path() {
  local path="$1"
  if [ -f "$path" ] || [ ! -e "$path" ]; then
    realpath "$path" 2>/dev/null || echo "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
  elif [ -d "$path" ]; then
    (cd "$path" && pwd) 2>/dev/null || echo "$path"
  else
    log_error "Path '$path' is neither a file nor a directory."
    exit 1
  fi
}

function cleanup_containers() {
    log_info "Cleaning up containers..."
    if [ -n "${DOCKER_COMPOSE_TARGET_FILE}" ]; then
      if [ -f "${OPENBAO_TEST_TEST_ENV_FILE}" ]; then
        run_docker_compose down "${OPENBAO_TEST_SERVICE_NAME}" --remove-orphans --volumes
      fi
    fi
#    log_info "Free port 8200 if bound"
#    lsof -ti:8200 | xargs -r kill -9 2>/dev/null || true
}

# Enhanced cleanup function (force kill orphans, free port)
function cleanup_containers_new() {
    log_info "INFO: Cleaning up containers..."
    docker-compose down --remove-orphans --volumes --timeout 30 2>/dev/null || true
    docker kill $(docker ps -q --filter ancestor=openbao-ansible) 2>/dev/null || true
    docker rm $(docker ps -aq --filter ancestor=openbao-ansible) 2>/dev/null || true
    # Free port 8200 if bound
    lsof -ti:8200 | xargs -r kill -9 2>/dev/null || true
    log_info "INFO: Cleanup complete."
}

function cleanup_files() {
    log_info "Cleaning up temporary files..."
    rm -rf "${OPENBAO_TEST_DIR}"
}

function cleanup() {
    cleanup_containers
    cleanup_files
    log_info "Cleanup complete."
}

function full_path() {
  local path="$1"
  if [ -f "$path" ] || [ ! -e "$path" ]; then
    realpath "$path" 2>/dev/null || echo "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
  elif [ -d "$path" ]; then
    (cd "$path" && pwd) 2>/dev/null || echo "$path"
  else
    log_error "Path '$path' is neither a file nor a directory."
    exit 1
  fi
}

function print_test_cases() {
    local i=0
    while [ "$i" -lt "${#TESTS[@]}" ]; do
        local test_index=$((i / 2 + 1))
        local test_name="${TESTS[i]}"
        local test_func="${TESTS[i+1]}"
        echo "${test_index} | ${test_func} - ${test_name}"
        i=$((i + 2))
    done
}

# Function to report result
function add_test_result() {
    local test_index="$1"
    local test_name="$2"
    local failed="$3"
    local message="$4"
    local escaped_message=$(echo "${message}" | sed 's/\"/\\\"/g')
    TEST_RESULTS+=("{\"test_index\": \"${test_index}\", \"test_name\": \"${test_name}\", \"failed\": ${failed}, \"message\": \"${escaped_message}\"}")
}

# --- End Utility Functions ---

# --- Test Suite Functions ---

# Test Initial Container Startup and State Management
function test_initialization() {
    log_info "--- Running Test: Container Initialization Validation ---"

    # Check that the init.json.enc file was created
    log_info "Verifying that init.json.enc exists on the host..."
    if [ ! -f "${OPENBAO_TEST_HOME_DIR}/config/init.json.enc" ]; then
        log_error "Encrypted init file not found."
        return 1
    fi
    log_info "Encrypted init file found."

    echo "*********"
    log_info "Content of encrypted init file:"
    exec_in_container openbao_info --content
    echo "\n"
    echo "*********"

    # Check vault initialization status
    log_info "Checking vault initialization status..."
    exec_in_container bao status || log_info "Vault status check failed."

    log_info "Validating openbao_info content output..."
    local DECRYPTED_CONTENT=$(exec_in_container openbao_info --content)
    if ! echo "${DECRYPTED_CONTENT}" | grep -q 'root_token'; then
        log_error "Decrypted content does not contain 'root_token'."
        return 1
    fi

    return 0
}

# Test Setup Validation
function test_setup_validation() {
    log_info "--- Running Test: Setup Validation ---"

    log_info "Verifying admin token is present in the encrypted init file..."
    ADMIN_TOKEN=$(exec_in_container openbao_info --admin-token)
    if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
        log_error "Admin token not found or is empty."
        return 1
    fi
    log_info "Admin token successfully retrieved. ADMIN_TOKEN => [${ADMIN_TOKEN}]."

    log_info "Use admin token for secret write/read"
    log_info "secret write"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao kv put secret/test value=test_data
    log_info "secret read"
    local read_back=$(run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao kv get -format=json secret/test | jq -r '.data.data.value')
    log_info "read_back=${read_back}"
    if [ "${read_back}" != "test_data" ]; then
        log_error "Secret write/read failed."
        return 1
    fi
    log_info "Admin token and secret ops verified."

    log_info "policy list"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy list -format=json
    log_info "Policy check with admin"
#    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy list | grep admin > /dev/null; then
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy list -format=json | jq -e '.[] | select(. == "admin")' > /dev/null; then
        log_error "Admin policy not found."
        return 1
    fi
    log_info "Admin policy found."

    log_info "Check if the 'admin' policy is read"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy read admin > /dev/null; then
        log_error "Admin policy read failed."
        return 1
    fi
    log_info "Admin policy read successful."

    log_info "Check if the 'user' policy was created"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy read user > /dev/null; then
        log_error "User policy not found."
        return 1
    fi
    log_info "User policy found."

    log_info "auth list"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao auth list -format=json
    log_info "Check if the 'userpass' auth method was enabled"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao auth list -format=json | jq -e 'has("userpass/")' > /dev/null; then
        log_error "Userpass auth method not enabled."
        return 1
    fi
    log_info "Userpass auth method is enabled."

    log_info "secrets list"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao secrets list -format=json
    log_info "Check if the 'kv' secrets engine was enabled"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao secrets list -format=json | jq -e '."secret/".type == "kv"' > /dev/null; then
        log_error "KV secrets engine not enabled."
        return 1
    fi
    log_info "KV secrets engine is enabled."

    return 0
}

# Test Auto-Unseal and Container Resilience
function test_auto_unseal() {
    log_info "--- Running Test: Container Auto-unseal Validation ---"

    if ! run_docker_compose restart "${OPENBAO_TEST_SERVICE_NAME}"; then
        log_error "Failed to restart container."
        return 1
    fi
    log_info "Container restarted."

    log_info "Waiting for container health check to pass agan..."
    wait_for_container_health || return 1

    # Check that the vault is unsealed
    if exec_in_container bao status -format=json | jq -e '.sealed' | grep -q 'true'; then
        log_error "OpenBao remained sealed after restart."
        return 1
    fi
    log_info "OpenBao successfully auto-unsealed after restart."

    return 0
}

# Test Data Integrity and Accessibility
function test_data_integrity() {
    log_info "--- Running Test: Data Integrity and Accessibility ---"
    local ADMIN_TOKEN=$(exec_in_container openbao_info --admin-token)
    if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
        log_error "Admin token could not be fetched."
        return 1
    fi
    log_info "Admin token successfully fetched."

    log_info "Use admin for integrity check"
    log_info "secret write"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao kv put secret/integrity key=integrity_value
    log_info "secret get"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao kv get -format=json secret/integrity
    log_info "secret read"
    local integrity_read=$(run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ADMIN_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao kv get -format=json secret/integrity | jq -r '.data.data.key')

#    exec_in_container "VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${ADMIN_TOKEN} bao kv put secret/integrity key=integrity_value"
#    local integrity_read=$(exec_in_container "VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${ADMIN_TOKEN} bao kv get secret/integrity | grep key | cut -d' ' -f2")
    if [ "$integrity_read" != "integrity_value" ]; then
        log_error "Data integrity check failed."
        return 1
    fi
    log_info "Secret value verified."

    return 0
}

# Test External Service Connectivity
function test_external_connectivity() {
    log_info "--- Running Test: Container External Connectivity Validation ---"

    #########################
    ## Note:
    ##
    ## The docker-compose.test.yml uses Dynamic Port Mapping.
    ## Instead of hard-coding the host port, it lets Docker chooses an available random port and the test script must retrieve it for use.
    ##
    ## The Dynamic Port Mapping above allows a single host to run parallel CICD test jobs (Jenkins, etc) using Docker containers
    ## and avoid port binding issues.
    ##
    local BAO_CONTAINER_PORT="8200"

    log_info "Retrieving container ID and host port mapping..."
    local CONTAINER_ID=$(run_docker_compose ps -q "${OPENBAO_TEST_SERVICE_NAME}")

    ## Using the host loopback address since container binds to the 0.0.0.0 host IP
    local BAO_HOST_ADDRESS="127.0.0.1"

    ## Determine the host port to use based on the environment
    local BAO_HOST_PORT=$(docker inspect --format='{{(index (index .NetworkSettings.Ports "'${BAO_CONTAINER_PORT}'/tcp") 0).HostPort}}' "${CONTAINER_ID}")

    log_info "Container ID: ${CONTAINER_ID}, Host Address: ${BAO_HOST_ADDRESS}, Host Port: ${BAO_HOST_PORT}"

    # Test unauthenticated endpoint
    log_info "Testing unauthenticated health endpoint..."
    if ! curl --silent --fail -o /dev/null "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/health"; then
        log_error "Unauthenticated health check failed."
        log_error "health check curl result:"
        curl -v --silent "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/health"
        log_error "docker container status:"
        run_docker_compose ps "${OPENBAO_TEST_SERVICE_NAME}"
        log_info "Test container network info:"
        docker inspect --format='{{json .NetworkSettings}}' "${CONTAINER_ID}"
        return 1
    fi
    log_info "Unauthenticated health check passed."

    # Test authenticated endpoint using the root token
    log_info "Testing authenticated endpoint with root token..."
    local ROOT_TOKEN=$(exec_in_container openbao_info --root-token)
    if [ -z "${ROOT_TOKEN}" ]; then
        log_error "Failed to retrieve root token via openbao_info."
        return 1
    fi

    local HTTP_STATUS=$(curl -s -H "X-Vault-Token: ${ROOT_TOKEN}" -o /dev/null -w "%{http_code}" "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/mounts")
    if [ "$HTTP_STATUS" -ne 200 ]; then
        log_error "Authenticated mounts check failed with status code $HTTP_STATUS."
        return 1
    fi
    log_info "Authenticated mounts check with root token passed."

    # Test authenticated endpoint using the new admin token
    ADMIN_TOKEN=$(exec_in_container openbao_info --admin-token)
    if [ -z "$ADMIN_TOKEN" ]; then
        log_error "Admin token not available for auth check."
        return 1
    fi

#    log_info "Testing authenticated endpoint with admin token..."
#    if ! curl --silent --fail --header "X-Vault-Token: ${ADMIN_TOKEN}" "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/mounts" > /dev/null; then
#        log_error "Authenticated mounts check with admin token failed."
#        return 1
#    fi
#    log_info "Authenticated mounts check with admin token passed."

    log_info "Auth check with admin"
    local mounts_check=$(curl -s -H "X-Vault-Token: ${ADMIN_TOKEN}" "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/mounts" | jq '.data')
    if [ -z "$mounts_check" ] || [ "$mounts_check" = "null" ]; then
        log_error "Authenticated mounts check with admin token failed."
        return 1
    fi
    log_info "Authenticated mounts check with admin token passed."

    return 0
}

function test_idempotent_initial_startup() {
    log_info "--- Running Test: Idempotent Initial Startup ---"

    local ROOT_TOKEN=$(exec_in_container openbao_info --root-token)

    log_info "Stop container"
    docker_compose_down

    log_info "Remove content"
    execute_eval_command "rm -fr ${OPENBAO_TEST_HOME_DIR}/file/*"
    execute_eval_command "rm -f ${OPENBAO_TEST_HOME_DIR}/.setup_completed"

    log_info "Start container"
    docker_compose_up
    wait_for_container_health

    log_info "Verify setup completed"
    local setup_file_check=$(exec_in_container "ls /vault/.setup_completed")
    if [ -z "$setup_file_check" ]; then
        log_error "Setup not completed (.setup_completed missing)."
        return 1
    fi

    if [ ! -f "${OPENBAO_TEST_HOME_DIR}/.setup_completed" ]; then
        log_error "Setup not completed (.setup_completed missing)."
        return 1
    fi
    local NEW_ROOT_TOKEN=$(exec_in_container openbao_info --root-token)
    if [ -z "$NEW_ROOT_TOKEN" ] || [ "$NEW_ROOT_TOKEN" = "null" ]; then
        log_error "Root token not available."
        return 1
    fi

    log_info "Verify a new root token has been created"
    if [ "$NEW_ROOT_TOKEN" == "$ROOT_TOKEN" ]; then
        log_error "A NEW root token has not been created."
        return 1
    fi

    log_info "Verify policy (exact match)"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${NEW_ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy list -format=json | jq -e '.[] | select(. == "admin")' > /dev/null; then
        log_error "Admin policy not found."
        return 1
    fi
    log_info "Verify userpass (exact key)"
    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${NEW_ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao auth list -format=json | jq -e 'has("userpass/")' > /dev/null; then
        log_error "Userpass auth not enabled."
        return 1
    fi
    log_info "Verify tokens length"
    local content=$(exec_in_container openbao_info --content)
    local token_length=$(echo "$content" | jq '.tokens | length')
    local expected_number_of_tokens=3
    if [ "$token_length" -ne "${expected_number_of_tokens}" ]; then
        log_error "Token roles not configured (expected ${expected_number_of_tokens})."
        return 1
    fi
    log_info "Test passed: Initial idempotent setup."
}

function test_idempotent_removal_restart() {
    log_info "--- Running Test: Idempotent Removal and Restart ---"

    local ROOT_TOKEN=$(exec_in_container openbao_info --root-token)
    if [ -z "${ROOT_TOKEN}" ]; then
        log_error "Failed to retrieve root token via openbao_info."
        return 1
    fi

    log_info "Remove policy/user/token via API"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy delete admin
    log_info "Restart container"
    docker_compose_restart
    wait_for_container_health
    log_info "Verify recreated (check .setup_completed and resources)"
    local new_setup_check=$(exec_in_container "ls /vault/.setup_completed")
    if [ -z "$new_setup_check" ]; then
        log_error "Setup not recreated after restart."
        return 1
    fi

    local NEW_ROOT=$(exec_in_container openbao_info --root-token)
    if [ -z "${NEW_ROOT}" ]; then
        log_error "Failed to retrieve root token via openbao_info after policy delete and restart."
        return 1
    fi

    if ! run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy list -format=json | jq -e '.[] | select(. == "admin")' > /dev/null; then
        log_error "Admin policy not recreated."
        return 1
    fi
    log_info "Test passed: Resources recreated on restart."
}

function test_idempotent_modification_restart() {
    log_info "--- Running Test: Idempotent Modification and Restart ---"
    local ROOT_TOKEN=$(exec_in_container openbao_info --root-token)
    if [ -z "${ROOT_TOKEN}" ]; then
        log_error "Failed to retrieve root token via openbao_info."
        return 1
    fi

    log_info "Modify admin policy (remove sudo)"
    if ! run_docker_compose exec -T -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" \
        sh -c "echo 'path \"*\" { capabilities = [\"read\", \"list\"] }' | bao policy write admin -" ; then
        log_error "Failed to modify admin policy via single-line echo pipe."
        return 1
    fi
    log_info "Admin policy modified successfully."

    log_info "Restart container"
    docker_compose_restart
    wait_for_container_health
    log_info "Display admin policy"
    run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy read admin
    log_info "Read admin policy"
    local policy_resp=$(run_docker_compose exec -e VAULT_ADDR="${VAULT_ADDR}" -e VAULT_TOKEN="${ROOT_TOKEN}" "${OPENBAO_TEST_SERVICE_NAME}" bao policy read admin)
    if ! echo "$policy_resp" | grep -q "sudo"; then
        log_error "Policy not enforced to original YAML (sudo missing)."
        return 1
    fi
    log_info "Test passed: Resources enforced on modification."
}

# --- End Test Suite Functions ---

# --- Core Functions ---

function run_test() {
    local test_index="$1"
    local test_name="$2"
    local test_command="$3"
    log_step "Running Test: $test_index: $test_name"
    log_info "Executing command: $test_command"

    local message=""
    local failed="true"
    local start_time=$(date +%s)

    cleanup_containers
    docker_compose_up
    wait_for_container_health || {
        message="healthcheck before running test '$test_name' failed. Check logs for details."
        add_test_result "${test_index}" "${test_name}" "${failed}" "${message}"
        return 1
    }
    if eval "$test_command"; then
        failed="false"
        message="Test '$test_index' passed successfully."
    else
        message="Test '$test_index' failed. Check logs for details."
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_info "Test '$test_index' finished in ${duration} seconds. Failed: ${failed}"

    # Store results for final report
    add_test_result "${test_index}" "${test_name}" "${failed}" "${message}"
    if [ "${failed}" == "true" ]; then
        return 1
    fi
    return 0
}

# Updated run_tests: Sequential per-test up/down for isolation
function run_all_tests() {
    log_info "Starting OpenBao container regression tests..."

    local i=0
    local overall_failed=0
    local total_tests=$((${#TESTS[@]} / 2))

    while [ "$i" -lt "${#TESTS[@]}" ]; do
        local test_name="${TESTS[i]}"
        local test_function="${TESTS[i+1]}"
        local test_index=$((i / 2 + 1))
        local test_start_time=$(date +%s)
        local test_failed=false
        local test_message="Passed"

        # --- Test ID Filtering Logic (NEW) ---
        if [[ -n "$TARGET_TEST" ]]; then
            # Check if TARGET_TEST matches index or function name
            if [[ "$TARGET_TEST" != "$test_index" ]] && [[ "$TARGET_TEST" != "$test_function" ]]; then
                log_info "Skipping test ${test_index}: ${test_name} (Targeted test: ${TARGET_TEST})"
                i=$((i + 2))
                continue
            fi
        fi
        # --- End Test ID Filtering Logic ---

        log_info "--- Running Test ${test_index}/${total_tests}: ${test_name} ---"

        run_test "${test_index}" "${test_name}" "${test_function}"
        local test_rc=$?
        overall_failed=$((${overall_failed} + ${test_rc}))

        if [ $FAIL_FAST -eq 1 ] && [ $test_rc -ne 0 ]; then
            log_error "Fail-fast triggered: Stopping after ${test_name} failure."
            break  # Stop loop on first failure
        fi
        # For FAIL_FAST=0, continue (run_test already ||-ed internally if needed)

        i=$((i + 2))
    done

    return $overall_failed
}

function usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --fail-fast           Stop at the first failed test."
    echo "  -s, --skip-build          Skip the Docker image build phase."
    echo "  -k, --keep-tmp-files      Do not delete test containers and volumes after execution."
    echo "  -j, --junit               Generate JUnit XML report."
    echo "  -l                        Show/list test cases"
    echo "  -t, --test-id <ID>        Run a single test by its 1-based index or function name."
    echo "                            Example: -t 2 or -t test_setup_validation"
    echo "  -h, --help                Show this help message."

    echo "  -b, --build-id            Build ID (default 'test')."
    echo "  -i, --image-id            Docker image id (including namespace and tag)."
    echo "  -i, --image-name          Docker image name."
    echo "  -r, --test-results-dir    Test results directory (default 'test-results')."
    echo "  -d, --test-dir            Test run directory (default '.tests')."
    echo "  -x                        Run in shell debug mode"
    echo ""
    echo "Available Tests (Index | Function Name):"
    local i=0
    while [ "$i" -lt "${#TESTS[@]}" ]; do
        local test_index=$((i / 2 + 1))
        local test_name="${TESTS[i]}"
        local test_func="${TESTS[i+1]}"
        echo "  ${test_index} | ${test_func} - ${test_name}"
        i=$((i + 2))
    done
    echo ""
    echo "  Examples:"
    echo "       ${SCRIPT_NAME}"
    echo "       ${SCRIPT_NAME} -l"
    echo "       ${SCRIPT_NAME} -t test_idempotent_removal_restart"
    echo "       ## Keep the test runtime directory and container for post-test debug:"
    echo "       ${SCRIPT_NAME} -f -k -t test_data_integrity"
    echo "       ${SCRIPT_NAME} -f -k -t 3"
    echo "       ${SCRIPT_NAME} -x --junit --skip-build --test-results-dir '.test-results' --build-id build-5317"
    echo "       ${SCRIPT_NAME} -h"
}

# --- Argument Parsing ---
function parse_args() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -f|--fail-fast)
                FAIL_FAST=1
                shift
                ;;
            -s|--skip-build)
                SKIP_BUILD=1
                shift
                ;;
            -k|--keep-tmp)
                KEEP_TMP_FILES=1
                shift
                ;;
            -j|--junit)
                GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE=1
                shift
                ;;
            -t|--test-id)
                if [[ -z "$2" ]]; then
                    log_error "Error: --test-id requires a value (index or function name)."
                    usage
                    exit 1
                fi
                TARGET_TEST="$2"
                shift 2
                ;;
            -b|--build-id)
                OPENBAO_TEST_BUILD_ID="$2"
                shift 2
                ;;
            -i|--image)
                OPENBAO_TEST_IMAGE="$2"
                shift 2
                ;;
            -n|--image-name)
                OPENBAO_TEST_IMAGE_NAME="$2"
                shift 2
                ;;
            -r|--test-results-dir)
                OPENBAO_TEST_RESULTS_DIR="$2"
                shift 2
                ;;
            -d|--test-dir)
                OPENBAO_TEST_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -l) print_test_cases && exit ;;
            -x)
                set -x
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main function
function main() {
    log_info "--- Starting OpenBao Test Suite ---"
    log_info "Command line arguments: $*"

    # --- UID/GID Detection ---
    log_info "Detected host UID: ${HOST_UID}, GID: ${HOST_GID}"
    if [ "$HOST_UID" -eq 0 ]; then
        log_info "WARNING: Running as root - best practice to test container as non-root user with only run container permissions."
    fi

    parse_args "$@"

    #######################################
    ## set build specific variables
    ##
    ## prevents conflicts for parallel CICD jobs especially with respect to test container resources
    ## E.g., networks, storage mounts, results, etc
    ##
    #######################################
    OPENBAO_TEST_IMAGE_TAG="${OPENBAO_TEST_BUILD_ID}"
    OPENBAO_TEST_IMAGE="${OPENBAO_TEST_IMAGE_NAME}:${OPENBAO_TEST_IMAGE_TAG}"

    OPENBAO_TEST_CONTAINER_NAME="${OPENBAO_TEST_IMAGE_NAME//[\/.]/-}-${OPENBAO_TEST_BUILD_ID//[\/.]/-}"
    OPENBAO_TEST_PROJECT_NAME="${OPENBAO_TEST_IMAGE_NAME//[\/.]/-}-${OPENBAO_TEST_BUILD_ID//[\/.]/-}"
    OPENBAO_TEST_DIR=".test/${OPENBAO_TEST_BUILD_ID}"

    OPENBAO_TEST_JSON_REPORT_FILE="${OPENBAO_TEST_RESULTS_DIR}/test-report.${OPENBAO_TEST_BUILD_ID}.json"
    OPENBAO_TEST_JUNIT_REPORT_FILE="${OPENBAO_TEST_RESULTS_DIR}/junit-report.${OPENBAO_TEST_BUILD_ID}.xml"

    OPENBAO_TEST_HOME_DIR="${OPENBAO_TEST_DIR}/home"
    OPENBAO_TEST_PASSWD_FILE="${OPENBAO_TEST_DIR}/passwd"
    OPENBAO_TEST_GROUP_FILE="${OPENBAO_TEST_DIR}/group"
    OPENBAO_TEST_ENV_FILE="${OPENBAO_TEST_DIR}/openbao.env"
    OPENBAO_TEST_TEST_ENV_FILE="${OPENBAO_TEST_DIR}/.env.test"
    OPENBAO_TEST_CONFIG_FILE="${OPENBAO_TEST_HOME_DIR}/config/local.json"
    OPENBAO_TEST_SETUP_CONFIG_FILE="${OPENBAO_TEST_HOME_DIR}/config/openbao_config.yml"

    # --- Check for Required Files ---
    if [ ! -f "${DOCKER_BUILD_DIR}/Dockerfile" ]; then
        log_error "Dockerfile not found at: ${DOCKER_BUILD_DIR}/Dockerfile"
        exit 1
    fi

    # --- Reset Test Directory ---
    cleanup
    reset_test_dir

    # --- Check for Pre-existing Mounts ---
    local FULL_OPENBAO_TEST_HOME_DIR=$(full_path "${OPENBAO_TEST_HOME_DIR}")
    if ! check_existing_mounts; then
        log_error "Exiting due to conflicting mounts."
        exit 1
    fi

    if [ "${SKIP_BUILD}" -eq 0 ]; then
      build_image
    else
      log_info "Skipping build for image ${OPENBAO_TEST_IMAGE}"
      log_info "Checking if image ${OPENBAO_TEST_IMAGE} is present"
      if [ "$(docker images -q "${OPENBAO_TEST_IMAGE}")" ]; then
        log_info "${OPENBAO_TEST_IMAGE} Image is present."
      else
        log_error "${OPENBAO_TEST_IMAGE} Image is not present."
      fi
    fi

    # --- Generate Test Files ---
    generate_test_files

    # --- Run Test Suite ---
    log_info "Starting validation test suite."
    local overall_status="success"

    # --- Run Test Suite ---
    log_info "Starting validation test suite."
    local overall_status="success"

    # Disable set -e temporarily so that a failed run_tests doesn't exit the script
    set +e
    run_all_tests
    local RUN_TESTS_RC=$?
    set -e # Re-enable set -e

    # --- Generate JSON Report ---
    log_info "--- Test Report ---"
    log_info "Writing report to ${OPENBAO_TEST_JSON_REPORT_FILE}"
    mkdir -p "${OPENBAO_TEST_RESULTS_DIR}"
    echo "[$(IFS=,; echo "${TEST_RESULTS[*]}") ]" | jq '.' > "${OPENBAO_TEST_JSON_REPORT_FILE}"

    # --- Determine Overall Status ---
    local failed_tests=$(jq '[.[] | select(.failed == true)] | length' "${OPENBAO_TEST_JSON_REPORT_FILE}")
    if [ "$failed_tests" -gt 0 ]; then
        log_error "Some tests failed. Check the report for details."
        overall_status="failed"
        log_info "Post Failed Test checks:"
        log_error "Docker logs for service ${OPENBAO_TEST_SERVICE_NAME}:"
        run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
        log_info "run_docker_compose ps"
        run_docker_compose ps
        execute_eval_command "ls -Fla ${OPENBAO_TEST_DIR}/"
        execute_eval_command "ls -Fla ${OPENBAO_TEST_HOME_DIR}/"
        execute_eval_command "ls -Fla ${OPENBAO_TEST_HOME_DIR}/config/"
        log_info "run_docker_compose exec -T openbao-test openbao_info --content"
        run_docker_compose exec -T openbao-test openbao_info --content
    else
        log_info "All tests passed successfully."
        overall_status="passed"
    fi

    if [ "${GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE}" -eq 1 ]; then
        eval "${SCRIPT_DIR}/json2junit.py ${OPENBAO_TEST_JSON_REPORT_FILE} ${OPENBAO_TEST_JUNIT_REPORT_FILE}"
    fi

    # --- Clean up after all tests are done ---
    # Don't exit on error here, just log it.
    if [ "${KEEP_TMP_FILES}" -eq 0 ]; then
        cleanup || log_error "Cleanup failed."
    fi

    log_info "Final status: ${overall_status}"
    jq < "${OPENBAO_TEST_JSON_REPORT_FILE}"

    exit "$failed_tests"
}

# Call main function
main "$@"
