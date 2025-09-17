#!/bin/bash

set -eo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOCKER_BUILD_DIR="$(dirname "$SCRIPT_DIR")/image"
BUILD_COMPOSE_FILE="${DOCKER_BUILD_DIR}/docker-compose.build.yml"
DOCKER_COMPOSE_TARGET_FILE="${SCRIPT_DIR}/docker-compose.test.yml"

SKIP_BUILD=0
GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE=0
KEEP_TMP_FILES=0

# --- Configuration ---

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

## derived vars
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# --- End Configuration ---


# --- Utility Functions ---

# Function to run docker compose commands with a consistent project and file configuration
run_docker_compose() {
    docker compose --project-name "${OPENBAO_TEST_PROJECT_NAME}" -f "${DOCKER_COMPOSE_TARGET_FILE}" --env-file "${OPENBAO_TEST_TEST_ENV_FILE}" "$@"
}

log_info() {
    echo "INFO: $1" >&2
}

log_error() {
    echo "ERROR: $1" >&2
}

log_step() {
    echo "--- $1 ---" >&2
}

# --- Test Utilities ---
run_test() {
    local test_name="$1"
    local test_command="$2"
    log_step "Running Test: $test_name"
    log_info "Executing command: $test_command"

    local message=""
    local failed="true"
    local start_time=$(date +%s)

    if eval "$test_command"; then
        failed="false"
        message="Test passed successfully."
    else
        message="Test '$test_name' failed. Check logs for details."
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_info "Test finished in ${duration} seconds. Status: ${status}"

    # Store results for final report
#    TEST_RESULTS+=("{\"test_name\":\"${test_name}\",\"failed\":\"${failed}\",\"message\":\"${message}\"}")
    report_result "${test_name}" "${failed}" "${message}"
}

# --- Test Suite Functions ---

# Test Initial Container Startup and State Management
test_initialization() {
    log_info "Verifying container startup and health..."

    log_info "Bringing up the stack for the first time."

    if ! run_docker_compose up -d "${OPENBAO_TEST_SERVICE_NAME}"; then
        log_error "Failed to start container with docker compose."
        return 1
    fi

    log_info "Waiting for container health check to pass (unsealed state)..."
    wait_for_container_health || return 1

    # Check that the init.json.enc file was created
    log_info "Verifying that init.json.enc exists on the host..."
    if [ ! -f "${OPENBAO_TEST_HOME_DIR}/config/init.json.enc" ]; then
        log_error "Encrypted init file not found."
        return 1
    fi
    log_info "Encrypted init file found."

    # Check vault initialization status
    log_info "Checking vault initialization status..."
    run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao status || log_info "Vault status check failed."

    log_info "Validating openbao_info content output..."
    local DECRYPTED_CONTENT=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" sh -c "openbao_info --content")
    if ! echo "${DECRYPTED_CONTENT}" | grep -q 'root_token'; then
        log_error "Decrypted content does not contain 'root_token'."
        return 1
    fi

    return 0
}

# Test Setup Validation
test_setup_validation() {
    log_info "Verifying OpenBao policies and secrets..."
    local TEST_PASSED=0

    # Test for the presence of the admin token
    log_info "Verifying admin token is present in the encrypted init file..."
    ADMIN_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" openbao_info --admin-token)
    if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
        log_error "Admin token not found or is empty."
        return 1
    fi
    log_info "Admin token successfully retrieved."

    ## First bao login before performing bao query tests
    local ROOT_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" sh -c "openbao_info --root-token")
    log_info "ROOT_TOKEN: ${ROOT_TOKEN}"
    run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao login "${ROOT_TOKEN}"

    # Check if the 'admin' policy was created
    if ! run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao policy read admin > /dev/null; then
        log_error "Admin policy not found."
        return 1
    fi
    log_info "Admin policy found."

    # Check if the 'user' policy was created
    if ! run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao policy read user > /dev/null; then
        log_error "User policy not found."
        return 1
    fi
    log_info "User policy found."

    # Check if the 'userpass' auth method was enabled
    if ! run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao auth list -format=json | jq -e '."userpass/"' > /dev/null; then
        log_error "Userpass auth method not enabled."
        return 1
    fi
    log_info "Userpass auth method is enabled."

    # Check if the 'kv' secrets engine was enabled
    if ! run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao secrets list -format=json | jq -e '."kv/"' > /dev/null; then
        log_error "KV secrets engine not enabled."
        return 1
    fi
    log_info "KV secrets engine is enabled."

    return 0
}

# Test Auto-Unseal and Container Resilience
test_auto_unseal() {
    log_info "Testing auto-unseal by restarting the container..."

    if ! run_docker_compose restart "${OPENBAO_TEST_SERVICE_NAME}"; then
        log_error "Failed to restart container."
        return 1
    fi
    log_info "Container restarted."

    log_info "Waiting for container health check to pass again..."
    wait_for_container_health || return 1

    # Check that the vault is unsealed
    if run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao status -format=json | jq -e '.sealed' | grep -q 'true'; then
        log_error "OpenBao remained sealed after restart."
        return 1
    fi
    log_info "OpenBao successfully auto-unsealed after restart."

    return 0
}

# Test Data Integrity and Accessibility
test_data_integrity() {
    log_info "Verifying data integrity and accessibility of keys..."

    # Check if the root token is accessible via the utility script
    log_info "Checking if root token can be fetched from init.json.enc..."
    local ROOT_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" sh -c "openbao_info --root-token")
    if [ -z "${ROOT_TOKEN}" ]; then
        log_error "Failed to retrieve root token via openbao_info."
        return 1
    fi
    log_info "Root token successfully fetched."

    # Check if the admin token is accessible via the utility script
    log_info "Checking if admin token can be fetched from init.json.enc..."
    local ADMIN_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" sh -c "openbao_info --admin-token")
    if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
        log_error "Admin token could not be fetched."
        return 1
    fi
    log_info "Admin token successfully fetched."

    ## First bao login before performing bao kv put/get tests
    run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao login "${ROOT_TOKEN}"

    # Write a test secret and read it back
    log_info "Writing a test secret to KV engine..."
    local MAX_RETRIES=5
    local RETRY_COUNT=0
    local SUCCESS=false
    while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
        run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao kv put kv/test-secret mykey=myvalue > /dev/null
        if [ "$?" -eq 0 ]; then
            log_info "Test secret written."
            SUCCESS=true
            break
        fi
        log_info "Read attempt $((RETRY_COUNT + 1)) failed, retrying in 2 seconds..."
        sleep 2
        RETRY_COUNT=$((RETRY_COUNT + 1))
    done

    log_info "Reading the test secret back with retries..."
    local READ_VALUE=""
    RETRY_COUNT=0
    SUCCESS=false
    while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
        READ_VALUE=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" bao kv get -field=mykey kv/test-secret 2>/dev/null || true)
        if [ "$?" -eq 0 ] && [ "${READ_VALUE}" == "myvalue" ]; then
            SUCCESS=true
            break
        fi
        log_info "Read attempt $((RETRY_COUNT + 1)) failed, retrying in 2 seconds..."
        sleep 2
        RETRY_COUNT=$((RETRY_COUNT + 1))
    done

    if [ "$SUCCESS" == "false" ]; then
        log_error "Failed to read correct value from secret after ${MAX_RETRIES} attempts. Expected 'myvalue', got '${READ_VALUE}'."
        return 1
    fi

    log_info "Secret value verified."

    return 0
}

# Test External Service Connectivity
test_external_connectivity() {
    log_info "Verifying external connectivity from host to container..."

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
    local ROOT_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" openbao_info --root-token)
    local HTTP_STATUS=$(curl -s -H "X-Vault-Token: ${ROOT_TOKEN}" -o /dev/null -w "%{http_code}" "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/mounts")
    if [ "$HTTP_STATUS" -ne 200 ]; then
        log_error "Authenticated mounts check failed with status code $HTTP_STATUS."
        return 1
    fi
    log_info "Authenticated mounts check with root token passed."

    # Test authenticated endpoint using the new admin token
    log_info "Testing authenticated endpoint with admin token..."
    ADMIN_TOKEN=$(run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" openbao_info --admin-token)
    if ! curl --silent --fail --header "X-Vault-Token: ${ADMIN_TOKEN}" "http://${BAO_HOST_ADDRESS}:${BAO_HOST_PORT}/v1/sys/mounts" > /dev/null; then
        log_error "Authenticated mounts check with admin token failed."
        return 1
    fi
    log_info "Authenticated mounts check with admin token passed."

    return 0
}

check_existing_mounts() {
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

# --- Main Functions ---

# Helper to reset the test directory and prepare for a clean run
reset_test_dir() {
    log_info "Resetting test directory: ${OPENBAO_TEST_DIR}"
    rm -rf "${OPENBAO_TEST_DIR}"
    mkdir -p "${OPENBAO_TEST_DIR}/secrets"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/config"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/file"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/logs"
    mkdir -p "${OPENBAO_TEST_HOME_DIR}/plugins"
}

# Helper to build the Docker image
build_image() {
    log_info "Building Docker image: ${OPENBAO_TEST_IMAGE}"
    ## the OPENBAO_TEST_IMAGE (includes the OPENBAO_TEST_IMAGE_TAG) in CICD pipelines can be specific to a build
    if ! env OPENBAO_BUILD_IMAGE="${OPENBAO_TEST_IMAGE}" docker compose --project-name "${OPENBAO_TEST_PROJECT_NAME}" -f "${BUILD_COMPOSE_FILE}" build; then
        log_error "Docker build failed."
        exit 1
    fi
    log_info "Docker image built successfully."
}

# Helper to generate necessary files for the test
generate_test_files() {
    log_info "Generating docker-compose test file and environment files..."
    FULL_SCRIPT_DIR=$(full_path "${SCRIPT_DIR}")
    FULL_DOCKER_BUILD_DIR=$(full_path "${DOCKER_BUILD_DIR}")
    FULL_OPENBAO_TEST_HOME_DIR=$(full_path "${OPENBAO_TEST_HOME_DIR}")
    FULL_OPENBAO_TEST_DIR=$(full_path "${OPENBAO_TEST_DIR}")
    FULL_OPENBAO_TEST_PASSWD_FILE=$(full_path "${OPENBAO_TEST_PASSWD_FILE}")
    FULL_OPENBAO_TEST_GROUP_FILE=$(full_path "${OPENBAO_TEST_GROUP_FILE}")
    FULL_OPENBAO_TEST_ENV_FILE=$(full_path "${OPENBAO_TEST_ENV_FILE}")
    FULL_OPENBAO_TEST_TEST_ENV_FILE=$(full_path "${OPENBAO_TEST_TEST_ENV_FILE}")

    generate_OPENBAO_TEST_PASSWD_FILE
    generate_OPENBAO_TEST_GROUP_FILE
    generate_OPENBAO_TEST_ENV_FILE
    generate_OPENBAO_TEST_TEST_ENV_FILE
    generate_openbao_config
}

generate_OPENBAO_TEST_PASSWD_FILE() {
    log_info "Generating passwd file..."
    echo "${OPENBAO_USER}:x:$(id -u):$(id -g):OpenBao User:/vault:/bin/sh" > "${OPENBAO_TEST_PASSWD_FILE}"
}

generate_OPENBAO_TEST_GROUP_FILE() {
    log_info "Generating group file..."
    echo "${OPENBAO_USER}:x:$(id -g):" > "${OPENBAO_TEST_GROUP_FILE}"
}

generate_OPENBAO_TEST_ENV_FILE() {
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

generate_OPENBAO_TEST_TEST_ENV_FILE() {
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

generate_openbao_config() {
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
  "default_lease_ttl": "168h",
  "max_lease_ttl": "720h",
  "ui": true
}
EOF

    chmod 644 "${OPENBAO_TEST_CONFIG_FILE}"
    log_info "Generated ${OPENBAO_TEST_CONFIG_FILE}"
}

# --- Utility Functions ---
wait_for_container_health() {
    log_info "Waiting for container to report health..."
    local HEALTH_STATUS=""
    local MAX_ATTEMPTS=30
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
            run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
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

        log_info "Health check attempt $((ATTEMPT + 1)): Status = $HEALTH_STATUS"
        if [ "$HEALTH_STATUS" == "healthy" ]; then
            log_info "Container is healthy."
            return 0
        fi
        # Log the healthcheck output for debugging
        log_info "Logging vault initialization status..."
        run_docker_compose exec -T "${OPENBAO_TEST_SERVICE_NAME}" sh -c "bao status 2>&1 | tee -a ${OPENBAO_CONTAINER_HOME_DIR}/logs/healthcheck_output" || log_info "Vault status update failed."

        sleep "${SLEEP_TIME}"
        ATTEMPT=$((ATTEMPT + 1))
    done

    log_error "Container did not become healthy within $MAX_ATTEMPTS seconds."
    log_info "Container logs:"
    run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
#    docker logs "${CONTAINER_ID}" || true
    return 1
}

# --- Utility Functions ---

full_path() {
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

clean_containers() {
    log_info "Cleaning up containers..."
    if [ -n "${DOCKER_COMPOSE_TARGET_FILE}" ]; then
      if [ -f "${OPENBAO_TEST_TEST_ENV_FILE}" ]; then
        run_docker_compose down "${OPENBAO_TEST_SERVICE_NAME}" --volumes --remove-orphans
      fi
    fi
}

clean_files() {
    log_info "Cleaning up temporary files..."
    rm -rf "${OPENBAO_TEST_DIR}"
}

cleanup() {
    clean_containers
    clean_files
    log_info "Cleanup complete."
}

full_path() {
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

# --- End Utility Functions ---


# --- Test Suite Functions ---


# Function to report result
report_result() {
    local test_name="$1"
    local failed="$2"
    local message="$3"
    local escaped_message=$(echo "${message}" | sed 's/\"/\\\"/g')
    TEST_RESULTS+=("{\"test_name\":\"${test_name}\", \"failed\": ${failed}, \"message\": \"${escaped_message}\"}")
}

# Main function
main() {
    log_info "--- Starting OpenBao Test Suite ---"
    log_info "Command line arguments: $*"

    # --- UID/GID Detection ---
    log_info "Detected host UID: ${HOST_UID}, GID: ${HOST_GID}"
    if [ "$HOST_UID" -eq 0 ]; then
        log_info "WARNING: Running as root - best practice to test container as non-root user with only run container permissions."
    fi

    # --- Argument Parsing ---
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -x)
                set -x
                shift
                ;;
            -j|--junit)
                GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE=1
                shift
                ;;
            -k|--keep-tmp)
                KEEP_TMP_FILES=1
                shift
                ;;
            -s|--skip-build)
                SKIP_BUILD=1
                shift
                ;;
            -b|--image-name)
                OPENBAO_TEST_IMAGE_NAME="$2"
                shift 2
                ;;
            -i|--image)
                OPENBAO_TEST_IMAGE="$2"
                shift 2
                ;;
            -r|--test-results-dir)
                OPENBAO_TEST_RESULTS_DIR="$2"
                shift 2
                ;;
            -t|--test-dir)
                OPENBAO_TEST_DIR="$2"
                shift 2
                ;;
            --build-id)
                OPENBAO_TEST_BUILD_ID="$2"
                shift 2
                ;;
            *)
                log_error "Unknown parameter passed: $1"
                exit 1
                ;;
        esac
    done

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

    run_test "Initial Container Startup and State Management" test_initialization
    run_test "Setup Validation" test_setup_validation
    run_test "Auto-Unseal and Container Resilience" test_auto_unseal
    run_test "Data Integrity and Accessibility" test_data_integrity
    run_test "External Service Connectivity" test_external_connectivity

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
        log_error "Docker logs for service ${OPENBAO_TEST_SERVICE_NAME}:"
        run_docker_compose logs "${OPENBAO_TEST_SERVICE_NAME}"
    else
        log_info "All tests passed successfully."
        overall_status="passed"
    fi

    if [ "${GENERATE_OPENBAO_TEST_JUNIT_REPORT_FILE}" -eq 1 ]; then
      eval "${SCRIPT_DIR}/json2junit.py ${OPENBAO_TEST_JSON_REPORT_FILE} ${OPENBAO_TEST_JUNIT_REPORT_FILE}"
    fi

    log_info "Final status: ${overall_status}"

    # --- Clean up after all tests are done ---
    # Don't exit on error here, just log it.
    if [ "${KEEP_TMP_FILES}" -eq 0 ]; then
      cleanup || log_error "Cleanup failed."
    fi

    cat "${OPENBAO_TEST_JSON_REPORT_FILE}" | jq

    exit "$failed_tests"
}

# Call main function
main "$@"
