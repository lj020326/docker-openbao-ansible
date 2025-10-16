#!/bin/sh
set -e

## ref: https://github.com/openbao/openbao/blob/main/scripts/docker/docker-entrypoint.sh

# --- Logging Configuration ---
# Define log levels with numeric values
LOG_LEVEL_ERROR=0
LOG_LEVEL_WARNING=1
LOG_LEVEL_INFO=2
LOG_LEVEL_DEBUG=3
LOG_LEVEL_TRACE=4

# Default entrypoint log level to INFO, but allow override via environment variable
export ENTRYPOINT_LOG_LEVEL=${ENTRYPOINT_LOG_LEVEL:-INFO}

# Function to convert a log level string to its numeric equivalent
_get_numeric_log_level() {
    case "$1" in
        "ERROR") echo "$LOG_LEVEL_ERROR" ;;
        "WARNING") echo "$LOG_LEVEL_WARNING" ;;
        "INFO") echo "$LOG_LEVEL_INFO" ;;
        "DEBUG") echo "$LOG_LEVEL_DEBUG" ;;
        "TRACE") echo "$LOG_LEVEL_TRACE" ;;
        *) echo "$LOG_LEVEL_INFO" ;;
    esac
}

# Get the numeric value of the currently set entrypoint log level
CURRENT_NUMERIC_LOG_LEVEL=$(_get_numeric_log_level "$ENTRYPOINT_LOG_LEVEL")

# Generic logging function: prints messages to stderr if their level is sufficient
_log() {
    local level="$1"
    local message="$2"
    local numeric_level=$(_get_numeric_log_level "$level")

    if [ "$numeric_level" -le "$CURRENT_NUMERIC_LOG_LEVEL" ]; then
        echo "Entrypoint $level: $message" >&2
    fi
}
# --- End Logging Configuration ---

_log INFO "Running as user: $(id -u), group: $(id -g)"

# Source env_secrets_expand.sh to resolve secrets
if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
    _log DEBUG "Expanding secrets"
    . /usr/local/bin/env_secrets_expand.sh
else
    _log ERROR "Issue occurred when expanding secrets"
    exit 1
fi

# Set defaults for OpenBao environment variables
OPENBAO_RUN_SETUP="${OPENBAO_RUN_SETUP:-true}"
# Align home directory with docker-compose mapping
OPENBAO_HOME_DIR="${OPENBAO_HOME_DIR:-/vault}"
OPENBAO_CONFIG_DIR="${OPENBAO_CONFIG_DIR:-${OPENBAO_HOME_DIR}/config}"
OPENBAO_INIT_FILE_PREFIX="${OPENBAO_INIT_FILE_PREFIX:-${OPENBAO_CONFIG_DIR}/init}"

# INTERNAL_VAULT_ADDR is used by the entrypoint for health checks and other internal CLI commands
INTERNAL_VAULT_ADDR=http://127.0.0.1:8200
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

_log DEBUG "docker-entrypoint.sh started with args: $@"
_log DEBUG "Shell environment:"
env | grep -v -i ANSIBLE_VAULT_PASSWORD >&2

_log DEBUG "Derived config settings:"
_log DEBUG "OPENBAO_HOME_DIR: ${OPENBAO_HOME_DIR}"
_log DEBUG "OPENBAO_CONFIG_DIR: ${OPENBAO_CONFIG_DIR}"
_log DEBUG "OPENBAO_INIT_FILE_PREFIX (for JSON data): ${OPENBAO_INIT_FILE_PREFIX}"
_log DEBUG "INTERNAL_VAULT_ADDR for health checks: ${INTERNAL_VAULT_ADDR}"
_log DEBUG "VAULT_ADDR for CLI commands: ${VAULT_ADDR}"

# --- Permission and Writability Validation for Critical Directories ---
validate_writability() {
    local dir="$1"
    local description="$2"
    _log DEBUG "Validating writability for '$dir' ('$description')..."
    touch "$dir/test_write" || { _log ERROR "Cannot write to $dir ($description)"; exit 1; }
    rm -f "$dir/test_write" || { _log ERROR "Cannot remove test file in $dir ($description)"; exit 1; }
    _log DEBUG "Writability for $dir is correct."
}

validate_writability "$OPENBAO_CONFIG_DIR" "Configuration Directory"
validate_writability "$OPENBAO_HOME_DIR/file" "Storage Directory"

# --- End Permission and Writability Validation ---

# Handle BAO_LOCAL_CONFIG
if [ -n "$BAO_LOCAL_CONFIG" ]; then
    _log DEBUG "Writing BAO_LOCAL_CONFIG to "$OPENBAO_CONFIG_DIR/local.json""
    echo "$BAO_LOCAL_CONFIG" > "$OPENBAO_CONFIG_DIR/local.json"
fi

# Check if config file exists
if [ ! -r "$OPENBAO_CONFIG_DIR/local.json" ]; then
    _log ERROR "Config file not found or not readable at "$OPENBAO_CONFIG_DIR/local.json""
    exit 1
fi
_log DEBUG "Contents of "$OPENBAO_CONFIG_DIR/local.json":"
cat "$OPENBAO_CONFIG_DIR/local.json" >&2

# Function for health checking with verbose curl output
wait_for_openbao() {
    local url="${INTERNAL_VAULT_ADDR}/v1/sys/health"
    _log DEBUG "wait_for_openbao: Checking health at "$url""

    local max_wait_attempts=12
    local attempt=0
    local server_responsive=0

    while [ "$attempt" -lt "$max_wait_attempts" ]; do
        local temp_verbose_log=$(mktemp)
        local http_code
        http_code=$(curl -v -k -s -o /dev/null -w "%{http_code}" "$url" 2>"$temp_verbose_log" || true)
        cat "$temp_verbose_log" > /dev/stderr
        rm "$temp_verbose_log"

        _log DEBUG "wait_for_openbao: Received HTTP code: "$http_code""
        if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 429 ] || [ "$http_code" -eq 501 ] || [ "$http_code" -eq 503 ]; then
            server_responsive=1
            return 0
        fi
        _log DEBUG "Waiting for main OpenBao server (attempt $((attempt + 1))/"$max_wait_attempts")"
        attempt=$((attempt + 1))
        sleep 10
    done

    if [ "$server_responsive" -eq 0 ]; then
        _log ERROR "Main OpenBao server did not become responsive within "$((max_wait_attempts * 10))" seconds."
        return 1
    fi
}


get_openbao_status_output() {
    VAULT_ADDR="${VAULT_ADDR}" bao status -format=json 2>/dev/null || true
}

check_initialized() {
    local status_output
    status_output=$(get_openbao_status_output)
    if echo "$status_output" | jq -e '.initialized == true' >/dev/null 2>&1; then
        _log DEBUG "check_initialized: OpenBao IS initialized."
        return 0
    fi
    _log DEBUG "check_initialized: OpenBao IS NOT initialized."
    return 1
}

check_sealed() {
    local status_output
    status_output=$(get_openbao_status_output)
    if echo "$status_output" | jq -e '.sealed == true' >/dev/null 2>&1; then
        _log DEBUG "check_sealed: OpenBao IS sealed."
        return 0
    fi
    _log DEBUG "check_sealed: OpenBao IS NOT sealed."
    return 1
}

# Encrypts the original init JSON file and saves it to the encrypted path
encrypt_init_json_file() {
    local unencrypted_file="$1"
    local encrypted_file="$2"
    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot encrypt initialization file."
        return 1
    fi
    _log DEBUG "Encrypting "$unencrypted_file" to "$encrypted_file" with ansible-vault"
    if ! ansible-vault encrypt "$unencrypted_file" --output="$encrypted_file" --vault-password-file=<(echo "${ANSIBLE_VAULT_PASSWORD}"); then
        _log ERROR "Failed to encrypt initialization file with ansible-vault."
        return 1
    fi
    _log INFO "Initialization file encrypted to "$encrypted_file""
    return 0
}

# Decrypts the encrypted file and return decrypted content
decrypt_ansible_vault_file() {
    local encrypted_file="$1"

    # Check if the encrypted file exists and is readable
    if [ ! -r "$encrypted_file" ]; then
        _log ERROR "Encrypted file not found or not readable at '$encrypted_file'"
        return 1
    fi

    # Check if the Ansible vault password is set
    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot decrypt file."
        return 1
    fi

    # Use a here string to pass the password to ansible-vault
    local decrypted_content
    if ! decrypted_content=$(ansible-vault decrypt "$encrypted_file" --output=- --vault-password-file=<(echo "${ANSIBLE_VAULT_PASSWORD}")); then
        _log ERROR "Failed to decrypt '$encrypted_file'."
        return 1
    fi

    _log DEBUG "Successfully decrypted '$encrypted_file' to a variable."
    echo "$decrypted_content"
    return 0
}

# This function will generate an init.json file based on the *current* state of OpenBao
# (i.e., by performing a `bao operator init` dry-run or similar to get keys if possible,
# or simulating if no other option) and then encrypt it.
# IMPORTANT: This will NOT re-initialize OpenBao if it's already initialized.
# Updated: record_initialization_state to add users/tokens stubs
record_initialization_state() {
    local unencrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json"
    local encrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"

    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot record initialization state (encrypt keys)."
        _log ERROR "Please ensure ANSIBLE_VAULT_PASSWORD is provided in your environment (e.g., in openbao.env)."
        return 1
    fi

    _log INFO "Recording OpenBao initialization state. Generating new unseal keys and root token."
    _log INFO "Unencrypted init JSON file will be at: "$unencrypted_init_json_file""

    _log DEBUG "Running bao operator init"
    local init_output

    _log TRACE "Enabling set -x for bao operator init command."
    set -x # Enable verbose tracing for the next command

    # Use INTERNAL_VAULT_ADDR for CLI commands targeting the local server
    # Running init again, but for already initialized server, it gives the keys back
    init_output=$(VAULT_ADDR="${INTERNAL_VAULT_ADDR}" bao operator init -key-shares=5 -key-threshold=3 -format=json 2>&1)
    local init_exit_code=$?
    set +x # Disable verbose tracing
    _log TRACE "Disabled set -x."

    if [ $init_exit_code -ne 0 ]; then
        # If it's already initialized, bao operator init exits with 2 (error),
        # but the output should still contain the keys if server is unsealed.
        # We need to check if the error is "Vault is already initialized" and if it output keys.
        if echo "$init_output" | grep -q "Vault is already initialized"; then
            _log WARNING "bao operator init reported 'Vault is already initialized'. Attempting to extract keys from its output."
        else
            _log ERROR "OpenBao initialization command failed with unexpected exit code $init_exit_code."
            _log ERROR "Output from bao operator init: $init_output"
            return 1
        fi
    fi

    # Check if the output actually contains the expected JSON structure
    if ! echo "$init_output" | jq -e '.unseal_keys_b64 and .root_token' >/dev/null 2>&1; then
        _log ERROR "OpenBao initialization output did not contain expected unseal_keys_b64 or root_token."
        _log ERROR "Full Output from bao operator init: $init_output"
        _log ERROR "This can happen if OpenBao is already initialized and sealed, and 'bao operator init' cannot retrieve the keys."
        return 1
    fi

    _log DEBUG "Saving initialization details to "$unencrypted_init_json_file""
    # Enhanced JSON with users/tokens
    echo "$init_output" | jq '{
        unseal_keys_b64: .unseal_keys_b64,
        root_token: .root_token,
        users: {},
        tokens: {}
    }' > "$unencrypted_init_json_file"
    chmod 0600 "$unencrypted_init_json_file" # chmod by current user (openbao)

    _log INFO "OpenBao initialization state recorded successfully."

    if encrypt_init_json_file "$unencrypted_init_json_file" "$encrypted_init_json_file"; then
        _log INFO "OpenBao initialization details encrypted to "$encrypted_init_json_file""
        if [ ! -f "$encrypted_init_json_file" ]; then
            _log ERROR "Encryption reported success, but file "$encrypted_init_json_file" was not found."
            return 1
        fi
        return 0
    else
        _log ERROR "Initialization state recording succeeded, but encryption failed."
        return 1
    fi
}


initialize_openbao() {
    _log INFO "Initializing OpenBao..."
    local encrypted_init_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"

    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot initialize and encrypt OpenBao setup."
        _log ERROR "Please ensure ANSIBLE_VAULT_PASSWORD is provided in your environment (e.g., in openbao.env)."
        return 1
    fi

    _log TRACE "Enabling set -x for bao operator init command."
    set -x # Enable verbose tracing for the next command

    # Use INTERNAL_VAULT_ADDR for CLI commands targeting the local server
    local init_output=$(VAULT_ADDR="${INTERNAL_VAULT_ADDR}" bao operator init -key-shares=5 -key-threshold=3 -format=json 2>&1)
    local init_exit_code=$?
    set +x # Disable verbose tracing
    _log TRACE "Disabled set -x."

    if [ $init_exit_code -ne 0 ]; then
        _log ERROR "OpenBao initialization failed with exit code $init_exit_code."
        _log ERROR "Output from bao operator init: $init_output"
        return 1
    fi

    # Check if the output actually contains the expected JSON structure
    if ! echo "$init_output" | jq -e '.unseal_keys_b64 and .root_token' >/dev/null 2>&1; then
        _log ERROR "OpenBao initialization output did not contain expected unseal_keys_b64 or root_token."
        _log ERROR "Full Output from bao operator init: $init_output"
        return 1
    fi

    _log INFO "Initialization successful. Encrypting init data..."

    # Write the raw JSON output to a file temporarily for encryption
    local unencrypted_init_file=$(mktemp)
    # Enhanced JSON with users/tokens
    echo "$init_output" | jq '{
        unseal_keys_b64: .unseal_keys_b64,
        root_token: .root_token,
        users: {},
        tokens: {}
    }' > "$unencrypted_init_file"
    chmod 0600 "$unencrypted_init_file" # chmod by current user (openbao)

    if ! encrypt_init_json_file "$unencrypted_init_file" "$encrypted_init_file"; then
        _log ERROR "Failed to encrypt initialization data."
        rm -f "$unencrypted_init_file"
        return 1
    fi

    # Clean up unencrypted temporary files
    rm -f "$unencrypted_init_file"

    _log INFO "Initialization keys and root token saved securely."
    return 0
}

unseal_openbao() {
    local unseal_key="$1"
    _log DEBUG "Attempting to unseal OpenBao with key: [redacted]"
    local unseal_output
    # bao operator unseal will run as the current user (openbao)
    unseal_output=$(VAULT_ADDR="${VAULT_ADDR}" bao operator unseal "$unseal_key" 2>&1)
    local unseal_exit=$?

    if [ $unseal_exit -ne 0 ]; then
        _log ERROR "Failed to unseal OpenBao. Exit code: "$unseal_exit"."
        _log ERROR "Output: "$unseal_output""
        return 1
    fi

    _log DEBUG "OpenBao successfully unsealed."
    return 0
}

auto_unseal() {
    local encrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"

    if [ ! -r "$encrypted_init_json_file" ]; then
        _log ERROR "Encrypted init JSON file not found at "$encrypted_init_json_file". Cannot auto-unseal."
        return 1
    fi
    _log DEBUG "Found encrypted init JSON file at "$encrypted_init_json_file", attempting auto-unseal."

    if ! init_json=$(decrypt_ansible_vault_file "${OPENBAO_INIT_FILE_PREFIX}.json.enc"); then
        _log ERROR "Failed to decrypt init JSON file for auto-unseal."
        return 1
    fi

    local unseal_keys=$(echo "${init_json}" | jq -r '.unseal_keys_b64[]')

    local root_token=$(echo "${init_json}" | jq -r '.root_token')
    _log DEBUG "Root token found for reference (not used for unseal): [redacted]"

    if [ -z "$unseal_keys" ]; then
        _log ERROR "No unseal keys found in decrypted initialization data."
        return 1
    fi

    local applied_keys=0
    # Use IFS= and read -r to correctly handle keys with spaces/special characters
    echo "$unseal_keys" | while IFS= read -r key; do
        if [ "$applied_keys" -ge 3 ]; then
            _log DEBUG "Reached threshold of 3 unseal keys, stopping."
            break # Exit the while loop
        fi
        if unseal_openbao "$key"; then
            applied_keys=$((applied_keys + 1))
        else
            _log ERROR "Failed to apply unseal key."
            return 1 # This will exit the subshell, not the main script
        fi
    done

    # Check the actual sealed status AFTER the while loop finishes
    if check_sealed; then
        _log ERROR "OpenBao is still sealed after auto-unseal attempt."
        return 1
    else
        _log INFO "Auto-unseal process completed, applied "$applied_keys" keys. OpenBao successfully unsealed."
        return 0
    fi
}


background_init_and_unseal() {
    local encrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"

    _log INFO "Background init/unseal process started."
    _log INFO "Waiting for OpenBao server to become responsive..."
    if ! wait_for_openbao; then
        _log ERROR "Main OpenBao server did not become responsive within the timeout. Exiting background unseal."
        exit 1
    fi
    _log INFO "OpenBao server is responsive."

    # Determine if OpenBao is initialized
    local is_openbao_initialized
    if check_initialized; then
        is_openbao_initialized=0 # true
        _log INFO "OpenBao API reports already initialized."
    else
        is_openbao_initialized=1 # false
        _log INFO "OpenBao API reports NOT initialized."
    fi

    # If OpenBao is not initialized, try to initialize it
    if [ "$is_openbao_initialized" -ne 0 ]; then # If OpenBao is NOT initialized
        _log INFO "Attempting OpenBao initialization and encryption..."
        if ! initialize_openbao; then
            _log ERROR "Initialization failed in background process. Exiting."
            exit 1
        fi
        _log INFO "OpenBao initialization and encryption completed successfully."
    else
        # If OpenBao IS initialized, we still need to make sure our *local* encrypted init file exists
        # so that auto-unseal can work if needed.
        if [ ! -f "$encrypted_init_json_file" ]; then
            _log WARNING "OpenBao API reports initialized, but encrypted initialization file not found at "$encrypted_init_json_file"."
            _log WARNING "This means OpenBao was initialized externally or its init file was deleted."
            _log INFO "Attempting to record initialization state (generate and encrypt new unseal keys/root token)."
            if ! record_initialization_state; then
                _log ERROR "Failed to record initialization state. Auto-unseal will not work. Exiting."
                exit 1
            fi
            _log INFO "Initialization state successfully recorded and encrypted."
        else
            _log DEBUG "Encrypted initialization file found at "$encrypted_init_json_file"."
        fi
    fi

    _log INFO "Checking OpenBao sealed status..."
    if check_sealed; then
        _log INFO "OpenBao IS sealed. Attempting auto-unseal..."
        if ! auto_unseal; then
            _log ERROR "Auto-unseal failed in background process. Exiting."
            exit 1
        fi
    else
        _log DEBUG "OpenBao is already unsealed."
    fi

    _log INFO "Verifying vault status before setup..."
    status_output=$(bao status 2>&1)
    if echo "$status_output" | grep -q "Sealed.*true"; then
        _log ERROR "Vault is sealed before running openbao_setup.sh: $status_output"
        _log DEBUG "Server log contents:"
        cat ${OPENBAO_HOME_DIR}/logs/server.log >&2
        stop_server_background
        exit 1
    fi
    _log DEBUG "Vault status: $status_output"

if [ "$OPENBAO_RUN_SETUP" = true ]; then
        _log INFO "Running openbao_setup.sh to configure policies and secret engines..."
        # Mount YAML if not exists (for idempotency)
        if [ ! -f /vault/config/openbao_config.yml ]; then
            _log WARN "openbao_config.yml not mounted; skipping idempotent setup."
        else
            eval "/usr/local/bin/openbao_setup.sh"
        fi
        if [ $? -ne 0 ]; then
            _log ERROR "openbao_setup.sh failed."
            _log DEBUG "Server log contents:"
            cat ${OPENBAO_HOME_DIR}/logs/server.log >&2
            stop_server_background
            exit 1
        fi
    fi
    touch "${OPENBAO_HOME_DIR}/.setup_completed"
    _log INFO "Wrote status file to ${OPENBAO_HOME_DIR}/.setup_completed"

    _log INFO "Background init/unseal process completed successfully."
}

run_server() {
    local server_args="-config=$OPENBAO_CONFIG_DIR/local.json"

    _log DEBUG "Execing OpenBao server as PID 1 with args: $server_args"

    background_init_and_unseal &

    # bao server will run as the current user (openbao)
    exec bao server $server_args
}

# Signal handling to ensure graceful shutdown
# The server is exec'd, so it will handle signals directly.
# This part is mostly for the init/unseal background process.
stop_server_background() {
    local server_pid=$(jobs -p | head -1)
    if [ -n "$server_pid" ]; then
        _log INFO "Sending SIGTERM to background server process (PID: $server_pid)..."
        kill -s TERM "$server_pid"
        wait "$server_pid" >/dev/null 2>&1
        _log INFO "Background server process stopped."
    fi
}
trap stop_server_background EXIT TERM INT HUP

if [ $# -eq 0 ]; then
    run_server
else
    # Any other command will run as the current user (openbao)
    exec "$@"
fi
