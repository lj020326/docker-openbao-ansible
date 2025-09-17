#!/bin/sh
set -e

# --- Logging Configuration ---
LOG_LEVEL_ERROR=0
LOG_LEVEL_WARNING=1
LOG_LEVEL_INFO=2
LOG_LEVEL_DEBUG=3
LOG_LEVEL_TRACE=4

export BOOTSTRAP_LOG_LEVEL=${BOOTSTRAP_LOG_LEVEL:-DEBUG}

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

CURRENT_NUMERIC_LOG_LEVEL=$(_get_numeric_log_level "$BOOTSTRAP_LOG_LEVEL")

_log() {
    local level="$1"
    local message="$2"
    local numeric_level=$(_get_numeric_log_level "$level")

    if [ "$numeric_level" -le "$CURRENT_NUMERIC_LOG_LEVEL" ]; then
        echo "Bootstrap $level: $message" >&2
    fi
}

# Source env_secrets_expand.sh to resolve secrets
if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
    _log DEBUG "Sourcing env_secrets_expand.sh"
    . /usr/local/bin/env_secrets_expand.sh
else
    _log ERROR "env_secrets_expand.sh not found"
    exit 1
fi

# Default files and directories
OPENBAO_HOME_DIR=${OPENBAO_HOME_DIR:-'/vault'}
OPENBAO_CONFIG_DIR=${OPENBAO_CONFIG_DIR:-${OPENBAO_HOME_DIR}/config}
OPENBAO_DATA_DIR=${OPENBAO_DATA_DIR:-${OPENBAO_HOME_DIR}/file}
OPENBAO_LOGS_DIR=${OPENBAO_LOGS_DIR:-${OPENBAO_HOME_DIR}/logs}
OPENBAO_PLUGINS_DIR=${OPENBAO_PLUGINS_DIR:-${OPENBAO_HOME_DIR}/plugins}

# Define OpenBao configuration variables
export BAO_ADDR=${BAO_ADDR:-'http://127.0.0.1:8200'}
export BAO_CACERT=${BAO_CACERT:-''}
export BAO_CLIENT_CERT=${BAO_CLIENT_CERT:-''}
export BAO_CLIENT_KEY=${BAO_CLIENT_KEY:-''}
export BAO_NAMESPACE=${BAO_NAMESPACE:-''}
export BAO_TOKEN=${BAO_TOKEN:-''}
export BAO_TOKEN_FILE=${BAO_TOKEN_FILE:-"${OPENBAO_HOME_DIR}/.vault-token"}
export BAO_FORMAT=${BAO_FORMAT:-'json'}

# State file locations
INIT_INFO_FILE=${OPENBAO_HOME_DIR}/config/init.json
ENCRYPTED_INIT_FILE=${OPENBAO_HOME_DIR}/config/init.json.enc
ANSIBLE_VAULT_PASSWORD_FILE=$(mktemp)

# Temporary files
BAO_STATUS_OUTPUT=$(mktemp)

# --- Utility Functions ---

# Cleanup function to remove temporary files
cleanup() {
    _log DEBUG "Cleaning up temporary files..."
    rm -f "${BAO_TOKEN_FILE}"
    _log DEBUG "Cleanup complete."
}

# Get the root token from the encrypted file
get_root_token() {
    if [ ! -f "$ENCRYPTED_INIT_FILE" ]; then
        _log ERROR "Encrypted init file not found: $ENCRYPTED_INIT_FILE"
        return 1
    fi
    _log DEBUG "Fetching root token..."
    # The openbao_info script handles decryption and token extraction
    root_token=$(openbao_info --root-token)
    if [ -z "$root_token" ]; then
        _log ERROR "Failed to fetch root token."
        return 1
    fi
    echo "${root_token}" > "${BAO_TOKEN_FILE}"
    export BAO_TOKEN=$(cat "${BAO_TOKEN_FILE}")
    _log DEBUG "Successfully fetched root token."
    return 0
}

get_ansible_password_file() {
    # Source the env_secrets_expansion script to resolve variables like ANSIBLE_VAULT_PASSWORD
    if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
      _log DEBUG "Sourcing /usr/local/bin/env_secrets_expand.sh to expand secrets."
      . /usr/local/bin/env_secrets_expand.sh
    else
      _log ERROR "env_secrets_expand.sh not found at /usr/local/bin/env_secrets_expand.sh"
      return 1
    fi
    
    # Write ANSIBLE_VAULT_PASSWORD to a temporary file
    if [ -z "${ANSIBLE_VAULT_PASSWORD}" ]; then
      _log ERROR "ANSIBLE_VAULT_PASSWORD is not set."
      return 1
    fi

    echo "${ANSIBLE_VAULT_PASSWORD}" > "${ANSIBLE_VAULT_PASSWORD_FILE}"
    chmod 600 "${ANSIBLE_VAULT_PASSWORD_FILE}"

    _log DEBUG "Created temporary password file: ${ANSIBLE_VAULT_PASSWORD_FILE}"
    return 0
}

# Generate a new admin token and update the encrypted init file
generate_admin_token() {
    _log INFO "Generating new admin token."

    # First, decrypt the existing init file to read its contents
    local decrypted_file=$(mktemp)
    if ! ansible-vault decrypt "$ENCRYPTED_INIT_FILE" --vault-password-file "${ANSIBLE_VAULT_PASSWORD_FILE}" --output "$decrypted_file" > /dev/null 2>&1; then
        _log ERROR "Failed to decrypt init.json.enc for token generation."
        rm -f "$decrypted_file"
        return 1
    fi

    # Get the token of the new admin user
    local admin_user_token
    admin_user_token=$(bao token create -display-name="admin_user_token" -policy="admin" -format=json | jq -r '.auth.client_token')

    if [ -z "$admin_user_token" ] || [ "$admin_user_token" = "null" ]; then
        _log ERROR "Failed to create or retrieve new admin user token."
        rm -f "$decrypted_file"
        return 1
    fi

    _log DEBUG "Created new admin token."

    # Update the decrypted JSON with the new admin token
    local updated_json=$(jq --arg admin_token "$admin_user_token" '.admin_token = $admin_token' "$decrypted_file")

    if [ -z "$updated_json" ]; then
        _log ERROR "Failed to add admin_token to the decrypted JSON."
        rm -f "$decrypted_file"
        return 1
    fi

    _log DEBUG "Successfully added admin token to JSON data."

    # Encrypt the updated JSON and save it back to the original file
    echo "$updated_json" | ansible-vault encrypt --vault-password-file "${ANSIBLE_VAULT_PASSWORD_FILE}" --output "$ENCRYPTED_INIT_FILE" > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        _log ERROR "Failed to re-encrypt the init file with the new admin token."
        rm -f "$decrypted_file"
        return 1
    fi

    _log INFO "Updated init.json.enc with new admin token."
    rm -f "$decrypted_file"
    return 0
}


# Check if the OpenBao server is initialized
check_initialized() {
    _log DEBUG "Checking if OpenBao is initialized..."
    if bao status -format=json | jq -e '.initialized' | grep -q 'true'; then
        _log DEBUG "OpenBao is initialized."
        return 0
    else
        _log ERROR "OpenBao is not initialized."
        return 1
    fi
}

# Check if the OpenBao server is sealed
check_sealed() {
    _log DEBUG "Checking if OpenBao is sealed..."
    if bao status -format=json | jq -e '.sealed' | grep -q 'true'; then
        _log DEBUG "OpenBao is sealed."
        return 0
    else
        _log ERROR "OpenBao is not sealed."
        return 1
    fi
}

# Create a policy named 'admin'
create_admin_policy() {
    _log INFO "Creating admin policy..."
    if ! bao policy write admin policy_admin.hcl; then
        _log ERROR "Failed to create admin policy."
        return 1
    fi
    _log INFO "Admin policy created."
    return 0
}

# Create a policy named 'user'
create_user_policy() {
    _log INFO "Creating user policy..."
    if ! bao policy write user policy_user.hcl; then
        _log ERROR "Failed to create user policy."
        return 1
    fi
    _log INFO "User policy created."
    return 0
}

# Enable the userpass auth method if not already enabled
enable_userpass() {
    _log INFO "Enabling userpass auth method..."
    if bao auth list | grep -q 'userpass/'; then
        _log INFO "userpass auth method is already enabled. Skipping."
        return 0
    fi

    if bao auth enable userpass; then
        _log INFO "Successfully enabled userpass auth method."
        return 0
    else
        _log ERROR "Failed to enable userpass auth method."
        return 1
    fi
    _log INFO "Userpass auth method enabled."
    return 0
}

# Create a 'testuser' with 'user' and 'admin' policies
create_test_user() {
    _log INFO "Creating test user 'test_user'..."
    if ! bao write auth/userpass/users/test_user password=test_password policies=user; then
        _log ERROR "Failed to create test user."
        return 1
    fi
    _log INFO "Test user 'test_user' created."
    return 0
}

# Enable the kv secrets engine if not already enabled
enable_kv() {
    _log INFO "Enabling KV secrets engine..."
    if bao secrets list | grep -q 'kv/'; then
        _log INFO "kv secrets engine is already enabled. Skipping."
        return 0
    fi
    if bao secrets enable -version=2 kv; then
        _log INFO "Successfully enabled kv secrets engine."
        return 0
    else
        _log ERROR "Failed to enable kv secrets engine."
        return 1
    fi
}

# Main function to run all setup tasks
main() {
    _log INFO "Starting OpenBao bootstrap process..."

    if ! get_ansible_password_file; then
        _log ERROR "Failed to get ansible password file. Cannot proceed with setup."
        exit 1
    fi

    if ! check_initialized; then
        _log ERROR "OpenBao is not initialized. Cannot proceed with setup."
        exit 1
    fi

    if check_sealed; then
        _log ERROR "OpenBao is sealed. Please unseal before running setup."
        exit 1
    fi

    if ! get_root_token; then
        _log ERROR "Failed to fetch root token. Cannot proceed with setup."
        exit 1
    fi

    _log DEBUG "Using BAO_TOKEN: $BAO_TOKEN"

    if ! create_admin_policy; then
        _log ERROR "Failed to create admin policy. Aborting."
        exit 1
    fi

    if ! create_user_policy; then
        _log ERROR "Failed to create user policy. Aborting."
        exit 1
    fi

    if ! enable_userpass; then
        _log ERROR "Failed to enable userpass auth method. Aborting."
        exit 1
    fi

    if ! create_test_user; then
        _log ERROR "Failed to create test user. Aborting."
        exit 1
    fi

    if ! enable_kv; then
        _log ERROR "Failed to enable kv secrets engine. Aborting."
        exit 1
    fi

    # New step to generate and store the admin token
    if ! generate_admin_token; then
        _log ERROR "Failed to generate admin token. Aborting."
        exit 1
    fi

    _log INFO "OpenBao bootstrap process completed successfully."
}

trap cleanup EXIT

# Parse arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        --all)
            main
            exit 0
            ;;
        *)
            _log ERROR "Unknown option: $1"
            exit 1
            ;;
    esac
done

_log INFO "OpenBao setup script finished."
