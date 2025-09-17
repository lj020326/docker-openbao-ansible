#!/bin/sh
set -e

# --- Configuration ---
ENCRYPTED_FILE="/vault/config/init.json.enc"
# Use a more descriptive temporary file path
DECRYPTED_FILE=$(mktemp /tmp/openbao_init_decrypted.XXXXXX)
ANSIBLE_VAULT_PASSWORD_FILE=$(mktemp)

# Initialize VERBOSE_MODE to false by default
VERBOSE_MODE=false
OPERATION_FLAG=

# Function to log messages to stderr, respecting VERBOSE_MODE
log_message() {
  if [ "$VERBOSE_MODE" = true ]; then
    echo "DEBUG: $1" >&2
  fi
}

# Function to log errors and exit
log_error() {
  echo "ERROR: $1" >&2
}

# Function to log errors and exit
error() {
  log_error "$1"
  exit 1
}

# Function to clean up temporary files
cleanup() {
  log_message "Cleaning up temporary files..."
  rm -f "${DECRYPTED_FILE}" "${ANSIBLE_VAULT_PASSWORD_FILE}"
  log_message "Cleanup complete."
}

# Register the cleanup function to run on exit
trap cleanup EXIT

# Function to decrypt init.json.enc
decrypt_init_json() {
  log_message "Attempting to decrypt $ENCRYPTED_FILE..."

  local decrypt_cmd="ansible-vault decrypt \"$ENCRYPTED_FILE\" --vault-password-file \"$ANSIBLE_VAULT_PASSWORD_FILE\" --output \"$DECRYPTED_FILE\""

  if [ "$VERBOSE_MODE" = true ]; then
    eval "$decrypt_cmd" >&2
  else
    eval "$decrypt_cmd > /dev/null 2>&1"
  fi

  if [ $? -ne 0 ]; then
    error "ansible-vault decryption failed for $ENCRYPTED_FILE"
  fi
  log_message "Decryption successful. Decrypted file at $DECRYPTED_FILE"
  return 0
}

# Check if OpenBao is unsealed
check_unsealed() {
  local status_output
  status_output=$(VAULT_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true)
  if [ -z "$status_output" ]; then
    log_message "bao status returned empty. OpenBao is not running or responsive."
    return 1
  fi
  if echo "$status_output" | jq -e '.sealed == false' >/dev/null 2>&1; then
    log_message "OpenBao is unsealed."
    return 0
  else
    log_message "OpenBao is sealed."
    return 1
  fi
}

# --- Main Logic ---

# Check for a valid operation flag
if [ "$#" -eq 0 ]; then
  error "No operation flag provided. Use --content, --root-token, --admin-token, --unseal-keys, --output-file, --decrypt, or --is-vault-ready."
fi

# Parse command line options
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v|--verbose)
      VERBOSE_MODE=true
      shift
      ;;
    --content|--root-token|--admin-token|--unseal-keys|--output-file|--decrypt|--is-vault-ready)
      OPERATION_FLAG="$1"
      shift
      ;;
    *)
      error "Unknown option: $1"
      ;;
  esac
done

# Source the env_secrets_expansion script to resolve variables like ANSIBLE_VAULT_PASSWORD
if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
  log_message "Sourcing /usr/local/bin/env_secrets_expand.sh to expand secrets."
  . /usr/local/bin/env_secrets_expand.sh
else
  log_error "env_secrets_expand.sh not found at /usr/local/bin/env_secrets_expand.sh"
fi

# Write ANSIBLE_VAULT_PASSWORD to a temporary file for operations that require it
if [ "$OPERATION_FLAG" != "--is-vault-ready" ]; then
  if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
    error "ANSIBLE_VAULT_PASSWORD is not set."
  fi
  echo "$ANSIBLE_VAULT_PASSWORD" > "$ANSIBLE_VAULT_PASSWORD_FILE"
  chmod 600 "$ANSIBLE_VAULT_PASSWORD_FILE"
  log_message "Created temporary password file: $ANSIBLE_VAULT_PASSWORD_FILE"
fi

# Check if encrypted file exists for operations requiring it
if [ "$OPERATION_FLAG" != "--output-file" ] && [ "$OPERATION_FLAG" != "--is-vault-ready" ] && [ ! -f "$ENCRYPTED_FILE" ]; then
  error "Encrypted file not found: $ENCRYPTED_FILE"
fi

# --- Use Cases ---
case "$OPERATION_FLAG" in
  --is-vault-ready)
    log_message "Checking for setup completion file..."
    if [ ! -f "/vault/.setup_completed" ]; then
      error "Setup completion file not found."
    fi
    log_message "Setup completion file found."

    log_message "Checking if OpenBao is unsealed..."
    if ! check_unsealed; then
      error "OpenBao is sealed."
    fi
    log_message "OpenBao is unsealed."
    log_message "Vault is ready."
    exit 0
    ;;
  --content)
    decrypt_init_json
    log_message "--- Content of decrypted init.json ---"
    cat "$DECRYPTED_FILE"
    ;;
  --root-token)
    decrypt_init_json
    jq -r '.root_token' "$DECRYPTED_FILE"
    ;;
  --admin-token)
    decrypt_init_json
    jq -r '.admin_token' "$DECRYPTED_FILE"
    ;;
  --unseal-keys)
    decrypt_init_json
    jq -r '.unseal_keys_b64[]' "$DECRYPTED_FILE"
    ;;
  --output-file)
    echo "$DECRYPTED_FILE"
    ;;
  --decrypt)
    decrypt_init_json
    ;;
  *)
    echo "Usage: $0 [-v|--verbose] [--content | --root-token | --admin-token | --unseal-keys | --output-file | --decrypt | --is-vault-ready]" >&2
    exit 1
    ;;
esac
