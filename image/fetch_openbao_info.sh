#!/bin/sh
set -e

ENCRYPTED_FILE="/vault/config/init.json.enc"
DECRYPTED_FILE=$(mktemp /tmp/init_json_decrypted.XXXXXX)
ANSIBLE_VAULT_PASSWORD_FILE=$(mktemp)

# Initialize VERBOSE_MODE to false by default
VERBOSE_MODE=false

# Function to log messages to stderr, respecting VERBOSE_MODE
log_message() {
  if [ "$VERBOSE_MODE" = true ]; then
    echo "DEBUG: $1" >&2
  fi
}

# Function to log errors and exit
log_error() {
  echo "ERROR: $1" >&2
  exit 1
}

# Function to clean up temporary files
cleanup() {
  log_message "Cleaning up temporary files..."
  rm -f "${DECRYPTED_FILE}" "${ANSIBLE_VAULT_PASSWORD_FILE}"
  log_message "Cleanup complete."
}

# Register cleanup function to run on exit
trap cleanup EXIT

# Parse command line arguments
# Loop through arguments until none are left
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v|--verbose)
      VERBOSE_MODE=true
      shift # Past argument
      ;;
    --root-token|--unseal-keys|--content)
      # These flags are handled later for operation,
      # but we need to pass them on
      OPERATION_FLAG="$1"
      shift # Past argument
      ;;
    *)
      # Unknown option
      echo "Usage: $0 [-v|--verbose] [--content | --root-token | --unseal-keys]" >&2
      exit 1
      ;;
  esac
done

# Check if an operation flag was provided
if [ -z "$OPERATION_FLAG" ]; then
  echo "ERROR: Missing operation flag. Usage: $0 [-v|--verbose] [--content | --root-token | --unseal-keys]" >&2
  exit 1
fi


# Source the secret expansion script to resolve variables like ANSIBLE_VAULT_PASSWORD.
if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
  log_message "Sourcing /usr/local/bin/env_secrets_expand.sh to expand secrets."
  . /usr/local/bin/env_secrets_expand.sh
else
  log_error "env_secrets_expand.sh not found at /usr/local/bin/. Cannot expand secrets."
fi

# Verify ANSIBLE_VAULT_PASSWORD is now set and non-empty after expansion
if [ -z "${ANSIBLE_VAULT_PASSWORD}" ]; then
  log_error "ANSIBLE_VAULT_PASSWORD is not set or is empty after env_secrets_expand.sh. Cannot decrypt."
fi
log_message "ANSIBLE_VAULT_PASSWORD appears to be resolved after expansion."

# Create temporary password file
echo "${ANSIBLE_VAULT_PASSWORD}" > "${ANSIBLE_VAULT_PASSWORD_FILE}"
chmod 600 "${ANSIBLE_VAULT_PASSWORD_FILE}"
log_message "Created temporary password file: ${ANSIBLE_VAULT_PASSWORD_FILE}"

# Check if encrypted file exists
if [ ! -f "${ENCRYPTED_FILE}" ]; then
  log_error "Encrypted file not found: ${ENCRYPTED_FILE}"
fi
log_message "Encrypted file found: ${ENCRYPTED_FILE}"

# Function to decrypt init.json.enc
decrypt_init_json() {
  log_message "Attempting to decrypt ${ENCRYPTED_FILE}..."

  local decrypt_cmd="ansible-vault decrypt \"${ENCRYPTED_FILE}\" --vault-password-file \"${ANSIBLE_VAULT_PASSWORD_FILE}\" --output \"${DECRYPTED_FILE}\""

  if [ "$VERBOSE_MODE" = true ]; then
    eval "${decrypt_cmd}" >&2 # Redirect stdout to stderr for visibility in verbose mode
  else
    eval "${decrypt_cmd} > /dev/null 2>&1" # Suppress all output from ansible-vault
  fi

  if [ $? -ne 0 ]; then
    log_error "ansible-vault decryption failed for ${ENCRYPTED_FILE}.\n  Please check the following:\n  1. Is the ANSIBLE_VAULT_PASSWORD correct after expansion?\n  2. Does the 'openbao' user have read permissions on ${ENCRYPTED_FILE} and write permissions to /tmp?"
  fi
  log_message "Decryption successful to ${DECRYPTED_FILE}."
}

# --- Use Cases ---

case "$OPERATION_FLAG" in
  --content)
    decrypt_init_json
    log_message "--- Content of decrypted init.json ---"
    cat "${DECRYPTED_FILE}"
    ;;
  --root-token)
    decrypt_init_json
    jq -r '.root_token' "${DECRYPTED_FILE}"
    ;;
  --unseal-keys)
    decrypt_init_json
    jq -r '.unseal_keys_b64[]' "${DECRYPTED_FILE}"
    ;;
  *)
    # This should ideally not be reached due to earlier check, but as a fallback
    echo "Usage: $0 [-v|--verbose] [--content | --root-token | --unseal-keys]" >&2
    exit 1
    ;;
esac
