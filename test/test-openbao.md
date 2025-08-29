
OpenBao Configuration Snapshot - 2025-08-29-1634

This document provides a snapshot of the docker-compose.yml, openbao/openbao.env, openbao/home/config/local.json, and the working docker-entrypoint.sh from August 29, 2025, at 16:34 PM EDT. This represents a known good configuration where OpenBao successfully initializes, encrypts its init.txt file, and auto-unseals upon startup.

Test Run will include:
1) initialization and encrypting token and keys and
2) remove container and
3) restart container to test decrypting encrypted keys and auto unsealing existing vault
4) fetch tests to verify initialization content can be fetched
5) host based curl tests against the traefik openboa https endpoint for health (non-token based) and sys/mounts (with token)

Note the container features:
1) container is non-root compliant: it does not (1) chown, (2) chmod, (3) su-exec or run any root required commands.
2) variable level logging
3) encrypt/decrypt json storage for root token and unseal keys 
4) utility script "fetch_openbao_info.sh" that can
   - display the content of the encrypted json file and 
   - retrieve the root_token value only without any other debug such that the results can be directly used to set ROOT_TOKEN value from host

docker-compose.yml
```yaml
networks:

  traefik_public:
    external: true

secrets:
  ansible_vault_password:
    external: true


services:
  ########################
  ## BASE GROUP SERVICES
  traefik:
    image: traefik:v3.2
    environment:
      PGID: '1102'
      PUID: '1102'
      TZ: America/New_York
    networks:
      - traefik_public
    ports:
      - mode: host
        protocol: tcp
        published: 80
        target: 80
      - mode: host
        protocol: tcp
        published: 443
        target: 443
    deploy:
      endpoint_mode: dnsrr
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 30s
        max_attempts: 3
        window: 60s
      update_config:
        order: start-first
      labels:
        - traefik.enable=true
        - traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https
        - traefik.http.routers.http-catchall.entrypoints=http
        - traefik.http.routers.http-catchall.middlewares=redirect-to-https
        - traefik.http.routers.http-catchall.rule=HostRegexp(`{host:.+}`)
        - traefik.http.routers.ping.entrypoints=https
        - traefik.http.routers.ping.rule=Host(`traefik.admin.johnson.int`) && PathPrefix(`/ping`)
        - traefik.http.routers.ping.service=ping@internal
        - traefik.http.routers.traefik-rtr.service=api@internal
        - traefik.http.routers.traefik-rtr.entrypoints=https
        - traefik.http.routers.traefik-rtr.rule=Host(`traefik.admin.johnson.int`)
        - traefik.http.services.api.loadbalancer.server.port=8080
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /home/container-user/docker/traefik:/etc/traefik
      - /home/container-user/docker/traefik/certs:/certs
      - /home/container-user/docker/shared:/shared


  ########################
  ## OPENBAO GROUP SERVICES
  openbao:
    image: media.johnson.int:5000/openbao-ansible:2.3.2
    env_file:
      - openbao/openbao.env
    user: 1102:1102
    cap_add:
      - IPC_LOCK
    networks:
      - traefik_public
    ports:
      - 8200:8200
      - 8201:8201
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 180s
      test:
      - CMD-SHELL
      - vault status > /vault/logs/healthcheck_output 2>&1 && grep -q 'Sealed.*false' /vault/logs/healthcheck_output
      timeout: 10s
    secrets:
      - ansible_vault_password
    deploy:
      mode: replicated
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
        - traefik.http.routers.openbao.rule=Host(`openbao.admin.johnson.int`)
        - traefik.http.routers.openbao.service=openbao-svc
        # Add middleware to ensure X-Forwarded-Proto is set to https
        - traefik.http.services.openbao-svc.loadbalancer.server.port=8200
        - traefik.http.services.openbao-svc.loadbalancer.server.scheme=http
#        - traefik.http.services.openbao-svc.loadbalancer.server.scheme=https
        # Define the middleware for setting X-Forwarded-Proto
        - traefik.http.middlewares.openbao-forwarded-headers.headers.customrequestheaders.X-Forwarded-Proto=https
        - traefik.http.middlewares.openbao-forwarded-headers.headers.customrequestheaders.X-Forwarded-Host=openbao.admin.johnson.int
    volumes:
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
      - /home/container-user/docker/openbao/passwd:/etc/passwd:ro
      - /home/container-user/docker/openbao/group:/etc/group:ro
      - /home/container-user/docker/openbao/home:/vault

```


openbao/openbao.env
```ini
#
# Ansible managed
#

VAULT_ADDR=http://127.0.0.1:8200

OPENBAO_HOME_DIR=/vault
OPENBAO_CONFIG_DIR=/vault/config

#ENV_SECRETS_DEBUG=true
ENTRYPOINT_LOG_LEVEL=DEBUG

################################
## vaulted credentials
ANSIBLE_VAULT_PASSWORD=dksec://ansible_vault_password
```

openbao/home/config/local.json
```json
{
    "api_addr": "https://openbao.admin.johnson.int",
    "cluster_addr": "http://0.0.0.0:8201",
    "default_lease_ttl": "168h",
    "listener": {
        "tcp": {
            "address": "[::]:8200",
            "cluster_address": "[::]:8201",
            "tls_disable": true
        }
    },
    "log_level": "debug",
    "max_lease_ttl": "720h",
    "storage": {
        "file": {
            "path": "/vault/file"
        }
    },
    "ui": true,
    "audit": {
        "file": {
            "path": "/vault/logs/audit.log",
            "options": {
                "log_raw": true
            },
            "mode": "0777"
        }
    }
}
```

docker-entrypoint.sh
```shell
#!/bin/sh
set -e

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
        *) echo "$LOG_LEVEL_INFO" ;; # Default to INFO if an invalid level is provided
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

# In a non-root container, the user is already `openbao` due to the Dockerfile's `USER openbao` directive.
# Therefore, we no longer need to check for the 'openbao' user in /etc/passwd or use 'su-exec'.
# All commands will run as the 'openbao' user inherently.
_log INFO "Running as user: $(id -u), group: $(id -g)"

# Source env_secrets_expand.sh FIRST to ensure environment variables are set
if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
    _log DEBUG "Sourcing env_secrets_expand.sh"
    . /usr/local/bin/env_secrets_expand.sh
else
    _log ERROR "env_secrets_expand.sh not found"
    exit 1
fi

# Set defaults for OpenBao environment variables AFTER sourcing env_secrets_expand.sh
# Values from openbao.env (via env_secrets_expand.sh) will take precedence.
: "${OPENBAO_HOME_DIR:=/vault}"
: "${OPENBAO_CONFIG_DIR:=/vault/config}"
# Changed OPENBAO_INIT_FILE to OPENBAO_INIT_FILE_PREFIX as it's now a JSON file base name
: "${OPENBAO_INIT_FILE_PREFIX:=$OPENBAO_CONFIG_DIR/init}"
# INTERNAL_VAULT_ADDR is used by the entrypoint for health checks.
# It prioritizes VAULT_ADDR from the environment, falling back to local http.
: "${INTERNAL_VAULT_ADDR:=${VAULT_ADDR:-http://127.0.0.1:8200}}"

_log DEBUG "docker-entrypoint.sh started with args: $@"
_log DEBUG "Shell environment after initial setup:"
env | grep -v -i ANSIBLE_VAULT_PASSWORD >&2

_log DEBUG "Derived config settings:"
_log DEBUG "OPENBAO_HOME_DIR: "$OPENBAO_HOME_DIR""
_log DEBUG "OPENBAO_CONFIG_DIR: "$OPENBAA_CONFIG_DIR""
_log DEBUG "OPENBAO_INIT_FILE_PREFIX (for JSON data): "$OPENBAO_INIT_FILE_PREFIX""
_log DEBUG "INTERNAL_VAULT_ADDR for health checks: "$INTERNAL_VAULT_ADDR""
_log DEBUG "VAULT_ADDR for CLI commands: "$VAULT_ADDR""

# Ensure necessary directories exist.
# These mkdir commands will create directories with the permissions of the current user (openbao).
mkdir -p "$OPENBAO_HOME_DIR" "$OPENBAO_CONFIG_DIR" "/vault/file" "/vault/logs"

# --- Permission and Writability Validation for Critical Directories ---
# In a non-root container, we cannot change ownership or set permissions for existing host-mounted volumes.
# We must assume these directories are already correctly owned and writable by the 'openbao' user
# (UID and GID matching the USER directive in the Dockerfile).
# This function will only validate writability by the current user.
validate_directory_permissions() {
    local dir_path="$1"
    local dir_friendly_name="$2"
    _log DEBUG "Validating writability for "$dir_path" ("$dir_friendly_name")..."

    if [ ! -d "$dir_path" ]; then
        _log ERROR "Required directory "$dir_path" ("$dir_friendly_name") does not exist."
        _log ERROR "Please ensure the host directory mounted to "$dir_path" exists and is properly mounted."
        exit 1
    fi

    # Test writability for the current user (which is 'openbao' as per Dockerfile)
    local test_file="$dir_path/.test_write_$(date +%s%N)"
    touch "$test_file" 2>/dev/null
    if [ $? -ne 0 ]; then
        _log ERROR "Directory "$dir_path" ("$dir_friendly_name") is not writable by the current 'openbao' user (UID $(id -u), GID $(id -g))."
        _log ERROR "Please ensure the host directory mounted to "$dir_path" has write permissions for this user."
        exit 1
    fi
    rm -f "$test_file"
    _log DEBUG "Writability for "$dir_path" is correct."
}

validate_directory_permissions "/vault/file" "Storage Directory"
validate_directory_permissions "/vault/logs" "Audit Log Directory"
validate_directory_permissions "$OPENBAO_CONFIG_DIR" "Configuration Directory"
# --- End Permission and Writability Validation ---


# Handle BAO_LOCAL_CONFIG
if [ -n "$BAO_LOCAL_CONFIG" ]; then
    _log DEBUG "Writing BAO_LOCAL_CONFIG to "$OPENBAO_CONFIG_DIR/local.json""
    echo "$BAO_LOCAL_CONFIG" > "$OPENBAO_CONFIG_DIR/local.json"
    # File will be created with current user's (openbao) permissions and default umask
fi

# Check if config file exists
if [ ! -r "$OPENBAO_CONFIG_DIR/local.json" ]; then
    _log ERROR "Config file not found or not readable at "$OPENBAO_CONFIG_DIR/local.json""
    exit 1
fi
_log DEBUG "Contents of "$OPENBAO_CONFIG_DIR/local.json":"
cat "$OPENBAO_CONFIG_DIR/local.json" >&2 # Direct cat to stderr for debug logs

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
        # Curl will run as the current user (openbao)
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
    # bao status will run as the current user (openbao)
    VAULT_ADDR="${VAULT_ADDR}" bao status -format=json 2>/dev/null || true
}

check_initialized() {
    local status_output
    status_output=$(get_openbao_status_output)
    _log TRACE "check_initialized: Raw bao status output: $status_output"
    if echo "$status_output" | jq -e '.initialized == true' >/dev/null 2>&1; then
        _log DEBUG "check_initialized: jq returned true. OpenBao IS initialized."
        return 0
    fi
    _log DEBUG "check_initialized: jq returned false/error. OpenBao IS NOT initialized."
    return 1
}

check_sealed() {
    local status_output
    status_output=$(get_openbao_status_output)
    _log TRACE "check_sealed: Raw bao status output: $status_output"
    if echo "$status_output" | jq -e '.sealed == true' >/dev/null 2>&1; then
        _log DEBUG "check_sealed: jq returned true. OpenBao IS sealed."
        return 0
    fi
    _log DEBUG "check_sealed: jq returned false/error. OpenBao IS NOT sealed."
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

    local ansible_vault_password_file=$(mktemp)
    echo "$ANSIBLE_VAULT_PASSWORD" > "$ansible_vault_password_file"
    chmod 600 "$ansible_vault_password_file" # chmod by current user (openbao)

    # ansible-vault will run as the current user (openbao)
    if ! ansible-vault encrypt "$unencrypted_file" --output="$encrypted_file" --vault-password-file="$ansible_vault_password_file"; then
        _log ERROR "Failed to encrypt "$unencrypted_file"."
        rm -f "$ansible_vault_password_file"
        return 1
    fi
    rm -f "$ansible_vault_password_file"
    _log DEBUG "Successfully encrypted "$unencrypted_file" to "$encrypted_file""
    rm -f "$unencrypted_file" # Remove unencrypted file after successful encryption
    return 0
}

# Decrypts the encrypted init JSON file to a temporary file
decrypt_init_json_file() {
    local encrypted_file="$1"
    local temp_file="$2"
    if [ ! -r "$encrypted_file" ]; then
        _log ERROR "Encrypted init file not found or not readable at "$encrypted_file""
        return 1
    fi

    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot decrypt initialization file."
        return 1
    fi

    local ansible_vault_password_file=$(mktemp)
    echo "$ANSIBLE_VAULT_PASSWORD" > "$ansible_vault_password_file"
    chmod 600 "$ansible_vault_password_file" # chmod by current user (openbao)

    # ansible-vault will run as the current user (openbao)
    if ! ansible-vault decrypt "$encrypted_file" --output="$temp_file" --vault-password-file="$ansible_vault_password_file"; then
        _log ERROR "Failed to decrypt "$encrypted_file"."
        rm -f "$ansible_vault_password_file" "$temp_file"
        return 1
    fi
    rm -f "$ansible_vault_password_file"
    _log DEBUG "Successfully decrypted "$encrypted_file" to "$temp_file""
    return 0
}


# This function will generate an init.json file based on the *current* state of OpenBao
# (i.e., by performing a `bao operator init` dry-run or similar to get keys if possible,
# or simulating if no other option) and then encrypt it.
# IMPORTANT: This will NOT re-initialize OpenBao if it's already initialized.
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
            _log ERROR "OpenBao initialization command failed with unexpected exit code "$init_exit_code"."
            _log ERROR "Output from bao operator init: "$init_output""
            return 1
        fi
    fi

    # Check if the output actually contains the expected JSON structure
    if ! echo "$init_output" | jq -e '.unseal_keys_b64 and .root_token' >/dev/null 2>&1; then
        _log ERROR "OpenBao initialization output did not contain expected unseal_keys_b64 or root_token."
        _log ERROR "Full Output from bao operator init: "$init_output""
        _log ERROR "This can happen if OpenBao is already initialized and sealed, and 'bao operator init' cannot retrieve the keys."
        return 1
    fi

    _log DEBUG "Saving initialization details to "$unencrypted_init_json_file""
    echo "$init_output" | jq '{unseal_keys_b64: .unseal_keys_b64, root_token: .root_token}' > "$unencrypted_init_json_file"
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
    local unencrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json"
    local encrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"

    if [ -z "$ANSIBLE_VAULT_PASSWORD" ]; then
        _log ERROR "ANSIBLE_VAULT_PASSWORD is not set. Cannot initialize and encrypt OpenBao setup."
        _log ERROR "Please ensure ANSIBLE_VAULT_PASSWORD is provided in your environment (e.g., in openbao.env)."
        return 1
    fi

    _log INFO "Initializing OpenBao. Unencrypted init JSON file will be at: "$unencrypted_init_json_file""

    _log DEBUG "Running bao operator init"
    local init_output

    _log TRACE "Enabling set -x for bao operator init command."
    set -x # Enable verbose tracing for the next command

    # Use INTERNAL_VAULT_ADDR for CLI commands targeting the local server
    init_output=$(VAULT_ADDR="${INTERNAL_VAULT_ADDR}" bao operator init -key-shares=5 -key-threshold=3 -format=json 2>&1)
    local init_exit_code=$?
    set +x # Disable verbose tracing
    _log TRACE "Disabled set -x."

    if [ $init_exit_code -ne 0 ]; then
        _log ERROR "OpenBao initialization failed with exit code "$init_exit_code"."
        _log ERROR "Output from bao operator init: "$init_output""
        return 1
    fi

    # Check if the output actually contains the expected JSON structure
    if ! echo "$init_output" | jq -e '.unseal_keys_b64 and .root_token' >/dev/null 2>&1; then
        _log ERROR "OpenBao initialization output did not contain expected unseal_keys_b64 or root_token."
        _log ERROR "Full Output from bao operator init: "$init_output""
        return 1
    fi

    _log DEBUG "Saving initialization details to "$unencrypted_init_json_file""
    echo "$init_output" | jq '{unseal_keys_b64: .unseal_keys_b64, root_token: .root_token}' > "$unencrypted_init_json_file"
    chmod 0600 "$unencrypted_init_json_file" # chmod by current user (openbao)

    _log INFO "OpenBao initialized successfully."

    if encrypt_init_json_file "$unencrypted_init_json_file" "$encrypted_init_json_file"; then
        _log INFO "OpenBao initialization details encrypted to "$encrypted_init_json_file""
        if [ ! -f "$encrypted_init_json_file" ]; then
            _log ERROR "Encryption reported success, but file "$encrypted_init_json_file" was not found."
            return 1
        fi
        return 0
    else
        _log ERROR "Initialization succeeded, but encryption failed."
        return 1
    fi
}

unseal_openbao() {
    local unseal_key="$1"
    _log DEBUG "Attempting to unseal OpenBao with key: [redacted]"
    local unseal_output
    # bao operator unseal will run as the current user (openbao)
    unseal_output=$(VAULT_ADDR="${VAULT_ADDR}" bao operator unseal "$unseal_key" 2>&1)
    local unseal_exit=$?

    if [ $unseal_exit -eq 0 ]; then
        _log DEBUG "OpenBao successfully unsealed."
        return 0
    else
        _log ERROR "Failed to unseal OpenBao. Exit code: "$unseal_exit"."
        _log ERROR "Output: "$unseal_output""
        return 1
    fi
}

auto_unseal() {
    local encrypted_init_json_file="${OPENBAO_INIT_FILE_PREFIX}.json.enc"
    local temp_decrypted_json_file="/tmp/openbao_init_decrypted.json"

    if [ ! -r "$encrypted_init_json_file" ]; then
        _log ERROR "Encrypted init JSON file not found at "$encrypted_init_json_file". Cannot auto-unseal."
        return 1
    fi
    _log DEBUG "Found encrypted init JSON file at "$encrypted_init_json_file", attempting auto-unseal."

    if ! decrypt_init_json_file "$encrypted_init_json_file" "$temp_decrypted_json_file"; then
        _log ERROR "Failed to decrypt init JSON file for auto-unseal."
        rm -f "$temp_decrypted_json_file"
        return 1
    fi

    local unseal_keys
    unseal_keys=$(jq -r '.unseal_keys_b64[]' < "$temp_decrypted_json_file")

    local root_token
    root_token=$(jq -r '.root_token' < "$temp_decrypted_json_file")
    _log DEBUG "Root token found for reference (not used for unseal): [redacted]"

    rm -f "$temp_decrypted_json_file" # Clean up decrypted file immediately

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

    _log INFO "Background init/unseal process completed successfully."
}

run_server() {
    local server_args="-config=$OPENBAO_CONFIG_DIR/local.json"

    _log DEBUG "Execing OpenBao server as PID 1 with args: $server_args"

    background_init_and_unseal &

    # bao server will run as the current user (openbao)
    exec bao server $server_args
}

if [ $# -eq 0 ]; then
    run_server
else
    # Any other command will run as the current user (openbao)
    exec "$@"
fi

```

Test Run includes:
1) initialization and encrypting token and keys and
2) remove container and restart to test decrypting encrypted keys and auto unsealing vault

```shell
root@control01:[docker]$ dockeservice rm docker_stack_openbaoth
docker_stack_openbao
root@control01:[docker]$ rm -fr /home/container-user/docker/openbao/home/file/*
root@control01:[docker]$ rm -fr /home/container-user/docker/openbao/home/logs/*
root@control01:[docker]$ rm -fr /home/container-user/docker/openbao/home/config/init*
root@control01:[docker]$ 
root@control01:[docker]$ docker stack deploy -c docker-compose.yml docker_stack --with-registry-auth
root@control01:[docker]$ docker service ps docker_stack_openbao
ID             NAME                     IMAGE                                           NODE        DESIRED STATE   CURRENT STATE            ERROR     PORTS
b45hyv3j604z   docker_stack_openbao.1   media.johnson.int:5000/openbao-ansible:latest   control01   Running         Starting 5 seconds ago             
root@control01:[docker]$ 
root@control01:[docker]$ docker service logs -f docker_stack_openbao
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Running as user: 1102, group: 1102
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Sourcing env_secrets_expand.sh
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: docker-entrypoint.sh started with args: 
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Shell environment after initial setup:
docker_stack_openbao.1.b45hyv3j604z@control01    | ENTRYPOINT_LOG_LEVEL=DEBUG
docker_stack_openbao.1.b45hyv3j604z@control01    | HOSTNAME=b19b091edff8
docker_stack_openbao.1.b45hyv3j604z@control01    | VAULT_ADDR=http://127.0.0.1:8200
docker_stack_openbao.1.b45hyv3j604z@control01    | SHLVL=1
docker_stack_openbao.1.b45hyv3j604z@control01    | HOME=/vault
docker_stack_openbao.1.b45hyv3j604z@control01    | VERSION=
docker_stack_openbao.1.b45hyv3j604z@control01    | NAME=openbao
docker_stack_openbao.1.b45hyv3j604z@control01    | OPENBAO_CONFIG_DIR=/vault/config
docker_stack_openbao.1.b45hyv3j604z@control01    | PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
docker_stack_openbao.1.b45hyv3j604z@control01    | OPENBAO_HOME_DIR=/vault
docker_stack_openbao.1.b45hyv3j604z@control01    | PWD=/
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Derived config settings:
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OPENBAO_HOME_DIR: /vault
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OPENBAO_CONFIG_DIR: 
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OPENBAO_INIT_FILE_PREFIX (for JSON data): /vault/config/init
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: INTERNAL_VAULT_ADDR for health checks: http://127.0.0.1:8200
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: VAULT_ADDR for CLI commands: http://127.0.0.1:8200
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Validating writability for /vault/file (Storage
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Writability for /vault/file is correct.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Validating writability for /vault/logs (Audit
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Writability for /vault/logs is correct.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Validating writability for /vault/config (Configuration
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Writability for /vault/config is correct.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Contents of /vault/config/local.json:
docker_stack_openbao.1.b45hyv3j604z@control01    | {
docker_stack_openbao.1.b45hyv3j604z@control01    |     "api_addr": "https://openbao.admin.johnson.int",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "cluster_addr": "http://0.0.0.0:8201",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "default_lease_ttl": "168h",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "listener": {
docker_stack_openbao.1.b45hyv3j604z@control01    |         "tcp": {
docker_stack_openbao.1.b45hyv3j604z@control01    |             "address": "[::]:8200",
docker_stack_openbao.1.b45hyv3j604z@control01    |             "cluster_address": "[::]:8201",
docker_stack_openbao.1.b45hyv3j604z@control01    |             "tls_disable": true
docker_stack_openbao.1.b45hyv3j604z@control01    |         }
docker_stack_openbao.1.b45hyv3j604z@control01    |     },
docker_stack_openbao.1.b45hyv3j604z@control01    |     "log_level": "debug",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "max_lease_ttl": "720h",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "storage": {
docker_stack_openbao.1.b45hyv3j604z@control01    |         "file": {
docker_stack_openbao.1.b45hyv3j604z@control01    |             "path": "/vault/file"
docker_stack_openbao.1.b45hyv3j604z@control01    |         }
docker_stack_openbao.1.b45hyv3j604z@control01    |     },
docker_stack_openbao.1.b45hyv3j604z@control01    |     "ui": true,
docker_stack_openbao.1.b45hyv3j604z@control01    |     "audit": {
docker_stack_openbao.1.b45hyv3j604z@control01    |         "file": {
docker_stack_openbao.1.b45hyv3j604z@control01    |             "path": "/vault/logs/audit.log",
docker_stack_openbao.1.b45hyv3j604z@control01    |             "options": {
docker_stack_openbao.1.b45hyv3j604z@control01    |                 "log_raw": true
docker_stack_openbao.1.b45hyv3j604z@control01    |             },
docker_stack_openbao.1.b45hyv3j604z@control01    |             "mode": "0777"
docker_stack_openbao.1.b45hyv3j604z@control01    |         }
docker_stack_openbao.1.b45hyv3j604z@control01    |     }
docker_stack_openbao.1.b45hyv3j604z@control01    | }
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Execing OpenBao server as PID 1 with args: -config=/vault/config/local.json
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Background init/unseal process started.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Waiting for OpenBao server to become responsive...
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: wait_for_openbao: Checking health at http://127.0.0.1:8200/v1/sys/health
docker_stack_openbao.1.b45hyv3j604z@control01    | ==> OpenBao server configuration:
docker_stack_openbao.1.b45hyv3j604z@control01    | 
docker_stack_openbao.1.b45hyv3j604z@control01    | Administrative Namespace: 
docker_stack_openbao.1.b45hyv3j604z@control01    |              Api Address: https://openbao.admin.johnson.int
docker_stack_openbao.1.b45hyv3j604z@control01    |                      Cgo: disabled
docker_stack_openbao.1.b45hyv3j604z@control01    |          Cluster Address: https://openbao.admin.johnson.int:444
docker_stack_openbao.1.b45hyv3j604z@control01    |    Environment Variables: ANSIBLE_VAULT_PASSWORD, ENTRYPOINT_LOG_LEVEL, HOME, HOSTNAME, NAME, OPENBAO_CONFIG_DIR, OPENBAO_HOME_DIR, PATH, PWD, SHLVL, VAULT_ADDR, VERSION
docker_stack_openbao.1.b45hyv3j604z@control01    |               Go Version: go1.24.6
docker_stack_openbao.1.b45hyv3j604z@control01    |               Listener 1: tcp (addr: "[::]:8200", cluster address: "[::]:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
docker_stack_openbao.1.b45hyv3j604z@control01    |                Log Level: debug
docker_stack_openbao.1.b45hyv3j604z@control01    |            Recovery Mode: false
docker_stack_openbao.1.b45hyv3j604z@control01    |                  Storage: file
docker_stack_openbao.1.b45hyv3j604z@control01    |                  Version: OpenBao v2.3.2, built 2025-08-08T04:05:27Z
docker_stack_openbao.1.b45hyv3j604z@control01    |              Version Sha: b1a68f558c89d18d38fbb8675bb6fc1d90b71e98
docker_stack_openbao.1.b45hyv3j604z@control01    | 
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.134-0400 [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
docker_stack_openbao.1.b45hyv3j604z@control01    | ==> OpenBao server started! Log data will stream in below:
docker_stack_openbao.1.b45hyv3j604z@control01    | 
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.134-0400 [DEBUG] core: set config: sanitized config="{\"administrative_namespace_path\":\"\",\"allow_audit_log_prefixing\":false,\"api_addr\":\"https://openbao.admin.johnson.int\",\"cache_size\":0,\"cluster_addr\":\"http://0.0.0.0:8201\",\"cluster_cipher_suites\":\"\",\"cluster_name\":\"\",\"default_lease_ttl\":604800,\"default_max_request_duration\":0,\"detect_deadlocks\":\"\",\"disable_cache\":false,\"disable_clustering\":false,\"disable_indexing\":false,\"disable_performance_standby\":false,\"disable_printable_check\":false,\"disable_sealwrap\":false,\"disable_sentinel_trace\":false,\"enable_response_header_hostname\":false,\"enable_response_header_raft_node_id\":false,\"enable_ui\":true,\"imprecise_lease_role_tracking\":false,\"introspection_endpoint\":false,\"listeners\":[{\"config\":{\"address\":\"[::]:8200\",\"cluster_address\":\"[::]:8201\",\"tls_disable\":true},\"type\":\"tcp\"}],\"log_format\":\"\",\"log_level\":\"debug\",\"log_requests_level\":\"\",\"max_lease_ttl\":2592000,\"pid_file\":\"\",\"plugin_directory\":\"\",\"plugin_file_permissions\":0,\"plugin_file_uid\":0,\"raw_storage_endpoint\":false,\"seals\":[{\"disabled\":false,\"type\":\"shamir\"}],\"storage\":{\"cluster_addr\":\"http://0.0.0.0:8201\",\"disable_clustering\":false,\"redirect_addr\":\"https://openbao.admin.johnson.int\",\"type\":\"file\"},\"unsafe_allow_api_audit_creation\":false,\"unsafe_cross_namespace_identity\":false}"
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.134-0400 [DEBUG] storage.cache: creating LRU cache: size=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.135-0400 [INFO]  core: Initializing version history cache for core
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.135-0400 [DEBUG] cluster listener addresses synthesized: cluster_addresses=[[::]:8201]
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.136-0400 [DEBUG] would have sent systemd notification (systemd not present): notification=READY=1
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:10.928-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | *   Trying 127.0.0.1:8200...
docker_stack_openbao.1.b45hyv3j604z@control01    | * Connected to 127.0.0.1 (127.0.0.1) port 8200
docker_stack_openbao.1.b45hyv3j604z@control01    | * using HTTP/1.x
docker_stack_openbao.1.b45hyv3j604z@control01    | > GET /v1/sys/health HTTP/1.1
docker_stack_openbao.1.b45hyv3j604z@control01    | > Host: 127.0.0.1:8200
docker_stack_openbao.1.b45hyv3j604z@control01    | > User-Agent: curl/8.12.1
docker_stack_openbao.1.b45hyv3j604z@control01    | > Accept: */*
docker_stack_openbao.1.b45hyv3j604z@control01    | > 
docker_stack_openbao.1.b45hyv3j604z@control01    | * Request completely sent off
docker_stack_openbao.1.b45hyv3j604z@control01    | < HTTP/1.1 501 Not Implemented
docker_stack_openbao.1.b45hyv3j604z@control01    | < Cache-Control: no-store
docker_stack_openbao.1.b45hyv3j604z@control01    | < Content-Type: application/json
docker_stack_openbao.1.b45hyv3j604z@control01    | < Strict-Transport-Security: max-age=31536000; includeSubDomains
docker_stack_openbao.1.b45hyv3j604z@control01    | < Date: Fri, 29 Aug 2025 20:22:10 GMT
docker_stack_openbao.1.b45hyv3j604z@control01    | < Content-Length: 199
docker_stack_openbao.1.b45hyv3j604z@control01    | < 
docker_stack_openbao.1.b45hyv3j604z@control01    | { [199 bytes data]
docker_stack_openbao.1.b45hyv3j604z@control01    | * Connection #0 to host 127.0.0.1 left intact
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: wait_for_openbao: Received HTTP code: 501
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao server is responsive.
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.405-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.405-0400 [INFO]  core: seal configuration missing, not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: check_initialized: jq returned false/error. OpenBao IS NOT initialized.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao API reports NOT initialized.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Attempting OpenBao initialization and encryption...
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Initializing OpenBao. Unencrypted init JSON file will be at: /vault/config/init.json
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Running bao operator init
docker_stack_openbao.1.b45hyv3j604z@control01    | + VAULT_ADDR=http://127.0.0.1:8200 bao operator init '-key-shares=5' '-key-threshold=3' '-format=json'
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.541-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.541-0400 [INFO]  core: seal configuration missing, not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.542-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.544-0400 [INFO]  core: security barrier initialized: stored=1 shares=5 threshold=3
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: cluster name not found/set, generating new
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: cluster name set: name=vault-cluster-3d3feb5a
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: cluster ID not found, generating new
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: cluster ID set: id=6db8dc44-4bd8-9154-aa2c-0bcf8a6f56f4
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [INFO]  core: post-unseal setup starting
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: done clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.545-0400 [DEBUG] core: persisting feature flags
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.556-0400 [INFO]  core: loaded wrapping token key
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.556-0400 [INFO]  core: successfully setup plugin catalog: plugin-directory=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.557-0400 [INFO]  core: no mounts in legacy mount table; adding default mount table
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.559-0400 [INFO]  core: successfully mounted: type=cubbyhole version="v2.3.2+builtin.bao" path=cubbyhole/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.559-0400 [INFO]  core: successfully mounted: type=system version="v2.3.2+builtin.bao" path=sys/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.560-0400 [INFO]  core: successfully mounted: type=identity version="v2.3.2+builtin.bao" path=identity/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.561-0400 [INFO]  core: no mounts in legacy auth table; adding default mount table
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.565-0400 [INFO]  core: successfully mounted: type=token version="v2.3.2+builtin.bao" path=token/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.565-0400 [INFO]  rollback: Starting the rollback manager with 256 workers
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.566-0400 [INFO]  rollback: starting rollback manager
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.566-0400 [INFO]  core: restoring leases
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.566-0400 [DEBUG] expiration: collecting leases
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.566-0400 [DEBUG] expiration: leases collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.566-0400 [INFO]  expiration: lease restore complete
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [DEBUG] identity: loading entities: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [DEBUG] identity: entities collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [INFO]  identity: entities restored
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [DEBUG] identity: identity loading groups: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [DEBUG] identity: groups collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [INFO]  identity: groups restored
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [DEBUG] identity: identity loading OIDC clients: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [INFO]  core: usage gauge collection is disabled
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.567-0400 [INFO]  core: Recorded vault version: vault version=2.3.2 upgrade time="2025-08-29 20:22:11.567623654 +0000 UTC" build date=2025-08-08T04:05:27Z
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.568-0400 [DEBUG] secrets.identity.identity_ae2f8af1: wrote OIDC default provider
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.568-0400 [DEBUG] secrets.identity.identity_ae2f8af1: wrote OIDC default key
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.568-0400 [DEBUG] secrets.identity.identity_ae2f8af1: wrote OIDC allow_all assignment
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.568-0400 [INFO]  core: post-unseal setup complete
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [INFO]  core: root token generated
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [INFO]  core: pre-seal teardown starting
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [DEBUG] expiration: stop triggered
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [DEBUG] expiration: finished stopping
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [INFO]  rollback: stopping rollback manager
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:11.569-0400 [INFO]  core: pre-seal teardown complete
docker_stack_openbao.1.b45hyv3j604z@control01    | + init_output='{
docker_stack_openbao.1.b45hyv3j604z@control01    |   "unseal_keys_b64": [
docker_stack_openbao.1.b45hyv3j604z@control01    |     "wqPn4d19H74XuQ4rUCoQbI+hvYYaCut4Lkt0r6rO92eT",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "y0/JCHrD2IXGNwn4rTRmQGMNN9IijRxckIwfKLceP1bf",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "C8ujEB6hYnGnRf5MDCxsv0ACSXje3opxwcHCjcoTHxlk",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "e76+Hs1GEbcf8EWx7hGiZrz50hASUQmqIVH+/irETyMp",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "fTB3WO5lKi+ln7M+6FZcEaJkkBg3u/my4hUppnWaK2uc"
docker_stack_openbao.1.b45hyv3j604z@control01    |   ],
docker_stack_openbao.1.b45hyv3j604z@control01    |   "unseal_keys_hex": [
docker_stack_openbao.1.b45hyv3j604z@control01    |     "c2a3e7e1dd7d1fbe17b90e2b502a106c8fa1bd861a0aeb782e4b74afaacef76793",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "cb4fc9087ac3d885c63709f8ad346640630d37d2228d1c5c908c1f28b71e3f56df",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "0bcba3101ea16271a745fe4c0c2c6cbf40024978dede8a71c1c1c28dca131f1964",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "7bbebe1ecd4611b71ff045b1ee11a266bcf9d210125109aa2151fefe2ac44f2329",
docker_stack_openbao.1.b45hyv3j604z@control01    |     "7d307758ee652a2fa59fb33ee8565c11a264901837bbf9b2e21529a6759a2b6b9c"
docker_stack_openbao.1.b45hyv3j604z@control01    |   ],
docker_stack_openbao.1.b45hyv3j604z@control01    |   "unseal_shares": 5,
docker_stack_openbao.1.b45hyv3j604z@control01    |   "unseal_threshold": 3,
docker_stack_openbao.1.b45hyv3j604z@control01    |   "recovery_keys_b64": [],
docker_stack_openbao.1.b45hyv3j604z@control01    |   "recovery_keys_hex": [],
docker_stack_openbao.1.b45hyv3j604z@control01    |   "recovery_keys_shares": 0,
docker_stack_openbao.1.b45hyv3j604z@control01    |   "recovery_keys_threshold": 0,
docker_stack_openbao.1.b45hyv3j604z@control01    |   "root_token": "s.zf5p64xppGVxG21LX6PSqHTe"
docker_stack_openbao.1.b45hyv3j604z@control01    | }'
docker_stack_openbao.1.b45hyv3j604z@control01    | + local 'init_exit_code=0'
docker_stack_openbao.1.b45hyv3j604z@control01    | + set +x
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Saving initialization details to /vault/config/init.json
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao initialized successfully.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Encrypting /vault/config/init.json to /vault/config/init.json.enc with ansible-vault
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Successfully encrypted /vault/config/init.json to /vault/config/init.json.enc
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao initialization details encrypted to /vault/config/init.json.enc
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao initialization and encryption completed successfully.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Checking OpenBao sealed status...
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: check_sealed: jq returned true. OpenBao IS sealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: OpenBao IS sealed. Attempting auto-unseal...
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Found encrypted init JSON file at /vault/config/init.json.enc, attempting auto-unseal.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Successfully decrypted /vault/config/init.json.enc to /tmp/openbao_init_decrypted.json
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Root token found for reference (not used for unseal): [redacted]
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.502-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.502-0400 [DEBUG] core: cannot unseal, not enough keys: keys=1 threshold=3 nonce=40acbdd5-e293-eb6e-85d2-b83fc0ed2d00
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.630-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.630-0400 [DEBUG] core: cannot unseal, not enough keys: keys=2 threshold=3 nonce=40acbdd5-e293-eb6e-85d2-b83fc0ed2d00
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.756-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [DEBUG] core: starting cluster listeners
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [INFO]  core.cluster-listener.tcp: starting listener: listener_address=[::]:8201
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [INFO]  core.cluster-listener: serving cluster requests: cluster_listen_address=[::]:8201
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [INFO]  core: post-unseal setup starting
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [DEBUG] core: clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [DEBUG] core: done clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.757-0400 [DEBUG] core: persisting feature flags
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.758-0400 [INFO]  core: loaded wrapping token key
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.758-0400 [INFO]  core: successfully setup plugin catalog: plugin-directory=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.759-0400 [INFO]  core: successfully mounted: type=system version="v2.3.2+builtin.bao" path=sys/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.760-0400 [INFO]  core: successfully mounted: type=identity version="v2.3.2+builtin.bao" path=identity/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.760-0400 [INFO]  core: successfully mounted: type=cubbyhole version="v2.3.2+builtin.bao" path=cubbyhole/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.762-0400 [INFO]  core: successfully mounted: type=token version="v2.3.2+builtin.bao" path=token/ namespace="ID: root. Path: "
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.762-0400 [INFO]  rollback: Starting the rollback manager with 256 workers
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.762-0400 [INFO]  rollback: starting rollback manager
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [INFO]  core: restoring leases
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [DEBUG] expiration: collecting leases
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [DEBUG] expiration: leases collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [DEBUG] identity: loading entities: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [INFO]  expiration: lease restore complete
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.763-0400 [DEBUG] identity: entities collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [INFO]  identity: entities restored
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] identity: identity loading groups: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] identity: groups collected: num_existing=0
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [INFO]  identity: groups restored
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] identity: identity loading OIDC clients: namespace=""
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] core: request forwarding setup function
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] core: clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] core: done clearing forwarding clients
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] core: request forwarding not setup
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [DEBUG] core: leaving request forwarding setup function
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.764-0400 [INFO]  core: usage gauge collection is disabled
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.765-0400 [INFO]  core: post-unseal setup complete
docker_stack_openbao.1.b45hyv3j604z@control01    | 2025-08-29T16:22:43.765-0400 [INFO]  core: vault is unsealed
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: Reached threshold of 3 unseal keys, stopping.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint DEBUG: check_sealed: jq returned false/error. OpenBao IS NOT sealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Auto-unseal process completed, applied 0 keys. OpenBao successfully unsealed.
docker_stack_openbao.1.b45hyv3j604z@control01    | Entrypoint INFO: Background init/unseal process completed successfully.

^Croot@control01:[docker]$ 
root@control01:[docker]$ ll openbao/home/file/
total 20
drwxr-x--- 5 container-user container-user 4096 Aug 29 16:22 ./
drwxr-x--- 8 container-user container-user 4096 Aug 29 11:26 ../
drwx------ 6 container-user container-user 4096 Aug 29 16:22 core/
drwx------ 3 container-user container-user 4096 Aug 29 16:22 logical/
drwx------ 4 container-user container-user 4096 Aug 29 16:22 sys/
root@control01:[docker]$ ll openbao/home/config/
total 24
drwxr-x--- 2 container-user container-user 4096 Aug 29 16:22 ./
drwxr-x--- 8 container-user container-user 4096 Aug 29 11:26 ../
-rw------- 1 container-user container-user 1715 Aug 29 16:22 init.json.enc
-rw------- 1 container-user container-user  647 Aug 29 00:18 local.good.json
-rw------- 1 container-user container-user  647 Aug 29 10:48 local.json
-rw-r--r-- 1 container-user container-user   31 Aug 29 09:39 .vault_pass
root@control01:[docker]$ 
root@control01:[docker]$ docker service rm docker_stack_openbao
docker_stack_openbao
root@control01:[docker]$ 
root@control01:[docker]$ docker stack deploy -c docker-compose.yml docker_stack --with-registry-auth
root@control01:[docker]$ 
root@control01:[docker]$ docker service logs -f docker_stack_openbao
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Running as user: 1102, group: 1102
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Sourcing env_secrets_expand.sh
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: docker-entrypoint.sh started with args: 
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Shell environment after initial setup:
docker_stack_openbao.1.qex1zb67hx05@control01    | ENTRYPOINT_LOG_LEVEL=DEBUG
docker_stack_openbao.1.qex1zb67hx05@control01    | HOSTNAME=107b43417135
docker_stack_openbao.1.qex1zb67hx05@control01    | VAULT_ADDR=http://127.0.0.1:8200
docker_stack_openbao.1.qex1zb67hx05@control01    | SHLVL=1
docker_stack_openbao.1.qex1zb67hx05@control01    | HOME=/vault
docker_stack_openbao.1.qex1zb67hx05@control01    | VERSION=
docker_stack_openbao.1.qex1zb67hx05@control01    | NAME=openbao
docker_stack_openbao.1.qex1zb67hx05@control01    | OPENBAO_CONFIG_DIR=/vault/config
docker_stack_openbao.1.qex1zb67hx05@control01    | PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
docker_stack_openbao.1.qex1zb67hx05@control01    | OPENBAO_HOME_DIR=/vault
docker_stack_openbao.1.qex1zb67hx05@control01    | PWD=/
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Derived config settings:
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OPENBAO_HOME_DIR: /vault
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OPENBAO_CONFIG_DIR: 
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OPENBAO_INIT_FILE_PREFIX (for JSON data): /vault/config/init
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: INTERNAL_VAULT_ADDR for health checks: http://127.0.0.1:8200
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: VAULT_ADDR for CLI commands: http://127.0.0.1:8200
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Validating writability for /vault/file (Storage
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Writability for /vault/file is correct.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Validating writability for /vault/logs (Audit
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Writability for /vault/logs is correct.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Validating writability for /vault/config (Configuration
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Writability for /vault/config is correct.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Contents of /vault/config/local.json:
docker_stack_openbao.1.qex1zb67hx05@control01    | {
docker_stack_openbao.1.qex1zb67hx05@control01    |     "api_addr": "https://openbao.admin.johnson.int",
docker_stack_openbao.1.qex1zb67hx05@control01    |     "cluster_addr": "http://0.0.0.0:8201",
docker_stack_openbao.1.qex1zb67hx05@control01    |     "default_lease_ttl": "168h",
docker_stack_openbao.1.qex1zb67hx05@control01    |     "listener": {
docker_stack_openbao.1.qex1zb67hx05@control01    |         "tcp": {
docker_stack_openbao.1.qex1zb67hx05@control01    |             "address": "[::]:8200",
docker_stack_openbao.1.qex1zb67hx05@control01    |             "cluster_address": "[::]:8201",
docker_stack_openbao.1.qex1zb67hx05@control01    |             "tls_disable": true
docker_stack_openbao.1.qex1zb67hx05@control01    |         }
docker_stack_openbao.1.qex1zb67hx05@control01    |     },
docker_stack_openbao.1.qex1zb67hx05@control01    |     "log_level": "debug",
docker_stack_openbao.1.qex1zb67hx05@control01    |     "max_lease_ttl": "720h",
docker_stack_openbao.1.qex1zb67hx05@control01    |     "storage": {
docker_stack_openbao.1.qex1zb67hx05@control01    |         "file": {
docker_stack_openbao.1.qex1zb67hx05@control01    |             "path": "/vault/file"
docker_stack_openbao.1.qex1zb67hx05@control01    |         }
docker_stack_openbao.1.qex1zb67hx05@control01    |     },
docker_stack_openbao.1.qex1zb67hx05@control01    |     "ui": true,
docker_stack_openbao.1.qex1zb67hx05@control01    |     "audit": {
docker_stack_openbao.1.qex1zb67hx05@control01    |         "file": {
docker_stack_openbao.1.qex1zb67hx05@control01    |             "path": "/vault/logs/audit.log",
docker_stack_openbao.1.qex1zb67hx05@control01    |             "options": {
docker_stack_openbao.1.qex1zb67hx05@control01    |                 "log_raw": true
docker_stack_openbao.1.qex1zb67hx05@control01    |             },
docker_stack_openbao.1.qex1zb67hx05@control01    |             "mode": "0777"
docker_stack_openbao.1.qex1zb67hx05@control01    |         }
docker_stack_openbao.1.qex1zb67hx05@control01    |     }
docker_stack_openbao.1.qex1zb67hx05@control01    | }
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Execing OpenBao server as PID 1 with args: -config=/vault/config/local.json
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Background init/unseal process started.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Waiting for OpenBao server to become responsive...
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: wait_for_openbao: Checking health at http://127.0.0.1:8200/v1/sys/health
docker_stack_openbao.1.qex1zb67hx05@control01    | ==> OpenBao server configuration:
docker_stack_openbao.1.qex1zb67hx05@control01    | 
docker_stack_openbao.1.qex1zb67hx05@control01    | Administrative Namespace: 
docker_stack_openbao.1.qex1zb67hx05@control01    |              Api Address: https://openbao.admin.johnson.int
docker_stack_openbao.1.qex1zb67hx05@control01    |                      Cgo: disabled
docker_stack_openbao.1.qex1zb67hx05@control01    |          Cluster Address: https://openbao.admin.johnson.int:444
docker_stack_openbao.1.qex1zb67hx05@control01    |    Environment Variables: ANSIBLE_VAULT_PASSWORD, ENTRYPOINT_LOG_LEVEL, HOME, HOSTNAME, NAME, OPENBAO_CONFIG_DIR, OPENBAO_HOME_DIR, PATH, PWD, SHLVL, VAULT_ADDR, VERSION
docker_stack_openbao.1.qex1zb67hx05@control01    |               Go Version: go1.24.6
docker_stack_openbao.1.qex1zb67hx05@control01    |               Listener 1: tcp (addr: "[::]:8200", cluster address: "[::]:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
docker_stack_openbao.1.qex1zb67hx05@control01    |                Log Level: debug
docker_stack_openbao.1.qex1zb67hx05@control01    |            Recovery Mode: false
docker_stack_openbao.1.qex1zb67hx05@control01    |                  Storage: file
docker_stack_openbao.1.qex1zb67hx05@control01    |                  Version: OpenBao v2.3.2, built 2025-08-08T04:05:27Z
docker_stack_openbao.1.qex1zb67hx05@control01    |              Version Sha: b1a68f558c89d18d38fbb8675bb6fc1d90b71e98
docker_stack_openbao.1.qex1zb67hx05@control01    | 
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:28.984-0400 [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:28.985-0400 [DEBUG] core: set config: sanitized config="{\"administrative_namespace_path\":\"\",\"allow_audit_log_prefixing\":false,\"api_addr\":\"https://openbao.admin.johnson.int\",\"cache_size\":0,\"cluster_addr\":\"http://0.0.0.0:8201\",\"cluster_cipher_suites\":\"\",\"cluster_name\":\"\",\"default_lease_ttl\":604800,\"default_max_request_duration\":0,\"detect_deadlocks\":\"\",\"disable_cache\":false,\"disable_clustering\":false,\"disable_indexing\":false,\"disable_performance_standby\":false,\"disable_printable_check\":false,\"disable_sealwrap\":false,\"disable_sentinel_trace\":false,\"enable_response_header_hostname\":false,\"enable_response_header_raft_node_id\":false,\"enable_ui\":true,\"imprecise_lease_role_tracking\":false,\"introspection_endpoint\":false,\"listeners\":[{\"config\":{\"address\":\"[::]:8200\",\"cluster_address\":\"[::]:8201\",\"tls_disable\":true},\"type\":\"tcp\"}],\"log_format\":\"\",\"log_level\":\"debug\",\"log_requests_level\":\"\",\"max_lease_ttl\":2592000,\"pid_file\":\"\",\"plugin_directory\":\"\",\"plugin_file_permissions\":0,\"plugin_file_uid\":0,\"raw_storage_endpoint\":false,\"seals\":[{\"disabled\":false,\"type\":\"shamir\"}],\"storage\":{\"cluster_addr\":\"http://0.0.0.0:8201\",\"disable_clustering\":false,\"redirect_addr\":\"https://openbao.admin.johnson.int\",\"type\":\"file\"},\"unsafe_allow_api_audit_creation\":false,\"unsafe_cross_namespace_identity\":false}"
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:28.985-0400 [DEBUG] storage.cache: creating LRU cache: size=0
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:29.132-0400 [INFO]  core: Initializing version history cache for core
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:29.132-0400 [DEBUG] cluster listener addresses synthesized: cluster_addresses=[[::]:8201]
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:24:29.133-0400 [DEBUG] would have sent systemd notification (systemd not present): notification=READY=1
docker_stack_openbao.1.qex1zb67hx05@control01    | ==> OpenBao server started! Log data will stream in below:
docker_stack_openbao.1.qex1zb67hx05@control01    | 
docker_stack_openbao.1.qex1zb67hx05@control01    | *   Trying 127.0.0.1:8200...
docker_stack_openbao.1.qex1zb67hx05@control01    | * Connected to 127.0.0.1 (127.0.0.1) port 8200
docker_stack_openbao.1.qex1zb67hx05@control01    | * using HTTP/1.x
docker_stack_openbao.1.qex1zb67hx05@control01    | > GET /v1/sys/health HTTP/1.1
docker_stack_openbao.1.qex1zb67hx05@control01    | > Host: 127.0.0.1:8200
docker_stack_openbao.1.qex1zb67hx05@control01    | > User-Agent: curl/8.12.1
docker_stack_openbao.1.qex1zb67hx05@control01    | > Accept: */*
docker_stack_openbao.1.qex1zb67hx05@control01    | > 
docker_stack_openbao.1.qex1zb67hx05@control01    | * Request completely sent off
docker_stack_openbao.1.qex1zb67hx05@control01    | < HTTP/1.1 503 Service Unavailable
docker_stack_openbao.1.qex1zb67hx05@control01    | < Cache-Control: no-store
docker_stack_openbao.1.qex1zb67hx05@control01    | < Content-Type: application/json
docker_stack_openbao.1.qex1zb67hx05@control01    | < Strict-Transport-Security: max-age=31536000; includeSubDomains
docker_stack_openbao.1.qex1zb67hx05@control01    | < Date: Fri, 29 Aug 2025 20:24:29 GMT
docker_stack_openbao.1.qex1zb67hx05@control01    | < Content-Length: 198
docker_stack_openbao.1.qex1zb67hx05@control01    | < 
docker_stack_openbao.1.qex1zb67hx05@control01    | { [198 bytes data]
docker_stack_openbao.1.qex1zb67hx05@control01    | * Connection #0 to host 127.0.0.1 left intact
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: wait_for_openbao: Received HTTP code: 503
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: OpenBao server is responsive.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: check_initialized: jq returned true. OpenBao IS initialized.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: OpenBao API reports already initialized.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Encrypted initialization file found at /vault/config/init.json.enc.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Checking OpenBao sealed status...
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: check_sealed: jq returned true. OpenBao IS sealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: OpenBao IS sealed. Attempting auto-unseal...
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Found encrypted init JSON file at /vault/config/init.json.enc, attempting auto-unseal.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Successfully decrypted /vault/config/init.json.enc to /tmp/openbao_init_decrypted.json
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Root token found for reference (not used for unseal): [redacted]
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:26.964-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:26.965-0400 [DEBUG] core: cannot unseal, not enough keys: keys=1 threshold=3 nonce=41a98505-9502-ef95-cd7c-2f7d08f39eb3
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.095-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.095-0400 [DEBUG] core: cannot unseal, not enough keys: keys=2 threshold=3 nonce=41a98505-9502-ef95-cd7c-2f7d08f39eb3
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Attempting to unseal OpenBao with key: [redacted]
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.232-0400 [DEBUG] core: unseal key supplied: migrate=false
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.301-0400 [DEBUG] core: starting cluster listeners
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.301-0400 [INFO]  core.cluster-listener.tcp: starting listener: listener_address=[::]:8201
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.301-0400 [INFO]  core.cluster-listener: serving cluster requests: cluster_listen_address=[::]:8201
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.433-0400 [INFO]  core: post-unseal setup starting
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.435-0400 [DEBUG] core: clearing forwarding clients
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.435-0400 [DEBUG] core: done clearing forwarding clients
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.435-0400 [DEBUG] core: persisting feature flags
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.436-0400 [INFO]  core: loaded wrapping token key
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.436-0400 [INFO]  core: successfully setup plugin catalog: plugin-directory=""
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.439-0400 [INFO]  core: successfully mounted: type=system version="v2.3.2+builtin.bao" path=sys/ namespace="ID: root. Path: "
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.440-0400 [INFO]  core: successfully mounted: type=identity version="v2.3.2+builtin.bao" path=identity/ namespace="ID: root. Path: "
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.440-0400 [INFO]  core: successfully mounted: type=cubbyhole version="v2.3.2+builtin.bao" path=cubbyhole/ namespace="ID: root. Path: "
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.443-0400 [INFO]  core: successfully mounted: type=token version="v2.3.2+builtin.bao" path=token/ namespace="ID: root. Path: "
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.444-0400 [INFO]  rollback: Starting the rollback manager with 256 workers
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.444-0400 [INFO]  rollback: starting rollback manager
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.445-0400 [INFO]  core: restoring leases
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.445-0400 [DEBUG] expiration: collecting leases
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.445-0400 [DEBUG] expiration: leases collected: num_existing=0
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.446-0400 [DEBUG] identity: loading entities: namespace=""
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.446-0400 [INFO]  expiration: lease restore complete
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.446-0400 [DEBUG] identity: entities collected: num_existing=0
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.446-0400 [INFO]  identity: entities restored
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] identity: identity loading groups: namespace=""
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] identity: groups collected: num_existing=0
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [INFO]  identity: groups restored
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] identity: identity loading OIDC clients: namespace=""
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] core: request forwarding setup function
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] core: clearing forwarding clients
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] core: done clearing forwarding clients
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] core: request forwarding not setup
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [DEBUG] core: leaving request forwarding setup function
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.447-0400 [INFO]  core: usage gauge collection is disabled
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.449-0400 [INFO]  core: post-unseal setup complete
docker_stack_openbao.1.qex1zb67hx05@control01    | 2025-08-29T16:25:27.449-0400 [INFO]  core: vault is unsealed
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: OpenBao successfully unsealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: Reached threshold of 3 unseal keys, stopping.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint DEBUG: check_sealed: jq returned false/error. OpenBao IS NOT sealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Auto-unseal process completed, applied 0 keys. OpenBao successfully unsealed.
docker_stack_openbao.1.qex1zb67hx05@control01    | Entrypoint INFO: Background init/unseal process completed successfully.
^Croot@control01:[docker]$ 
root@control01:[docker]$ 
root@control01:[docker]$ docker service ps docker_stack_openbao
ID             NAME                     IMAGE                                           NODE        DESIRED STATE   CURRENT STATE           ERROR     PORTS
qex1zb67hx05   docker_stack_openbao.1   media.johnson.int:5000/openbao-ansible:latest   control01   Running         Running 6 seconds ago             
root@control01:[docker]$ 
root@control01:[docker]$ CONTAINER_ID=$(docker ps --filter "name=docker_stack_openbao" --format "{{.ID}}")
root@control01:[docker]$ echo "OpenBao Container ID: ${CONTAINER_ID}"
OpenBao Container ID: 53a0b74728e7
root@control01:[docker]$ ROOT_TOKEN=$(docker exec -it "${CONTAINER_ID}" sh -c '/usr/local/bin/fetch_openbao_info.sh --root-token')
root@control01:[docker]$ echo "Retrieved Root Token: ${ROOT_TOKEN}"
Retrieved Root Token: s.zf5p64xppGVxG21LX6PSqHTe
root@control01:[docker]$ 
root@control01:[docker]$ docker exec -it "${CONTAINER_ID}" sh -c '/usr/local/bin/fetch_openbao_info.sh --content'
{
  "unseal_keys_b64": [
    "wqPn4d19H74XuQ4rUCoQbI+hvYYaCut4Lkt0r6rO92eT",
    "y0/JCHrD2IXGNwn4rTRmQGMNN9IijRxckIwfKLceP1bf",
    "C8ujEB6hYnGnRf5MDCxsv0ACSXje3opxwcHCjcoTHxlk",
    "e76+Hs1GEbcf8EWx7hGiZrz50hASUQmqIVH+/irETyMp",
    "fTB3WO5lKi+ln7M+6FZcEaJkkBg3u/my4hUppnWaK2uc"
  ],
  "root_token": "s.zf5p64xppGVxG21LX6PSqHTe"
}
root@control01:[docker]$ 
root@control01:[docker]$ curl -s "https://openbao.admin.johnson.int/v1/sys/health" | jq
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1756499200,
  "version": "2.3.2",
  "cluster_name": "vault-cluster-3d3feb5a",
  "cluster_id": "6db8dc44-4bd8-9154-aa2c-0bcf8a6f56f4"
}
root@control01:[docker]$ ROOT_TOKEN="s.zf5p64xppGVxG21LX6PSqHTe"
root@control01:[docker]$ curl -s -H "X-Vault-Token: ${ROOT_TOKEN}" "https://openbao.admin.johnson.int/v1/sys/mounts" | jq
{
  "sys/": {
    "accessor": "system_6cfc0f45",
    "config": {
      "default_lease_ttl": 0,
      "force_no_cache": false,
      "max_lease_ttl": 0,
      "passthrough_request_headers": [
        "Accept"
      ]
    },
    "description": "system endpoints used for control, policy and debugging",
    "external_entropy_access": false,
    "local": false,
    "options": null,
    "plugin_version": "",
    "running_plugin_version": "v2.3.2+builtin.bao",
    "running_sha256": "",
    "seal_wrap": true,
    "type": "system",
    "uuid": "eea8c080-9bbe-f6ad-68a0-97f19454902f"
  },
  "identity/": {
    "accessor": "identity_ae2f8af1",
    "config": {
      "default_lease_ttl": 0,
      "force_no_cache": false,
      "max_lease_ttl": 0,
      "passthrough_request_headers": [
        "Authorization"
      ]
    },
    "description": "identity store",
    "external_entropy_access": false,
    "local": false,
    "options": null,
    "plugin_version": "",
    "running_plugin_version": "v2.3.2+builtin.bao",
    "running_sha256": "",
    "seal_wrap": false,
    "type": "identity",
    "uuid": "3770c1a9-2bf9-f812-a84d-faee2dcc1a55"
  },
  "cubbyhole/": {
    "accessor": "cubbyhole_21a00d33",
    "config": {
      "default_lease_ttl": 0,
      "force_no_cache": false,
      "max_lease_ttl": 0
    },
    "description": "per-token private secret storage",
    "external_entropy_access": false,
    "local": true,
    "options": null,
    "plugin_version": "",
    "running_plugin_version": "v2.3.2+builtin.bao",
    "running_sha256": "",
    "seal_wrap": false,
    "type": "cubbyhole",
    "uuid": "3e62451a-40d0-a770-eb03-c074b099e578"
  },
  "request_id": "713fb6d2-0ba7-87ed-71c4-02d59e72071b",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "cubbyhole/": {
      "accessor": "cubbyhole_21a00d33",
      "config": {
        "default_lease_ttl": 0,
        "force_no_cache": false,
        "max_lease_ttl": 0
      },
      "description": "per-token private secret storage",
      "external_entropy_access": false,
      "local": true,
      "options": null,
      "plugin_version": "",
      "running_plugin_version": "v2.3.2+builtin.bao",
      "running_sha256": "",
      "seal_wrap": false,
      "type": "cubbyhole",
      "uuid": "3e62451a-40d0-a770-eb03-c074b099e578"
    },
    "identity/": {
      "accessor": "identity_ae2f8af1",
      "config": {
        "default_lease_ttl": 0,
        "force_no_cache": false,
        "max_lease_ttl": 0,
        "passthrough_request_headers": [
          "Authorization"
        ]
      },
      "description": "identity store",
      "external_entropy_access": false,
      "local": false,
      "options": null,
      "plugin_version": "",
      "running_plugin_version": "v2.3.2+builtin.bao",
      "running_sha256": "",
      "seal_wrap": false,
      "type": "identity",
      "uuid": "3770c1a9-2bf9-f812-a84d-faee2dcc1a55"
    },
    "sys/": {
      "accessor": "system_6cfc0f45",
      "config": {
        "default_lease_ttl": 0,
        "force_no_cache": false,
        "max_lease_ttl": 0,
        "passthrough_request_headers": [
          "Accept"
        ]
      },
      "description": "system endpoints used for control, policy and debugging",
      "external_entropy_access": false,
      "local": false,
      "options": null,
      "plugin_version": "",
      "running_plugin_version": "v2.3.2+builtin.bao",
      "running_sha256": "",
      "seal_wrap": true,
      "type": "system",
      "uuid": "eea8c080-9bbe-f6ad-68a0-97f19454902f"
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
root@control01:[docker]$ 

```
