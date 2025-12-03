
Testing notes

```shell
root@control01:[docker]$ echo "foobar123" > openbao/home/config/.vault_pass
root@control01:[docker]$ docker service rm docker_stack_openbao
docker_stack_openbao
root@control01:[docker]$ 
root@control01:[docker]$ cat openbao/openbao.env
#
# Ansible managed
#

VAULT_ADDR=http://127.0.0.1:8200
VAULT_LOG_LEVEL=trace

#OPENBAO_API_ADDR=http://openbao.admin.johnson.int
OPENBAO_HOME_DIR=/vault
OPENBAO_CONFIG_DIR=/vault/config

#ENV_SECRETS_DEBUG=true

################################
## vaulted credentials
ANSIBLE_VAULT_PASSWORD=dksec://ansible_vault_password
root@control01:[docker]$ 
root@control01:[docker]$ cat openbao/home/config/local.json
{
    "api_addr": "http://127.0.0.1:8200",
    "default_lease_ttl": "168h",
    "listener": {
        "tcp": {
            "address": "0.0.0.0:8200",
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
                "log_raw": "true"
            }
        }
    }
}
root@control01:[docker]$ 
root@control01:[docker]$ rm -rf openbao/home/file/*
root@control01:[docker]$ rm -f openbao/home/config/init.*
root@control01:[docker]$ rm -f openbao/home/logs/*
root@control01:[docker]$ 
root@control01:[docker]$ docker stack deploy -c docker-compose.yml docker_stack --with-registry-auth
Creating service docker_stack_openbao
root@control01:[docker]$ 
root@control01:[docker]$ docker service ps docker_stack_openbao
ID             NAME                     IMAGE                                           NODE        DESIRED STATE   CURRENT STATE            ERROR     PORTS
w3abu1fgfqcy   docker_stack_openbao.1   media.johnson.int:5000/openbao-ansible:latest   control01   Running         Running 37 seconds ago             
root@control01:[docker]$ 
root@control01:[docker]$ 
root@control01:[docker]$ CONTAINER_ID=$(docker ps --filter "name=docker_stack_openbao" --format "{{.ID}}")
root@control01:[docker]$ 
root@control01:[docker]$ docker service logs -f docker_stack_openbao
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Background init/unseal process started.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Waiting for OpenBao server to become responsive...
docker_stack_openbao.1.q26m9l693een@control01    | ==> OpenBao server configuration:
docker_stack_openbao.1.q26m9l693een@control01    | 
docker_stack_openbao.1.q26m9l693een@control01    | Administrative Namespace: 
docker_stack_openbao.1.q26m9l693een@control01    |              Api Address: https://openbao.admin.johnson.int
docker_stack_openbao.1.q26m9l693een@control01    |                      Cgo: disabled
docker_stack_openbao.1.q26m9l693een@control01    |          Cluster Address: https://openbao.admin.johnson.int:444
docker_stack_openbao.1.q26m9l693een@control01    |    Environment Variables: ANSIBLE_VAULT_PASSWORD, ENTRYPOINT_LOG_LEVEL, HOME, HOSTNAME, INTERNAL_VAULT_ADDR, NAME, OPENBAO_CONFIG_DIR, OPENBAO_HOME_DIR, OPENBAO_INIT_FILE, OPENBAO_INIT_FILE_PREFIX, PATH, PWD, SHLVL, VAULT_ADDR, VERSION
docker_stack_openbao.1.q26m9l693een@control01    |               Go Version: go1.24.6
docker_stack_openbao.1.q26m9l693een@control01    |               Listener 1: tcp (addr: "[::]:8200", cluster address: "[::]:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
docker_stack_openbao.1.q26m9l693een@control01    |                Log Level: info
docker_stack_openbao.1.q26m9l693een@control01    |            Recovery Mode: false
docker_stack_openbao.1.q26m9l693een@control01    |                  Storage: file
docker_stack_openbao.1.q26m9l693een@control01    |                  Version: OpenBao v2.3.2, built 2025-08-08T04:05:27Z
docker_stack_openbao.1.q26m9l693een@control01    |              Version Sha: b1a68f558c89d18d38fbb8675bb6fc1d90b71e98
docker_stack_openbao.1.q26m9l693een@control01    | 
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:13.157-0400 [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
docker_stack_openbao.1.q26m9l693een@control01    | ==> OpenBao server started! Log data will stream in below:
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:13.157-0400 [INFO]  core: Initializing version history cache for core
docker_stack_openbao.1.q26m9l693een@control01    | 
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:13.791-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao server is responsive.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Checking if OpenBao is initialized...
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:13.925-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:13.925-0400 [INFO]  core: seal configuration missing, not initialized
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao is NOT initialized. Attempting initialization...
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Initializing OpenBao...
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.058-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.058-0400 [INFO]  core: seal configuration missing, not initialized
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.059-0400 [INFO]  core: security barrier not initialized
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.061-0400 [INFO]  core: security barrier initialized: stored=1 shares=5 threshold=3
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.062-0400 [INFO]  core: post-unseal setup starting
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.077-0400 [INFO]  core: loaded wrapping token key
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.077-0400 [INFO]  core: successfully setup plugin catalog: plugin-directory=""
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.077-0400 [INFO]  core: no mounts in legacy mount table; adding default mount table
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.082-0400 [INFO]  core: successfully mounted: type=cubbyhole version="v2.3.2+builtin.bao" path=cubbyhole/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.083-0400 [INFO]  core: successfully mounted: type=system version="v2.3.2+builtin.bao" path=sys/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.083-0400 [INFO]  core: successfully mounted: type=identity version="v2.3.2+builtin.bao" path=identity/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.085-0400 [INFO]  core: no mounts in legacy auth table; adding default mount table
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.086-0400 [INFO]  core: successfully mounted: type=token version="v2.3.2+builtin.bao" path=token/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.086-0400 [INFO]  rollback: Starting the rollback manager with 256 workers
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.087-0400 [INFO]  rollback: starting rollback manager
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.087-0400 [INFO]  core: restoring leases
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.088-0400 [INFO]  expiration: lease restore complete
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.088-0400 [INFO]  identity: entities restored
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.088-0400 [INFO]  identity: groups restored
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.089-0400 [INFO]  core: usage gauge collection is disabled
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.089-0400 [INFO]  core: Recorded vault version: vault version=2.3.2 upgrade time="2025-08-29 13:19:14.089093867 +0000 UTC" build date=2025-08-08T04:05:27Z
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.090-0400 [INFO]  core: post-unseal setup complete
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.091-0400 [INFO]  core: root token generated
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.091-0400 [INFO]  core: pre-seal teardown starting
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.091-0400 [INFO]  rollback: stopping rollback manager
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:19:14.091-0400 [INFO]  core: pre-seal teardown complete
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Encrypting initialization details with ANSIBLE_VAULT_PASSWORD.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao initialization details encrypted to /vault/config/init.json.enc
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Initialization attempt completed.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Checking if OpenBao is sealed...
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao IS sealed. Attempting auto-unseal...
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Attempting auto-unseal...
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Decrypting initialization details from /vault/config/init.json.enc
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.543-0400 [INFO]  core.cluster-listener.tcp: starting listener: listener_address=[::]:8201
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.543-0400 [INFO]  core.cluster-listener: serving cluster requests: cluster_listen_address=[::]:8201
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.543-0400 [INFO]  core: post-unseal setup starting
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.544-0400 [INFO]  core: loaded wrapping token key
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.544-0400 [INFO]  core: successfully setup plugin catalog: plugin-directory=""
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.545-0400 [INFO]  core: successfully mounted: type=system version="v2.3.2+builtin.bao" path=sys/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.546-0400 [INFO]  core: successfully mounted: type=identity version="v2.3.2+builtin.bao" path=identity/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.546-0400 [INFO]  core: successfully mounted: type=cubbyhole version="v2.3.2+builtin.bao" path=cubbyhole/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.548-0400 [INFO]  core: successfully mounted: type=token version="v2.3.2+builtin.bao" path=token/ namespace="ID: root. Path: "
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.548-0400 [INFO]  rollback: Starting the rollback manager with 256 workers
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.548-0400 [INFO]  rollback: starting rollback manager
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.549-0400 [INFO]  core: restoring leases
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.550-0400 [INFO]  identity: entities restored
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.550-0400 [INFO]  identity: groups restored
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.550-0400 [INFO]  expiration: lease restore complete
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.550-0400 [INFO]  core: usage gauge collection is disabled
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.551-0400 [INFO]  core: post-unseal setup complete
docker_stack_openbao.1.q26m9l693een@control01    | 2025-08-29T09:20:10.551-0400 [INFO]  core: vault is unsealed
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao is already unsealed, stopping key application.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: OpenBao successfully unsealed.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Auto-unseal attempt completed.
docker_stack_openbao.1.q26m9l693een@control01    | Entrypoint INFO: Background init/unseal process completed successfully.
^Croot@control01:[docker]$ 
root@control01:[docker]$ 
```

## Fetch content from container

### 1. Fetch the content of `init.json.enc`

This command will output the full decrypted content of the `init.json` file.

```bash
docker exec -it "${CONTAINER_ID}" sh -c 'openbao_info --content'
```

---

### 2. Fetch the root token

This command will output only the root token from the decrypted `init.json` file.

```bash
ROOT_TOKEN=$(docker exec -it "${CONTAINER_ID}" sh -c 'openbao_info --root-token')
echo "OpenBao Root Token: ${ROOT_TOKEN}"
```

---

### Explanation

* **`set -e`**: Ensures the script exits immediately if any command fails.
* **Temporary Files**: `mktemp` is used to create secure, unique temporary files for the decrypted JSON and the vault password, reducing the risk of sensitive data exposure.
* **`cleanup` Function and `trap`**: The `cleanup` function ensures that these temporary files are removed automatically when the script exits, whether successfully or due to an error.
* **`env_secrets_expand.sh` Sourcing**: The script correctly sources `/usr/local/bin/env_secrets_expand.sh` within the container's shell session (`sh -c`) to ensure the `ANSIBLE_VAULT_PASSWORD` variable is properly expanded before `ansible-vault` is called.
* **`decrypt_init_json` Function**: Encapsulates the decryption logic, making the main script cleaner and preventing code duplication.
* **Case Statement**: The `case` statement handles the different command-line arguments (`--content` and `--root-token`), allowing you to specify which action you want the script to perform.
* **`jq -r ".root_token"`**: This command extracts the `root_token` field from the decrypted JSON, outputting just its raw value.
* **Error Handling**: Includes checks for the existence of `env_secrets_expand.sh`, the expanded `ANSIBLE_VAULT_PASSWORD`, and the encrypted `init.json.enc` file, providing helpful error messages to `stderr`.

This script provides a secure and robust way to retrieve sensitive information from your OpenBao container during testing or troubleshooting

### Manually fetch data from container

```shell
root@control01:[docker]$ docker exec -it "${CONTAINER_ID}" sh -c '
  # Source the secret expansion script to resolve variables like ANSIBLE_VAULT_PASSWORD.
  # This script is expected to set actual environment variables from the secret references.
  if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
    echo "DEBUG: Sourcing /usr/local/bin/env_secrets_expand.sh to expand secrets." >&2
    . /usr/local/bin/env_secrets_expand.sh
  else
    echo "ERROR: env_secrets_expand.sh not found at /usr/local/bin/. Cannot expand secrets." >&2
    exit 1
  fi

  set -e # Exit immediately if any command fails

  # 1. Verify ANSIBLE_VAULT_PASSWORD is now set and non-empty after expansion
  if [ -z "${ANSIBLE_VAULT_PASSWORD}" ]; then
    echo "ERROR: ANSIBLE_VAULT_PASSWORD is still not set or is empty after env_secrets_expand.sh. Cannot decrypt." >&2
    exit 1
  fi
  echo "DEBUG: ANSIBLE_VAULT_PASSWORD appears to be resolved after expansion." >&2

  # 2. Create a temporary file for the vault password
  ANSIBLE_VAULT_PASSWORD_FILE=$(mktemp)
  echo "${ANSIBLE_VAULT_PASSWORD}" > "${ANSIBLE_VAULT_PASSWORD_FILE}"
  chmod 600 "${ANSIBLE_VAULT_PASSWORD_FILE}" # Set strict permissions
  echo "DEBUG: Created temporary password file: ${ANSIBLE_VAULT_PASSWORD_FILE}" >&2

  DECRYPTED_FILE="/tmp/init.json.decrypted"
  ENCRYPTED_FILE="/vault/config/init.json.enc"

  # 3. Attempt to decrypt the file
  echo "DEBUG: Attempting to decrypt ${ENCRYPTED_FILE}..." >&2
  if ! ansible-vault decrypt "${ENCRYPTED_FILE}" --vault-password-file "${ANSIBLE_VAULT_PASSWORD_FILE}" --output "${DECRYPTED_FILE}"; then
    echo "ERROR: ansible-vault decryption failed for ${ENCRYPTED_FILE}." >&2
    echo "  Possible issues: 1. File does not exist. 2. Resolved password is incorrect. 3. Permissions." >&2
    rm -f "${ANSIBLE_VAULT_PASSWORD_FILE}" # Clean up password file
    exit 1
  fi
  echo "DEBUG: Decryption successful to ${DECRYPTED_FILE}." >&2

  # 4. Extract the file contents
  cat "${DECRYPTED_FILE}"

  # 5. Clean up temporary files
  echo "DEBUG: Cleaning up temporary files..." >&2
  rm -f "${ANSIBLE_VAULT_PASSWORD_FILE}" "${DECRYPTED_FILE}"
  echo "DEBUG: Cleanup complete." >&2
  exit 0
'
DEBUG: Sourcing /usr/local/bin/env_secrets_expand.sh to expand secrets.
DEBUG: ANSIBLE_VAULT_PASSWORD appears to be resolved after expansion.
DEBUG: Created temporary password file: /tmp/tmp.hMPLkD
DEBUG: Attempting to decrypt /vault/config/init.json.enc...
Decryption successful
DEBUG: Decryption successful to /tmp/init.json.decrypted.
{
  "unseal_keys_b64": [
    "3HlST+p5//Eu9sa5s8pPbgs4XGXQgeMXQ2Yt2s3O+RBN",
    "8Aix0mr38ZQNHdnhzhQsxlJie1dnnoPDzbIRSHSequ3O",
    "raii5OwfHeFCsWznjtUrcXL2zP8Ssw/3WxA+D1H2nOe7",
    "but3MiGH9/n+wnJbjUinEU8n2z2pMblnwV2RmZVMOmrI",
    "/VQbyy8OJQFLfwSMYyGTCEDCs2uWmpylAktjzIyJHtuY"
  ],
  "root_token": "s.RAhB3bMIaf8wyyGAvegvxQbF"
}
DEBUG: Cleaning up temporary files...
DEBUG: Cleanup complete.
root@control01:[docker]$ 

root@control01:[docker]$ ROOT_TOKEN=$(docker exec -it "${CONTAINER_ID}" sh -c '
  # Source the secret expansion script to resolve variables like ANSIBLE_VAULT_PASSWORD.
  # This script is expected to set actual environment variables from the secret references.
  if [ -f "/usr/local/bin/env_secrets_expand.sh" ]; then
    . /usr/local/bin/env_secrets_expand.sh
  else
    echo "ERROR: env_secrets_expand.sh not found at /usr/local/bin/. Cannot expand secrets." >&2
    exit 1
  fi

  set -e # Exit immediately if any command fails

  # 1. Verify ANSIBLE_VAULT_PASSWORD is now set and non-empty after expansion
  if [ -z "${ANSIBLE_VAULT_PASSWORD}" ]; then
    echo "ERROR: ANSIBLE_VAULT_PASSWORD is still not set or is empty after env_secrets_expand.sh. Cannot decrypt." >&2
    exit 1
  fi

  # 2. Create a temporary file for the vault password
  ANSIBLE_VAULT_PASSWORD_FILE=$(mktemp)
  echo "${ANSIBLE_VAULT_PASSWORD}" > "${ANSIBLE_VAULT_PASSWORD_FILE}"
  chmod 600 "${ANSIBLE_VAULT_PASSWORD_FILE}" # Set strict permissions

  DECRYPTED_FILE="/tmp/init.json.decrypted"
  ENCRYPTED_FILE="/vault/config/init.json.enc"

  # 3. Attempt to decrypt the file
  if ! ansible-vault decrypt "${ENCRYPTED_FILE}" --vault-password-file "${ANSIBLE_VAULT_PASSWORD_FILE}" --output "${DECRYPTED_FILE}" > /dev/null 2>&1; then
    echo "ERROR: ansible-vault decryption failed for ${ENCRYPTED_FILE}." >&2
    echo "  Possible issues: 1. File does not exist. 2. Resolved password is incorrect. 3. Permissions." >&2
    rm -f "${ANSIBLE_VAULT_PASSWORD_FILE}" # Clean up password file
    exit 1
  fi

  # 4. Extract the root token using jq
  ROOT_TOKEN_ACTUAL=$(jq -r ".root_token" "${DECRYPTED_FILE}")
  echo "${ROOT_TOKEN_ACTUAL}"

  # 5. Clean up temporary files
  rm -f "${ANSIBLE_VAULT_PASSWORD_FILE}" "${DECRYPTED_FILE}"
  exit 0
')
root@control01:[docker]$ echo "ROOT_TOKEN=${ROOT_TOKEN}"
ROOT_TOKEN=s.RAhB3bMIaf8wyyGAvegvxQbF
root@control01:[docker]$ 
root@control01:[docker]$ docker exec -it "${CONTAINER_ID}" sh -c '
  ansible-vault decrypt /vault/config/init.json.enc --vault-password-file /vault/config/.vault_pass --output /tmp/init.json.decrypted > /dev/null 2>&1;
  cat /tmp/init.json.decrypted;
  rm /tmp/init.json.decrypted;
  exit;
'
{
  "unseal_keys_b64": [
    "3HlpPbgs4XGXQgSXQ2Yt2s3O+T+p5//Eu9sa5s8eMRBN",
    "8AiQsxlJie1dnnxDzbIRSHSeq0mr38ZQNHdnhzhoPu3O",
    "raiUrcXL2zP8Ssi3WxA+D1H2n5OwfHeFCsWznjtw/Oe7",
    "butinEU8n2z2pM3nwV2RmZVMOMiGH9/n+wnJbjUblmrI",
    "/VQyGTCEDCs2uWbylAktjzIyJyy8OJQFLfwSMYmpHtuY"
  ],
  "root_token": "s.RAhB3bMIaf8wyyGAvegvxQbF"
}
root@control01:[docker]$ 
root@control01:[docker]$ docker exec -it ${CONTAINER_ID} sh
/ $ 
/ $ export ROOT_TOKEN="s.RAhB3bMIaf8wyyGAvegvxQbF"
/ $ export VAULT_ADDR=http://127.0.0.1:8200
/ $ 
/ $ # Test the standard mounts endpoint (should now work!)
/ $ curl -H "X-OpenBao-Token: ${ROOT_TOKEN}" "${VAULT_ADDR}/v1/sys/mounts"
{"errors":["permission denied"]}
/ $ curl -H "X-Vault-Token: ${ROOT_TOKEN}" "${VAULT_ADDR}/v1/sys/mounts"

{"sys/":{"accessor":"system_d4d635d6","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":true,"type":"system","uuid":"df37acad-9c9f-8e73-5582-94c76b15b1da"},"identity/":{"accessor":"identity_792bb078","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"3c599ed1-681e-c156-f797-59e18c801fe0"},"cubbyhole/":{"accessor":"cubbyhole_b5cfa9fc","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"d9bd4d4f-55d4-df49-5efe-d8aac733947e"},"request_id":"ea0e7560-2dd8-a5a7-4601-2e13656c8df4","lease_id":"","renewable":false,"lease_duration":0,"data":{"cubbyhole/":{"accessor":"cubbyhole_b5cfa9fc","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"d9bd4d4f-55d4-df49-5efe-d8aac733947e"},"identity/":{"accessor":"identity_792bb078","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"3c599ed1-681e-c156-f797-59e18c801fe0"},"sys/":{"accessor":"system_d4d635d6","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":true,"type":"system","uuid":"df37acad-9c9f-8e73-5582-94c76b15b1da"}},"wrap_info":null,"warnings":null,"auth":null}

/ $ 
/ $ # Test the health endpoint again (should still work)
/ $ curl -H "X-OpenBao-Token: ${ROOT_TOKEN}" "${VAULT_ADDR}/v1/sys/health?standbyok=true"
{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1756409319,"version":"2.3.2","cluster_name":"vault-cluster-8179c851","cluster_id":"cea5f557-ab69-86ed-34e2-c82f9ffb599e"}
/ $ 
/ $ # Test another sys endpoint
/ $ curl -H "X-OpenBao-Token: ${ROOT_TOKEN}" "${VAULT_ADDR}/v1/sys/seal-status"
{"type":"shamir","initialized":true,"sealed":false,"t":3,"n":5,"progress":0,"nonce":"","version":"2.3.2","build_date":"2025-08-08T04:05:27Z","migration":false,"cluster_name":"vault-cluster-8179c851","cluster_id":"cea5f557-ab69-86ed-34e2-c82f9ffb599e","recovery_seal":false,"storage_type":"file"}
/ $ 
/ $ vault login ${ROOT_TOKEN}
Success! You are now authenticated. The token information displayed below is
already stored in the token helper. You do NOT need to run "bao login" again.
Future OpenBao requests will automatically use this token.

Key                  Value
---                  -----
token                s.RAhB3bMIaf8wyyGAvegvxQbF
token_accessor       op2AVbQVaNef7OLOlqnHg3gT
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
/ $ 
/ $ vault policy write admin - <<EOF
> path "*" {
>   capabilities = ["create", "read", "update", "delete", "list", "sudo"]
> }
> EOF
Success! Uploaded policy: admin
/ $ vault token create -policy=admin
Key                  Value
---                  -----
token                s.RAhB3bMIaf8wyyGAvegvxQbF
token_accessor       55q1DvUjSqxvCNZH3cc0p5RO
token_duration       168h
token_renewable      true
token_policies       ["admin" "default"]
identity_policies    []
policies             ["admin" "default"]
/ $ 
/ $ exit
root@control01:[docker]$ 
root@control01:[docker]$ curl -s "https://openbao.admin.johnson.int/v1/sys/health" | jq
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1756473816,
  "version": "2.3.2",
  "cluster_name": "vault-cluster-1de8d78f",
  "cluster_id": "ad1cfea7-88ff-7bbd-a4d3-b915a98ee861"
}
## debug
root@control01:[docker]$ curl -v -k "https://openbao.admin.johnson.int/v1/sys/health"
* Host openbao.admin.johnson.int:443 was resolved.
* IPv6: (none)
* IPv4: 10.0.0.5
*   Trying 10.0.0.5:443...
* Connected to openbao.admin.johnson.int (10.0.0.5) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / secp521r1 / RSASSA-PSS
* ALPN: server accepted h2
* Server certificate:
*  subject: C=US; ST=North Carolina; L=Raleigh; O=Johnsonville Internal; OU=Mostly Impractical; CN=admin.johnson.int
*  start date: Aug 13 17:28:00 2025 GMT
*  expire date: Aug 13 17:28:00 2027 GMT
*  issuer: C=US; ST=North Carolina; L=Raleigh; O=Johnsonville Internal; OU=Mostly Impractical; CN=ca.admin.johnson.int
*  SSL certificate verify result: self-signed certificate in certificate chain (19), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 3: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://openbao.admin.johnson.int/v1/sys/health
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: openbao.admin.johnson.int]
* [HTTP/2] [1] [:path: /v1/sys/health]
* [HTTP/2] [1] [user-agent: curl/8.5.0]
* [HTTP/2] [1] [accept: */*]
> GET /v1/sys/health HTTP/2
> Host: openbao.admin.johnson.int
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/2 200 
< cache-control: no-store
< content-type: application/json
< date: Fri, 29 Aug 2025 05:14:33 GMT
< strict-transport-security: max-age=31536000; includeSubDomains
< content-length: 294
< 
{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1756444473,"version":"2.3.2","cluster_name":"vault-cluster-446fe7ab","cluster_id":"2a04b99c-5443-b5bf-d3f6-966dbc2ecc58"}
* Connection #0 to host openbao.admin.johnson.int left intact
root@control01:[docker]$ 
root@control01:[docker]$ curl -v -k -H "X-Vault-Token: ${ROOT_TOKEN_ACTUAL}" "https://openbao.admin.johnson.int/v1/sys/mounts"
* Host openbao.admin.johnson.int:443 was resolved.
* IPv6: (none)
* IPv4: 10.0.0.5
*   Trying 10.0.0.5:443...
* Connected to openbao.admin.johnson.int (10.0.0.5) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / secp521r1 / RSASSA-PSS
* ALPN: server accepted h2
* Server certificate:
*  subject: C=US; ST=North Carolina; L=Raleigh; O=Johnsonville Internal; OU=Mostly Impractical; CN=admin.johnson.int
*  start date: Aug 13 17:28:00 2025 GMT
*  expire date: Aug 13 17:28:00 2027 GMT
*  issuer: C=US; ST=North Carolina; L=Raleigh; O=Johnsonville Internal; OU=Mostly Impractical; CN=ca.admin.johnson.int
*  SSL certificate verify result: self-signed certificate in certificate chain (19), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 3: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://openbao.admin.johnson.int/v1/sys/mounts
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: openbao.admin.johnson.int]
* [HTTP/2] [1] [:path: /v1/sys/mounts]
* [HTTP/2] [1] [user-agent: curl/8.5.0]
* [HTTP/2] [1] [accept: */*]
* [HTTP/2] [1] [x-vault-token: s.RAhB3bMIaf8wyyGAvegvxQbF]
> GET /v1/sys/mounts HTTP/2
> Host: openbao.admin.johnson.int
> User-Agent: curl/8.5.0
> Accept: */*
> X-Vault-Token: s.RAhB3bMIaf8wyyGAvegvxQbF
> 
< HTTP/2 200 
< cache-control: no-store
< content-type: application/json
< date: Fri, 29 Aug 2025 05:14:43 GMT
< strict-transport-security: max-age=31536000; includeSubDomains
< 
{"sys/":{"accessor":"system_37a127b8","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":true,"type":"system","uuid":"8e374545-3ca3-9fc5-b9dc-22dbd08afc36"},"identity/":{"accessor":"identity_29e5f431","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"53e62bb3-c8a4-9a7e-ca6f-8d69e55c4f2a"},"cubbyhole/":{"accessor":"cubbyhole_34f08350","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"411af0f8-7693-961e-3ecd-c8127a5a1b65"},"request_id":"f89d07a5-c597-2060-c3c2-33c90ea3ff12","lease_id":"","renewable":false,"lease_duration":0,"data":{"cubbyhole/":{"accessor":"cubbyhole_34f08350","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"411af0f8-7693-961e-3ecd-c8127a5a1b65"},"identity/":{"accessor":"identity_29e5f431","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"53e62bb3-c8a4-9a7e-ca6f-8d69e55c4f2a"},"sys/":{"accessor":"system_37a127b8","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v2.3.2+builtin.bao","running_sha256":"","seal_wrap":true,"type":"system","uuid":"8e374545-3ca3-9fc5-b9dc-22dbd08afc36"}},"wrap_info":null,"warnings":null,"auth":null}
* Connection #0 to host openbao.admin.johnson.int left intact
root@control01:[docker]$ 

```
