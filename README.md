# OpenBao Enhanced Docker Image with Ansible Vault

This Docker image extends the official `openbao/openbao:2.3.2` image to provide a secure, automated setup for running an OpenBao server with initialization and auto-unsealing, using Ansible Vault to encrypt sensitive initialization data. The image is designed to run as a non-root user (`openbao`, UID=1102, GID=1102) and avoids requiring `chown` or root privileges at runtime, adhering to Docker security best practices.

## Features
- **Automated Initialization and Unsealing**: Initializes the OpenBao vault on first run and auto-unseals it using stored keys. On restarts, detects an initialized vault and unseals without reinitialization.
- **Ansible Vault Integration**: Encrypts the initialization output (`init.txt`) containing unseal keys and the root token using `ansible-vault`, with the password sourced from a secure file or environment variable.
- **Non-Root Execution**: Runs as the `openbao` user, eliminating the need for root privileges or `chown` operations.
- **Robust Health Check**: Includes a Docker Compose health check to verify the vault is unsealed (`Sealed: false`).
- **Debug Logging**: Comprehensive debug logs for troubleshooting, with sensitive data (unseal keys, tokens) redacted or not logged.
- **Custom Configuration**: Supports custom OpenBao configuration via `/vault/custom_config/local.json`.
- **Non-root Compliant**: Does not (1) chown, (2) chmod, (3) su-exec or run any root required commands.
- **Variable level logging**: The image now includes a robust logging mechanism with levels (ERROR, WARNING, INFO, DEBUG, TRACE) controlled by the ENTRYPOINT_LOG_LEVEL environment variable. This allows you to tailor the verbosity of the entrypoint script's output without modifying the script itself.
- **Encrypt/Decrypt JSON Storage for Root Token and Unseal Keys**:
  - OpenBao initialization now saves the unseal keys and the root token into a single init.json file.
  - This init.json file is then immediately encrypted using ansible-vault into init.json.enc, as long as ANSIBLE_VAULT_PASSWORD is set.
  - The auto_unseal function now decrypts this init.json.enc file (if it exists) to retrieve the keys for unsealing. 
- **Utility Script "fetch_openbao_info.sh"**: This script is enhanced to decrypt init.json.enc and provide two distinct functionalities:
  - --content: Displays the full content of the decrypted init.json, showing both unseal keys and the root token.
  - --root-token: Directly outputs only the root_token value, making it suitable for scripting (e.g., ROOT_TOKEN=$(docker exec ... fetch_openbao_info.sh --root-token)). All debug output from the script is sent to stderr to keep stdout clean for the token.

## Prerequisites
- **Docker**: Version 20.10 or later.
- **Docker Compose**: Version 2.0 or later.
- **Host Setup**:
  - An `openbao` user (UID=1102, GID=1102) defined in `/etc/passwd` on the host.
  - Host directories for `/vault/file`, `/vault/logs`, `/vault/custom_config`, and `/run/secrets` owned by `openbao` (1102:1102).
- **Ansible Vault Password**: A secure password stored in `/home/container-user/docker/openbao/secrets/ansible_vault_password` or set via the `ANSIBLE_VAULT_PASSWORD` environment variable.

## Installation

### 1. Clone or Create Project Directory
```bash
mkdir openbao-ansible
cd openbao-ansible
```

### 2. Create Dockerfile
Create a `Dockerfile` with the following content:
```dockerfile
FROM openbao/openbao:2.3.2
USER root
RUN apk add --no-cache ansible
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/env_secrets_expand.sh
USER openbao
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
```

### 3. Create Docker Compose File
Create a `docker-compose.yml` file:
```yaml
services:

  openbao:
    image: lj020326/openbao-ansible:latest
    container_name: docker-openbao-1
    environment:
      - VAULT_ADDR=http://127.0.0.1:8200
      - ANSIBLE_VAULT_PASSWORD=/run/secrets/ansible_vault_password
    ports:
      - "8200:8200"
    volumes:
      - /home/container-user/docker/openbao/home/file:/vault/file
      - /home/container-user/docker/openbao/home/logs:/vault/logs
      - /home/container-user/docker/openbao/home/custom_config:/vault/custom_config
      - /home/container-user/docker/openbao/secrets:/run/secrets
      - /etc/passwd:/etc/passwd:ro
    user: openbao
    healthcheck:
      test: ["CMD-SHELL", "vault status > /vault/logs/healthcheck_output 2>&1 && grep -q 'Sealed.*false' /vault/logs/healthcheck_output"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 300s
    networks:
      - docker_net
networks:
  docker_net:
    driver: bridge
```

### 4. Set Up Host Directories and Secrets
Create the necessary directories and set permissions:
```bash
# assuming a host user:group "container-user:container-user" with uid:gid "1102:1102" - can be overridden
$ id container-user
uid=1102(container-user) gid=1102(container-user) groups=4(adm),24(cdrom),30(dip),46(plugdev),998(docker),1102(container-user)
# the `docker-compose.yml` user key defines the host uid/gid used to run the container
$ grep "user:" docker-compose.yml
    user: 1102:1102
# the host "container-user" user is mapped to the container user/group "openbao" with mounts on /etc/passwd and /etc/groups
$ cat openbao/passwd
openbao:x:1102:1102:openbao user:/vault:/bin/bash
$ cat openbao/group
openbao:x:1102:
# Example: To set ownership for the parent directory (adjust path as needed) to match the `docker-compose.yml` defined `user`
$ sudo chown -R 1102:1102 /home/container-user/docker/openbao/home
$ mkdir -p /home/container-user/docker/openbao/home/{file,logs,custom_config}
$ mkdir -p /home/container-user/docker/openbao/secrets
$ echo "<secure-ansible-vault-password>" > /home/container-user/docker/openbao/secrets/ansible_vault_password
$ chown -R 1102:1102 /home/container-user/docker/openbao/home
$ chown 1102:1102 /home/container-user/docker/openbao/secrets/ansible_vault_password
$ chmod -R u+rwX /home/container-user/docker/openbao/home
$ chmod 600 /home/container-user/docker/openbao/secrets/ansible_vault_password
```
Replace `<secure-ansible-vault-password>` with a strong password (e.g., generated via `openssl rand -base64 32`).

### 5. Build and Push the Image
Copy the `docker-entrypoint.sh` and `env_secrets_expand.sh` scripts into the project directory, then build and push:
```bash
docker build -t openbao-ansible:latest -f Dockerfile .
docker tag openbao-ansible:latest media.johnson.int:5000/openbao-ansible:latest
docker push media.johnson.int:5000/openbao-ansible:latest
```

## Usage

### Start the OpenBao Container
```bash
docker compose -f docker-compose.yml up -d openbao
```

### Check Container Status
Verify the container is running and healthy:
```bash
docker compose ps -a
```
Expected output:
```
NAME               IMAGE                                            COMMAND                  SERVICE   CREATED         STATUS                    PORTS
docker-openbao-1   media.johnson.int:5000/openbao-ansible:latest   "/usr/local/bin/dock…"   openbao   2 minutes ago   Up 2 minutes (healthy)    0.0.0.0:8200->8200/tcp
```

### View Logs
Check the logs for initialization and unsealing status:
```bash
docker logs -f docker-openbao-1
```

### Retrieve Root Token
The root token and unseal keys are stored in `/vault/custom_config/init.txt` (encrypted with Ansible Vault). To retrieve:
```bash
docker compose exec openbao sh
cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/logs/init.txt.decrypted --vault-password-file=/dev/stdin
cat /vault/logs/init.txt.decrypted
rm /vault/logs/init.txt.decrypted
exit
```
Example output:
```
Unseal Key 1: <key1>
Unseal Key 2: <key2>
Unseal Key 3: <key3>
Unseal Key 4: <key4>
Unseal Key 5: <key5>
Initial Root Token: <root-token>
```
Store the root token securely (e.g., in a password manager) and avoid reusing it for regular operations.

### Create an Admin Token
To avoid using the root token, create an admin token with a policy:
```bash
docker compose exec openbao vault login <root-token>
docker compose exec openbao vault policy write admin - <<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
docker compose exec openbao vault token create -policy=admin
```
Use the generated admin token for regular operations.

### Next Steps
Now that your OpenBao instance is up, unsealed, and securely accessible, you can start leveraging its power! Here are some common next steps:

Enable Additional Secret Engines: You'll likely want to enable other secret engines, such as Key/Value (KV) stores for generic secrets, or database secret engines to generate dynamic credentials. For example, to enable a KV secret engine:

```shell
curl -s "https://localhost/v1/sys/health" | jq
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

CONTAINER_ID=$(docker ps --filter "name=docker_stack_openbao" --format "{{.ID}}")

curl -s -H "X-Vault-Token: ${ROOT_TOKEN}" \
--request POST \
--data '{"type": "kv"}' \
"http://localhost/v1/sys/mounts/secret" | jq

## debugging
curl -v -k -H "X-Vault-Token: ${ROOT_TOKEN}" \
--request POST \
--data '{"type": "kv"}' \
"http://localhost/v1/sys/mounts/secret"
```

Configure Auth Methods: Beyond tokens, you'll want to configure authentication methods for your users and applications. Common ones include Username/Password, LDAP, GitHub, or Kubernetes.

Write Policies: Define access control policies to determine what users and applications can do within OpenBao (e.g., read specific secrets, manage certain paths).

Integrate with Applications: Start integrating your applications to fetch secrets from OpenBao dynamically, rather than hardcoding them.

### Test Vault Access
Verify the vault is operational:
```bash
docker compose exec openbao vault login <admin-token>
docker compose exec openbao vault kv put secret/test key=value
docker compose exec openbao vault kv get secret/test
```

## Security Considerations
- **Root Token**: Avoid using the root token for regular operations. Create an admin token with limited privileges and consider revoking the root token after setup:
  ```bash
  docker compose exec openbao vault token revoke <root-token>
  ```
  **Warning**: Only revoke the root token if all necessary policies and tokens are configured, as it’s required for critical operations like rekeying.
- **Ansible Vault Password**: Ensure the `ANSIBLE_VAULT_PASSWORD` (stored in `/run/secrets/ansible_vault_password`) is strong and rotated periodically. To rotate:
  ```bash
  NEW_PASSWORD=$(openssl rand -base64 32)
  echo "$NEW_PASSWORD" > /home/container-user/docker/openbao/secrets/ansible_vault_password
  docker compose exec openbao sh
  cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/logs/init.txt.decrypted --vault-password-file=/dev/stdin
  echo "$NEW_PASSWORD" | ansible-vault encrypt /vault/logs/init.txt.decrypted --output=/vault/custom_config/init.txt --vault-password-file=/dev/stdin
  rm /vault/logs/init.txt.decrypted
  exit
  chown 1102:1102 /home/container-user/docker/openbao/secrets/ansible_vault_password
  chmod 600 /home/container-user/docker/openbao/secrets/ansible_vault_password
  ```
- **File Permissions**: Ensure host directories (`/home/container-user/docker/openbao/home/*` and `/home/container-user/docker/openbao/secrets/*`) are owned by `openbao` (1102:1102) with restricted permissions (`chmod 600` for secrets).
- **Logs**: The `docker-entrypoint.sh` script redacts unseal keys and does not log the root token. Verify logs for sensitive data:
  ```bash
  docker compose exec openbao cat /vault/logs/bao_server_output
  docker compose exec openbao cat /vault/logs/init_output
  ```

## Troubleshooting
- **Container Not Healthy**:
  - Check health check output:
    ```bash
    docker compose exec openbao cat /vault/logs/healthcheck_output
    ```
  - If `Sealed: true`, increase `start_period` in `docker-compose.yml` to `360s` and restart:
    ```bash
    docker compose -f docker-compose.yml down
    docker compose -f docker-compose.yml up -d openbao
    ```
- **Initialization or Unsealing Fails**:
  - Check logs:
    ```bash
    docker logs docker-openbao-1
    ```
  - Verify `init.txt` contents:
    ```bash
    docker compose exec openbao sh
    cat /run/secrets/ansible_vault_password | ansible-vault decrypt /vault/custom_config/init.txt --output=/vault/logs/init.txt.decrypted --vault-password-file=/dev/stdin
    cat /vault/logs/init.txt.decrypted
    rm /vault/logs/init.txt.decrypted
    exit
    ```
- **Permission Errors**:
  - Verify host directory permissions:
    ```bash
    ls -ld /home/container-user/docker/openbao/home/{file,logs,custom_config}
    ls -l /home/container-user/docker/openbao/secrets/ansible_vault_password
    ```
  - Fix if needed:
    ```bash
    chown -R 1102:1102 /home/container-user/docker/openbao/home
    chown 1102:1102 /home/container-user/docker/openbao/secrets/ansible_vault_password
    chmod -R u+rwX /home/container-user/docker/openbao/home
    chmod 600 /home/container-user/docker/openbao/secrets/ansible_vault_password
    ```

### 🚀 How to Use the Logging 

**To change the log level:**

By default, the `ENTRYPOINT_LOG_LEVEL` is set to `INFO`. To increase or decrease the verbosity, you can set this environment variable in your `docker-compose.yml` file under the `environment` section for your OpenBao service.

For example, to get more detailed `DEBUG` output:

```yaml
services:
  openbao:
    image: your_image_name:latest
    environment:
      - ENTRYPOINT_LOG_LEVEL=DEBUG # Or TRACE for even more detail
      # ... other environment variables
```

## Contributing
Contributions are welcome! Please submit pull requests or issues to the repository hosting this image.

## License
This project is licensed under the MIT License.