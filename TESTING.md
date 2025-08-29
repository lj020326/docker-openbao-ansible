
# Test Run Guide

To execute your tests with these non-root compliant scripts, follow these steps precisely:

## Preparation (Before any docker stack deploy)

1) **Update Files**: Replace your existing `docker-entrypoint.sh` and `fetch_openbao_info.sh` files with the new content provided above.

2) **Clean Host Directories**: Ensure your host's mounted `/vault` directories (e.g., `/home/container-user/docker/openbao/home/config/`, `/home/container-user/docker/openbao/home/file/`, `/home/container-user/docker/openbao/home/logs/`) are empty of any previous init files. This is crucial for a clean initialization.

```Bash
rm -fr /home/container-user/docker/openbao/home/file/*
rm -fr /home/container-user/docker/openbao/home/logs/*
rm -fr /home/container-user/docker/openbao/home/config/init*
```

3) **Verify Host Permissions**: This is critical for non-root containers.  Set ownership for the parent vault directory (adjust path as needed) to match the `docker-compose.yml` defined `user` (e.g., `user: 1102:1102`).  This will ensure the host directories you are mounting into `/vault` (e.g., `/home/container-user/docker/openbao/home`) are owned by the same user ID (UID) and group ID (GID) that `openbao` uses inside the container as defined in the `docker-compose.yml` user key.  Note that the `openbao` user is also mapped to the user/group ID by the passwd/group mounts.

```Bash
$ grep "user:" docker-compose.yml
    user: 1102:1102
$ cat openbao/passwd
openbao:x:1102:1102:openbao user:/vault:/bin/bash
$ cat openbao/group
openbao:x:1102:
$ id container-user
uid=1102(container-user) gid=1102(container-user) groups=4(adm),24(cdrom),30(dip),46(plugdev),998(docker),1102(container-user)
# Example: To set ownership for the parent directory (adjust path as needed) to match the `docker-compose.yml` defined `user`
$ sudo chown -R 1102:1102 /home/container-user/docker/openbao/home
```

If these permissions are not correct, the container will likely fail to start due to lack of write access.

## Test Criteria Execution

1. **Initialization and encrypting token and keys**:

- **Deploy the stack**:

```Bash
docker pull lj020326/openbao-ansible:latest
docker stack deploy -c docker-compose.yml docker_stack --with-registry-auth
```

**Monitor logs for initialization**: Observe the OpenBao container logs for messages indicating initialization, encryption, and unsealing. Look for Entrypoint INFO: OpenBao initialized successfully. and Entrypoint INFO: OpenBao initialization details encrypted to /vault/config/init.json.enc.

```Bash
docker service logs -f docker_stack_openbao
```

(Expect to see logs indicating initialization, encryption, and auto-unseal, all without su-exec errors)

2. **Remove container**:

**Remove the OpenBao service**:

```Bash
docker service rm docker_stack_openbao
```

(This removes the running container, but your encrypted init.json.enc file should persist on the host volume.)

3. **Restart container to test decrypting encrypted keys and auto unsealing existing vault**:

**Redeploy the stack (only OpenBao service will be created/updated)**:

```Bash
docker stack deploy -c docker-compose.yml docker_stack --with-registry-auth
```

**Monitor logs for auto-unseal**: This time, you should see logs indicating decryption and auto-unsealing of an already initialized Vault. Look for Entrypoint INFO: Found encrypted init JSON file at /vault/config/init.json.enc, attempting auto-unseal. and Entrypoint INFO: Auto-unseal process completed... OpenBao successfully unsealed.

```Bash
docker service logs -f docker_stack_openbao
```

(Expect logs confirming decryption of existing keys and successful auto-unseal.)

4. **Fetch tests to verify initialization content can be fetched**:

**Get the container ID**:

```Bash
CONTAINER_ID=$(docker ps --filter "name=docker_stack_openbao" --format "{{.ID}}")
echo "OpenBao Container ID: ${CONTAINER_ID}"
```

**Fetch and display full content**:

```Bash
docker exec -it "${CONTAINER_ID}" sh -c '/usr/local/bin/fetch_openbao_info.sh --content'
```

(Expect to see the JSON output containing unseal_keys_b64 and root_token.)

**Fetch only the root token**:

```Bash
ROOT_TOKEN=$(docker exec -it "${CONTAINER_ID}" sh -c '/usr/local/bin/fetch_openbao_info.sh --root-token')
echo "Retrieved Root Token: ${ROOT_TOKEN}"
```

(Expect only the root token string to be printed, with no extra debug output.)

5. **Host based curl tests against the Traefik OpenBao HTTPS endpoint**:

**Test health (non-token based)**:

```Bash
curl -s "https://openbao.admin.johnson.int/v1/sys/health" | jq
```

(Expect JSON output with "sealed": false, "initialized": true.)

**Test sys/mounts (with token)**:

```Bash
# You'll need the ROOT_TOKEN from step 4 for this.
# Make sure your host has jq installed for pretty printing.
curl -s -H "X-Vault-Token: ${ROOT_TOKEN}" "https://openbao.admin.johnson.int/v1/sys/mounts" | jq
```

(Expect JSON output listing mounted secrets engines, confirming successful authentication with the root token.)
