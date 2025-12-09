# **OpenBao Test Run Guide**

This guide details the process for running the OpenBao container test suite. The framework has been designed for portability and consistency by dynamically mapping your host user's ID to the container's user. This eliminates the need for manual file editing and ensures tests run correctly regardless of your host environment.

## ** The Testing Workflow **

The testing workflow is managed by a single script, test/test_openbao_container.sh, which acts as the orchestrator. The key steps are:

1. **UID/GID Detection**: The test script automatically detects the UID (User ID) and GID (Group ID) of the host user running the script.  
2. **File Generation**: It dynamically generates passwd and group files, ensuring the openbao user inside the container is correctly mapped to your host user's UID and GID.  
3. **Volume Permissions**: It uses sudo chown to set the correct permissions on the host volumes (openbao/home/) before they are mounted. This is a critical step for non-root container operation.  
4. **Docker Compose Execution**: The script then executes docker compose while passing the detected UID and GID as environment variables. The docker-compose.test.yml file is configured to receive these values, so it remains static and universal.

Notes, in the test steps below, the ".test" directory is a temporary directory created to run through the test cycle and removed after. 

## Build the test image

```shell
$ docker compose --project-name openbao-ansible-test -f test/docker-compose.build.yml build --env OPENBAO_TEST_IMAGE=openbao:test
$ 
```

## debugging

**Get the container ID**:

```Bash
CONTAINER_ID=$(docker ps --filter "name=docker_stack_openbao" --format "{{.ID}}")
echo "OpenBao Container ID: ${CONTAINER_ID}"
```

**Fetch and display full content**:

```Bash
docker exec -it "${CONTAINER_ID}" sh -c 'openbao_info --content'
docker exec -it "${CONTAINER_ID}" sh
/ $ bao login s.tokenvaluehere
## list the existing tokens
/ $ bao list auth/token/accessors
Keys
----
7QXrR8WEOINnhVwqdqOWIF0u
8QAJmBKmg2AdSc8goILur5Qe
OdZkGoVh6wZm5VxGvq1lWxnD
/ $ 
## get the token information
/ $ bao token lookup -accessor 7QXrR8WEOINnhVwqdqOWIF0u
Key                 Value
---                 -----
accessor            7QXrR8WEOINnhVwqdqOWIF0u
creation_time       1765001453
creation_ttl        168h
display_name        userpass-test_user
entity_id           52ae335c-8f1d-336c-9d6f-e51ae12f19af
expire_time         2025-12-13T01:10:53.922626206-05:00
explicit_max_ttl    0s
id                  n/a
issue_time          2025-12-06T01:10:53.922629993-05:00
meta                map[username:test_user]
num_uses            0
orphan              true
path                auth/userpass/login/test_user
policies            [default user]
renewable           true
ttl                 85h13m50s
type                service
/ $ 
/ $ bao token lookup -accessor 8QAJmBKmg2AdSc8goILur5Qe
Key                 Value
---                 -----
accessor            8QAJmBKmg2AdSc8goILur5Qe
creation_time       1765293475
creation_ttl        24h
display_name        token-admin-renewed
entity_id           n/a
expire_time         2025-12-10T10:17:55.59609141-05:00
explicit_max_ttl    0s
id                  n/a
issue_time          2025-12-09T10:17:55.596094987-05:00
meta                <nil>
num_uses            0
orphan              false
path                auth/token/create
policies            [admin default]
renewable           true
ttl                 22h20m28s
type                service
/ $ 
/ $ bao token lookup -accessor OdZkGoVh6wZm5VxGvq1lWxnD
Key                 Value
---                 -----
accessor            OdZkGoVh6wZm5VxGvq1lWxnD
creation_time       1764947570
creation_ttl        0s
display_name        root
entity_id           n/a
expire_time         <nil>
explicit_max_ttl    0s
id                  n/a
meta                <nil>
num_uses            0
orphan              true
path                auth/token/root
policies            [root]
ttl                 0s
type                service
/ $
/ $ bao secrets list -format=json
## The pki/ mount (description: PKI secrets engine for Root CA) is a legacy or misconfigured mount in this case.
## If it’s not used, disable it to avoid confusion:
/ $ bao write -force sys/mounts/pki/tune default_lease_ttl=0s
/ $ bao delete sys/mounts/pki
## verify configuration
/ $ bao read pki/config
/ $ bao list pki/issuers
/ $ bao read pki/roles/internal-api
## Verify OpenBao Configuration:
## Confirm the pki-intermediate mount:
## Expected: type: pki, description: Intermediate CA PKI.
/ $ bao read sys/mounts/pki-intermediate
## Check issuers:
/ $ bao list pki-intermediate/issuers
/ $ bao read pki-intermediate/config
## Ensure at least one issuer is listed and default_issuer is set (e.g., a UUID like 123e4567-e89b-12d3-a456-426614174000).
## Verify the internal-api role:
## Expected: allowed_domains: ["api.internal"], allow_subdomains: true, ttl: 720h, max_ttl: 720h.
/ $ bao read pki-intermediate/roles/internal-api
## to show vault_admin_token permissions
/ $ bao token capabilities <vault_admin_token> sys/mounts/pki-intermediate
/ $ bao token capabilities <vault_admin_token> pki-intermediate/config/ca
/ $ bao token capabilities <vault_admin_token> pki-intermediate/issuers
/ $ bao token capabilities <vault_admin_token> pki-intermediate/roles/internal-api
/ $ bao list pki-intermediate/issuers
Keys
----
46b0e61b-0498-3f5e-4a25-c41615494679
627570b1-6e16-d590-a4cb-0e629a0abd17
c6bb2f87-6775-8db9-ba68-25c76c9f5402
/ $ 
/ $ bao read pki-intermediate/roles/internal-api
Key                                   Value
---                                   -----
allow_any_name                        false
allow_bare_domains                    false
allow_glob_domains                    false
allow_ip_sans                         true
allow_localhost                       true
allow_subdomains                      true
allow_token_displayname               false
allow_wildcard_certificates           true
allowed_domains                       [dettonville.int johnson.int admin.johnson.int control02.johnson.int plex.johnson.int media.johnson.int admin01.dettonville.int admin02.dettonville.int admin03.dettonville.int admin.dettonville.int]
allowed_domains_template              false
allowed_other_sans                    []
allowed_serial_numbers                []
allowed_uri_sans                      []
allowed_uri_sans_template             false
allowed_user_ids                      []
basic_constraints_valid_for_non_ca    false
client_flag                           true
cn_validations                        [email hostname]
code_signing_flag                     false
country                               []
email_protection_flag                 false
enforce_hostnames                     true
ext_key_usage                         []
ext_key_usage_oids                    []
generate_lease                        false
issuer_ref                            default
key_bits                              2048
key_type                              rsa
key_usage                             [DigitalSignature KeyAgreement KeyEncipherment]
locality                              []
max_ttl                               72h
no_store                              false
not_after                             n/a
not_after_bound                       permit
not_before                            n/a
not_before_bound                      permit
not_before_duration                   30s
organization                          []
ou                                    []
policy_identifiers                    []
postal_code                           []
province                              []
require_cn                            true
server_flag                           true
signature_bits                        256
street_address                        []
ttl                                   12h
use_csr_common_name                   true
use_csr_sans                          true
use_pss                               false
/ $ 
/ $ bao read sys/mounts
Key                  Value
---                  -----
cubbyhole/           map[accessor:cubbyhole_5023a686 config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:0] description:per-token private secret storage external_entropy_access:false local:true options:<nil> plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:false type:cubbyhole uuid:f15e26cd-3241-c5fc-7d87-c60570a1a756]
identity/            map[accessor:identity_168b3f31 config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:0 passthrough_request_headers:[Authorization]] description:identity store external_entropy_access:false local:false options:<nil> plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:false type:identity uuid:520802e4-fda1-ab97-0097-09c8f12b6293]
kv/                  map[accessor:kv_c7de6f0f config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:0] deprecation_status:supported description: external_entropy_access:false local:false options:map[version:2] plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:false type:kv uuid:5698a353-6913-0f79-6344-e9d6f36b1b34]
pki-intermediate/    map[accessor:pki_d8c3be41 config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:0] deprecation_status:supported description:Intermediate CA PKI external_entropy_access:false local:false options:map[] plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:false type:pki uuid:81cf236c-c4f4-8a8a-4ad0-2d61985d6330]
pki/                 map[accessor:pki_90fd3ed1 config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:1576800000] deprecation_status:supported description:PKI secrets engine for Root CA external_entropy_access:false local:false options:map[] plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:false type:pki uuid:e571f146-ed5d-df81-4900-092f6a2d2e88]
sys/                 map[accessor:system_ce8bc43b config:map[default_lease_ttl:0 force_no_cache:false max_lease_ttl:0 passthrough_request_headers:[Accept]] description:system endpoints used for control, policy and debugging external_entropy_access:false local:false options:<nil> plugin_version: running_plugin_version:v2.3.2+builtin.bao running_sha256: seal_wrap:true type:system uuid:c3ca1f7e-2088-72fe-9184-5b4698024eab]
## Manually test certificate issuance:
/ $ bao write pki-intermediate/issue/internal-api common_name=admin01.dettonville.int ttl=720h
## to reset the pki-intermediate mount
/ $ bao write -force sys/mounts/pki-intermediate
```

## Run the test image

```shell
$ mkdir -p .test
$ echo "openbao:x:$(id -u):$(id -g):OpenBao User:/vault:/bin/sh" > .test/passwd
$ echo "openbao:x:$(id -g):" > .test/group
$ cat "
OPENBAO_TEST_IMAGE=openbao:test
OPENBAO_TEST_DIR=.test
OPENBAO_CONTAINER_HOME_DIR=/vault
UID=$(id -u)
GID=$(id -g)
" > .test/.env.test
$ 
$ ljohnson@lees-mbp:[docker-openbao](main)$ ./test/test-openbao-container.sh -j -k 2>&1 | tee test-log.txt
INFO: --- Starting OpenBao Test Suite ---
INFO: Command line arguments: -x -k
INFO: Detected host UID: 501, GID: 20
...
...
...
$ ## with debug
$ ljohnson@lees-mbp:[docker-openbao](main)$ ./test/test-openbao-container.sh -x -j -k 2>&1 | tee test-log.txt
$ alias run_docker_compose="docker compose -f test/docker-compose.test.yml --env-file .test/test/.env.test"
$ 
$ run_docker_compose up -d
$ run_docker_compose up -d openbao-test
$ run_docker_compose logs -n 10 -f openbao-test
$ 
$ ## if project names are used as done within the test script then introspect to find the project name used
$ ## list the docker projects to get the project name
$ docker compose ls -a
$ 
$ alias run_docker_compose="docker compose --project-name openbao-ansible-test -f test/docker-compose.test.yml --env-file .test/test/.env.test"
$ 
$ ./test/test-openbao-container.sh -j --image-name "lj020326/openbao-ansible" --build-id "build-44-2.3.2" -k 2>&1 | tee test-log.txt
$ OPENBAO_TEST_BUILD_ID="test"
$ PROJECT_NAME=$(docker compose ls -q | head -n 1)
$ alias run_docker_compose="docker compose --project-name ${PROJECT_NAME} -f test/docker-compose.test.yml --env-file .test/${OPENBAO_TEST_BUILD_ID}/.env.test"
$ 
$ run_docker_compose up -d
$ run_docker_compose up -d openbao-test
$ run_docker_compose logs -f openbao-test
$ 
$ 
$ CONTAINER_ID=$(docker compose --project-name openbao-ansible-test -f test/docker-compose.test.yml --env-file .test/test/.env.test ps -q openbao-test)
$ echo "CONTAINER_ID=${CONTAINER_ID}"
$ docker logs "$CONTAINER_ID" 2>&1 | grep -i "openbao_setup.sh"
$ 
$ run_docker_compose logs openbao-test
$ run_docker_compose ps 
$ run_docker_compose ps -a openbao-test
$ run_docker_compose ps -q openbao-test
$ ## to show/verify the mounts
$ docker inspect --format '{{json .Mounts}}' lj020326-openbao-ansible-build-44-2-3-2 | jq
...
$ 
$ run_docker_compose down
$ 
$ run_docker_compose up -d
$ run_docker_compose exec -T openbao-test openbao_info --content
$ run_docker_compose exec -T openbao-test openbao_info --root-token
$ run_docker_compose exec -T openbao-test openbao_info --admin-token
$ run_docker_compose exec -T openbao-test bao mounts -format=json
$ run_docker_compose exec -T openbao-test bao secrets list -format=json
$ run_docker_compose exec -T openbao-test bao secrets list -format=json | jq -r '.["kv/"].type'
$ run_docker_compose exec -T openbao-test bao status
$ run_docker_compose exec -T openbao-test bash -c "ls /vault/config/init.json.enc"
$ run_docker_compose exec -T openbao-test sh
$ run_docker_compose exec -T openbao-test sh -c "openbao_info --content"
$ run_docker_compose exec -T openbao-test sh -c "ls /vault/config/init.json.enc"
$ run_docker_compose exec -T openbao-test sh -c 'openbao_info --root-token'
$ run_docker_compose exec openbao-test sh
$ local root_token=$(docker compose --project-name openbao-ansible-test -f test/docker-compose.test.yml --env-file .test/.env.test exec -T "${CONTAINER_SERVICE_NAME}" openbao_info --root-token)
$ local admin_token=$(docker compose --project-name openbao-ansible-test -f test/docker-compose.test.yml --env-file .test/.env.test exec -T "${CONTAINER_SERVICE_NAME}" openbao_info --admin-token)
$ 
$ run_docker_compose down
$ rm -fr .test
```

## Run the test image with a specific build id

```shell
./test/test-openbao-container.sh -j --image-name "lj020326/openbao-ansible" --build-id "build-44-2.3.2" -k 2>&1 | tee test-log.txt
INFO: --- Starting OpenBao Test Suite ---
INFO: Command line arguments: -j --image-name lj020326/openbao-ansible --build-id build-44-2.3.2 -k
INFO: Detected host UID: 501, GID: 20
INFO: Cleaning up containers...
 Container lj020326-openbao-ansible-build-44-2-3-2  Stopping
 Container lj020326-openbao-ansible-build-44-2-3-2  Stopped
 Container lj020326-openbao-ansible-build-44-2-3-2  Removing
 Container lj020326-openbao-ansible-build-44-2-3-2  Removed
 Network lj020326-openbao-ansible-build-44-2-3-2_default  Removing
 Network lj020326-openbao-ansible-build-44-2-3-2_default  Removed
INFO: Cleaning up temporary files...
INFO: Cleanup complete.
INFO: Resetting test directory: .test
INFO: Building Docker image: lj020326/openbao-ansible:build-44-2.3.2
 Service openbao-build  Building
Sending build context to Docker daemon  62.33kB
Step 1/19 : ARG OPENBAO_VERSION="2.3.2"
Step 2/19 : ARG OPENBAO_BUILD_IMAGE="openbao:${OPENBAO_VERSION}"
Step 3/19 : FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}
 ---> bdf057a3861b
Step 4/19 : ARG BUILD_DATE
 ---> Using cache
 ---> 31d9d13d4cc1
Step 5/19 : ARG BUILD_ID=devel
 ---> Using cache
 ---> 796dc34fd6b8
Step 6/19 : LABEL build=$BUILD_ID
 ---> Using cache
 ---> bccf8585fc56
Step 7/19 : RUN apk add --no-cache curl
 ---> Using cache
 ---> 5e640ba05f76
Step 8/19 : RUN apk add --no-cache ansible
 ---> Using cache
 ---> 893faa778ce6
Step 9/19 : RUN apk add --no-cache jq
 ---> Using cache
 ---> 336dcfe67020
Step 10/19 : COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
 ---> Using cache
 ---> dce566419181
Step 11/19 : COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
 ---> Using cache
 ---> 25c75796070c
Step 12/19 : COPY openbao_info.sh /usr/local/bin/openbao_info
 ---> Using cache
 ---> fbd7950447e4
Step 13/19 : COPY openbao_setup.sh /usr/local/bin/openbao_setup.sh
 ---> Using cache
 ---> 97e047c39208
Step 14/19 : RUN chmod 755 /usr/local/bin/docker-entrypoint.sh   /usr/local/bin/env_secrets_expand.sh   /usr/local/bin/openbao_info   /usr/local/bin/openbao_setup.sh
 ---> Using cache
 ---> f090b158412f
Step 15/19 : COPY configs/policy_admin.hcl /
 ---> Using cache
 ---> 7030ffbc6a32
Step 16/19 : COPY configs/policy_user.hcl /
 ---> Using cache
 ---> 265dbdfbd10e
Step 17/19 : USER openbao
 ---> Using cache
 ---> 6c463f3e89ce
Step 18/19 : ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
 ---> Using cache
 ---> 6691445cb77a
Step 19/19 : LABEL com.docker.compose.image.builder=classic
 ---> Using cache
 ---> 4c44ddc0b451
Successfully built 4c44ddc0b451
Successfully tagged lj020326/openbao-ansible:build-44-2.3.2
 Service openbao-build  Built
 openbao-build  Built
INFO: Docker image built successfully.
INFO: Generating docker-compose test file and environment files...
INFO: Generating passwd file...
INFO: Generating group file...
INFO: Generating OpenBao environment file...
INFO: Generated .test/openbao.env with OPENBAO_RUN_SETUP set to true.
INFO: Generating test environment file...
INFO: Generated .test/.env.test
INFO: Generating OpenBao config file...
INFO: Generated .test/home/config/local.json
INFO: Starting validation test suite.
--- Running Test: Initial Container Startup and State Management ---
INFO: Executing command: test_initialization
INFO: Verifying container startup and health...
INFO: Bringing up the stack for the first time.
 Network lj020326-openbao-ansible-build-44-2-3-2_default  Creating
 Network lj020326-openbao-ansible-build-44-2-3-2_default  Created
 Container lj020326-openbao-ansible-build-44-2-3-2  Creating
 Container lj020326-openbao-ansible-build-44-2-3-2  Created
 Container lj020326-openbao-ansible-build-44-2-3-2  Starting
 Container lj020326-openbao-ansible-build-44-2-3-2  Started
INFO: Waiting for container health check to pass (unsealed state)...
INFO: Waiting for container to report health...
INFO: Container ID d59a2aca25a976590802beb5ebc32905bee7953b062479159d0650f2d98cf9ad => CONTAINER_NAME=/lj020326-openbao-ansible-build-44-2-3-2
INFO: Health check attempt 1: Status = starting
INFO: Logging vault initialization status...
Key                Value
---                -----
Seal Type          shamir
Initialized        false
Sealed             true
Total Shares       0
Threshold          0
Unseal Progress    0/0
Unseal Nonce       n/a
Version            2.3.2
Build Date         2025-08-08T04:05:27Z
Storage Type       file
HA Enabled         false
INFO: Health check attempt 2: Status = starting
INFO: Logging vault initialization status...
Key                Value
---                -----
Seal Type          shamir
Initialized        false
Sealed             true
Total Shares       0
Threshold          0
Unseal Progress    0/0
Unseal Nonce       n/a
Version            2.3.2
Build Date         2025-08-08T04:05:27Z
Storage Type       file
HA Enabled         false
INFO: Health check attempt 3: Status = starting
INFO: Logging vault initialization status...
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    0/3
Unseal Nonce       n/a
Version            2.3.2
Build Date         2025-08-08T04:05:27Z
Storage Type       file
HA Enabled         false
INFO: Health check attempt 4: Status = starting
INFO: Logging vault initialization status...
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    5
Threshold       3
Version         2.3.2
Build Date      2025-08-08T04:05:27Z
Storage Type    file
Cluster Name    vault-cluster-a91d0aa5
Cluster ID      3fd7a2ed-5fdc-4880-b14c-e706a37b6411
HA Enabled      false
INFO: Health check attempt 5: Status = healthy
INFO: Container is healthy.
INFO: Verifying that init.json.enc exists on the host...
INFO: Encrypted init file found.
INFO: Checking vault initialization status...
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    5
Threshold       3
Version         2.3.2
Build Date      2025-08-08T04:05:27Z
Storage Type    file
Cluster Name    vault-cluster-a91d0aa5
Cluster ID      3fd7a2ed-5fdc-4880-b14c-e706a37b6411
HA Enabled      false
INFO: Validating openbao_info content output...
INFO: Test finished in 27 seconds. Status: 
--- Running Test: Setup Validation ---
INFO: Executing command: test_setup_validation
INFO: Verifying OpenBao policies and secrets...
INFO: Verifying admin token is present in the encrypted init file...
INFO: Admin token successfully retrieved.
INFO: ROOT_TOKEN: s.yUy68Kz2ef5WGFCle8Lem6k5
Success! You are now authenticated. The token information displayed below is
already stored in the token helper. You do NOT need to run "bao login" again.
Future OpenBao requests will automatically use this token.

Key                  Value
---                  -----
token                s.yUy68Kz2ef5WGFCle8Lem6k5
token_accessor       0TX1xTJqHcjrHHLl4Ml2wMpW
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
INFO: Admin policy found.
INFO: User policy found.
INFO: Userpass auth method is enabled.
INFO: KV secrets engine is enabled.
INFO: Test finished in 7 seconds. Status: 
--- Running Test: Auto-Unseal and Container Resilience ---
INFO: Executing command: test_auto_unseal
INFO: Testing auto-unseal by restarting the container...
 Container lj020326-openbao-ansible-build-44-2-3-2  Restarting
 Container lj020326-openbao-ansible-build-44-2-3-2  Started
INFO: Container restarted.
INFO: Waiting for container health check to pass again...
INFO: Waiting for container to report health...
INFO: Container ID d59a2aca25a976590802beb5ebc32905bee7953b062479159d0650f2d98cf9ad => CONTAINER_NAME=/lj020326-openbao-ansible-build-44-2-3-2
INFO: Health check attempt 1: Status = starting
INFO: Logging vault initialization status...
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    0/3
Unseal Nonce       n/a
Version            2.3.2
Build Date         2025-08-08T04:05:27Z
Storage Type       file
HA Enabled         false
INFO: Health check attempt 2: Status = starting
INFO: Logging vault initialization status...
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    0/3
Unseal Nonce       n/a
Version            2.3.2
Build Date         2025-08-08T04:05:27Z
Storage Type       file
HA Enabled         false
INFO: Health check attempt 3: Status = starting
INFO: Logging vault initialization status...
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    5
Threshold       3
Version         2.3.2
Build Date      2025-08-08T04:05:27Z
Storage Type    file
Cluster Name    vault-cluster-a91d0aa5
Cluster ID      3fd7a2ed-5fdc-4880-b14c-e706a37b6411
HA Enabled      false
INFO: Health check attempt 4: Status = healthy
INFO: Container is healthy.
INFO: OpenBao successfully auto-unsealed after restart.
INFO: Test finished in 20 seconds. Status: 
--- Running Test: Data Integrity and Accessibility ---
INFO: Executing command: test_data_integrity
INFO: Verifying data integrity and accessibility of keys...
INFO: Checking if root token can be fetched from init.json.enc...
INFO: Root token successfully fetched.
INFO: Checking if admin token can be fetched from init.json.enc...
INFO: Admin token successfully fetched.
Success! You are now authenticated. The token information displayed below is
already stored in the token helper. You do NOT need to run "bao login" again.
Future OpenBao requests will automatically use this token.

Key                  Value
---                  -----
token                s.yUy68Kz2ef5WGFCle8Lem6k5
token_accessor       0TX1xTJqHcjrHHLl4Ml2wMpW
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
INFO: Writing a test secret to KV engine...
INFO: Test secret written.
INFO: Reading the test secret back with retries...
INFO: Secret value verified.
INFO: Test finished in 5 seconds. Status: 
--- Running Test: External Service Connectivity ---
INFO: Executing command: test_external_connectivity
INFO: Verifying external connectivity from host to container...
INFO: Retrieving container ID and host port mapping...
INFO: Test container ports:
map[8200/tcp:[{0.0.0.0 55062}]]
INFO: Container ID: , Host Port: 55062
INFO: Testing unauthenticated health endpoint...
INFO: Unauthenticated health check passed.
INFO: Testing authenticated endpoint with root token...
INFO: Authenticated mounts check with root token passed.
INFO: Testing authenticated endpoint with admin token...
INFO: Authenticated mounts check with admin token passed.
INFO: Test finished in 4 seconds. Status: 
INFO: --- Test Report ---
INFO: Writing report to .test-results/test-report.json
INFO: All tests passed successfully.
Successfully converted '.test-results/test-report.json' to '.test-results/junit-report.xml'.
INFO: Final status: passed
ljohnson@lees-mbp:[docker-openbao](main)$ 
```

To run with fail-fast and keep the test temporary files for post-test analysis and/or debugging:
```shell
$ test/test-openbao-container.sh -f -k 2>&1 | tee test-log.txt
$ alias run_docker_compose="docker compose -f test/docker-compose.test.yml --env-file .test/test/.env.test"
$ run_docker_compose ps
$ ls -Fla .test/test/
$ ls -Fla .test/test/home/
$ ls -Fla .test/test/home/config/
$ cat .test/test/home/config/init.json
$ run_docker_compose exec -T openbao-test openbao_info --content
$ packagedir ../docker-openbao
```
