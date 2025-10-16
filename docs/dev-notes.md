
```shell
$ test/test-openbao-container.sh 2>&1 | tee test-log.txt
```

To run with fail-fast and keep the test temporary files for post-test analysis and/or debugging:
```shell
$ test/test-openbao-container.sh -f -k 2>&1 | tee test-log.txt
$ packagedir ../docker-openbao
Ensure output dir exists: ../docker-openbao/save
Packaging directory: docker-openbao
Output will be saved to: ../docker-openbao/save/directory.docker-openbao.txt

Packaging complete! All files from '../docker-openbao' are saved in '../docker-openbao/save/directory.docker-openbao.txt'.
$
```

The directory content is concatenated into a single text file in "./save/directory.docker-openbao.txt"

Post the directory content text file onto the AI platform canvas with following prompt:

```text
The latest test results are in the embedded file with header regex "^### FILE: test-log.txt ###"

Please review the latest docker repo content in the attached repo directory contents including the test results file.
```


---

```shell
$ test/test-openbao-container.sh -j --image-name "lj020326/openbao-ansible" --build-id "build-44-2.3.2" -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -x -j --image-name "lj020326/openbao-ansible" --build-id "build-44-2.3.2" -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -x --junit --skip-build --test-results-dir '.test-results' --build-id build-4181 -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -x --junit --test-results-dir '.test-results' --build-id build-4181 -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -x -j --build-id "build-44-2.3.2" -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -x -j -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -f -k -t test_idempotent_initial_startup 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -f -k -t test_idempotent_modification_restart 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -f -k -t test_idempotent_removal_restart 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -f -k 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh -f 2>&1 | tee test-log.txt
$ test/test-openbao-container.sh 2>&1 | tee test-log.txt
```

Now:
```shell
$ test/test-openbao-container.sh -f -k -t test_idempotent_initial_startup 2>&1 | tee test-log.txt
INFO: --- Starting OpenBao Test Suite ---
INFO: Command line arguments: -f -k -t test_idempotent_initial_startup
INFO: Detected host UID: 501, GID: 20
INFO: Cleaning up containers...
INFO: Cleaning up temporary files...
INFO: Cleanup complete.
INFO: Resetting test directory: .test/test
INFO: Checking for containers with pre-existing mounts to /Users/ljohnson/repos/docker/docker-openbao/.test/test/home...
INFO: No conflicting mounts found.
INFO: Building Docker image: openbao-ansible:test
time="2025-10-15T16:45:40-04:00" level=warning msg="Docker Compose is configured to build using Bake, but buildkit isn't enabled"
 Service openbao-build  Building
Sending build context to Docker daemon  73.32kB

Step 1/23 : ARG OPENBAO_VERSION="2.3.2"
Step 2/23 : ARG OPENBAO_BUILD_IMAGE="openbao:${OPENBAO_VERSION}"
Step 3/23 : FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}
 ---> bdf057a3861b
Step 4/23 : ARG BUILD_DATE
 ---> Using cache
 ---> d9c397a078b5
Step 5/23 : ARG BUILD_ID=devel
 ---> Using cache
 ---> cd4f020a5425
Step 6/23 : LABEL build=$BUILD_ID
 ---> Using cache
 ---> 1997606041ff
Step 7/23 : RUN apk add --no-cache curl
 ---> Using cache
 ---> fdb74b9a001e
Step 8/23 : RUN apk add --no-cache ansible
 ---> Using cache
 ---> 664c4273e652
Step 9/23 : RUN apk add --no-cache jq
 ---> Using cache
 ---> 7d5706531255
Step 10/23 : RUN apk add --no-cache python3 py3-pip py3-yaml
 ---> Using cache
 ---> cc43ed539d8f
Step 11/23 : RUN apk add --no-cache bash  # Added: For re-encryption subprocess
 ---> Using cache
 ---> cb925a60d6b5
Step 12/23 : RUN python3 -m venv /opt/venv &&     /opt/venv/bin/pip install --no-cache-dir hvac pyyaml
 ---> Using cache
 ---> 4cfc1b8f5250
Step 13/23 : COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
 ---> Using cache
 ---> cae51425cbd2
Step 14/23 : COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
 ---> Using cache
 ---> c35d10e2ae82
Step 15/23 : COPY openbao_info.sh /usr/local/bin/openbao_info
 ---> Using cache
 ---> 9c077e9f6ee5
Step 16/23 : COPY openbao_setup.sh /usr/local/bin/openbao_setup.sh
 ---> Using cache
 ---> 68b75393529b
Step 17/23 : COPY openbao_idempotent_setup.py /usr/local/bin/openbao_idempotent_setup.py
 ---> Using cache
 ---> ce519f79e17d
Step 18/23 : RUN chmod 755 /usr/local/bin/docker-entrypoint.sh     /usr/local/bin/env_secrets_expand.sh     /usr/local/bin/openbao_info     /usr/local/bin/openbao_setup.sh     /usr/local/bin/openbao_idempotent_setup.py
 ---> Using cache
 ---> 71ec33b6f8ec
Step 19/23 : ENV PATH="/usr/local/bin:$PATH"
 ---> Using cache
 ---> 744c81b7238d
Step 20/23 : USER openbao
 ---> Using cache
 ---> 930b19ac63d8
Step 21/23 : ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
 ---> Using cache
 ---> 24db46f69cd1
Step 22/23 : LABEL com.docker.compose.image.builder=classic
 ---> Using cache
 ---> 9df7b276be65
Step 23/23 : LABEL com.docker.compose.image.builder=classic
 ---> Using cache
 ---> 7979a907ed7b
Successfully built 7979a907ed7b
Successfully tagged openbao-ansible:test
 Service openbao-build  Built
 openbao-build  Built
INFO: Docker image built successfully.
INFO: Generating docker-compose test file and environment files...
INFO: Generating passwd file...
INFO: Generating group file...
INFO: Generating OpenBao environment file...
INFO: Generated .test/test/openbao.env with OPENBAO_RUN_SETUP set to true.
INFO: Generating test environment file...
INFO: Generated .test/test/.env.test
INFO: Generating OpenBao config file...
INFO: Generated .test/test/home/config/local.json
INFO: Generated .test/test/home/config/openbao_config.yml
INFO: Starting validation test suite.
INFO: Starting validation test suite.
INFO: Starting OpenBao container regression tests...
INFO: Skipping test 1: Test 1: Initial Container Startup and State Management (Targeted test: test_idempotent_initial_startup)
INFO: Skipping test 2: Test 2: Setup Validation (Targeted test: test_idempotent_initial_startup)
INFO: Skipping test 3: Test 3: Auto-Unseal and Container Resilience (Targeted test: test_idempotent_initial_startup)
INFO: Skipping test 4: Test 4: Data Integrity and Accessibility (Targeted test: test_idempotent_initial_startup)
INFO: Skipping test 5: Test 5: External Service Connectivity (Targeted test: test_idempotent_initial_startup)
INFO: --- Running Test 6/8: Test 6: Idempotent Initial Startup ---
--- Running Test: Test 6: Idempotent Initial Startup ---
INFO: Executing command: test_idempotent_initial_startup
INFO: Cleaning up containers...
 Network openbao-ansible-test_default  Removing
 Network openbao-ansible-test_default  Removed
 Network openbao-ansible-test_default  Creating
 Network openbao-ansible-test_default  Created
 Container openbao-ansible-test  Creating
 Container openbao-ansible-test  Created
 Container openbao-ansible-test  Starting
 Container openbao-ansible-test  Started
INFO: Waiting for container to report health...
INFO: Container ID 9095b1948c6350b512c9f53b3a03c25ba39cbcc1843019c651040b65c53eabd9 => CONTAINER_NAME=/openbao-ansible-test
INFO: Health check attempt 1: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 2: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 3: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 4: RUN_STATUS = running, HEALTH_STATUS = starting
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
Cluster Name    vault-cluster-2213cb2c
Cluster ID      d456c53e-3adf-0d5f-0e47-83f784073a67
HA Enabled      false
INFO: Health check attempt 5: RUN_STATUS = running, HEALTH_STATUS = healthy
INFO: Container is healthy.
INFO: --- Running Test: Idempotent Initial Startup ---
INFO: Stop container
 Container openbao-ansible-test  Stopping
 Container openbao-ansible-test  Stopped
 Container openbao-ansible-test  Removing
 Container openbao-ansible-test  Removed
 Network openbao-ansible-test_default  Removing
 Network openbao-ansible-test_default  Removed
INFO: Remove content
INFO: rm -fr .test/test/home/file/*
INFO: rm -f .test/test/home/.setup_completed
INFO: Start container
 Network openbao-ansible-test_default  Creating
 Network openbao-ansible-test_default  Created
 Container openbao-ansible-test  Creating
 Container openbao-ansible-test  Created
 Container openbao-ansible-test  Starting
 Container openbao-ansible-test  Started
INFO: Waiting for container to report health...
INFO: Container ID 7ea07847d7921d972f3ec48ff101e6d0de9fa1c9b3621950473888545b1a9ef0 => CONTAINER_NAME=/openbao-ansible-test
INFO: Health check attempt 1: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 2: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 3: RUN_STATUS = running, HEALTH_STATUS = starting
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
INFO: Health check attempt 4: RUN_STATUS = running, HEALTH_STATUS = starting
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
Cluster Name    vault-cluster-c053e371
Cluster ID      636f0889-3e09-bb44-ac0e-f11354b0cc5e
HA Enabled      false
INFO: Health check attempt 5: RUN_STATUS = running, HEALTH_STATUS = healthy
INFO: Container is healthy.
INFO: Verify setup completed
INFO: Verify a new root token has been created
INFO: Verify policy (exact match)
INFO: Verify userpass (exact key)
INFO: Verify tokens length
INFO: Test passed: Initial idempotent setup.
INFO: Test finished in 51 seconds. Failed: false
INFO: Skipping test 7: Test 7: Idempotent Removal Restart (Targeted test: test_idempotent_initial_startup)
INFO: Skipping test 8: Test 8: Idempotent Modification Restart (Targeted test: test_idempotent_initial_startup)
INFO: --- Test Report ---
INFO: Writing report to .test-results/test-report.test.json
INFO: All tests passed successfully.
INFO: Final status: passed
[
  {
    "test_name": "Test 6: Idempotent Initial Startup",
    "failed": false,
    "message": "Test passed successfully."
  }
]
$ 
```

The latest test results are in the embedded file with header regex "^### FILE: test-log.txt ###"

Please review the latest docker repo content in the attached repo directory contents including the test results file.
