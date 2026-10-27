# Testing & Code Quality Guide

This repository provides containerized builds, target across multiple Python and Ansible-core version matrices. This document outlines the testing workflow, linting rules, pre-commit configuration, and local validation steps required to ensure build consistency and container health.

---

## 🛠️ Prerequisites

Before running tests locally, ensure you have the following tools installed on your host machine:

* **Docker** (or Docker Desktop with Buildx enabled)
* **Python 3.10+**
* **pre-commit** (`pip install pre-commit`)
* **hadolint** (Dockerfile linter)
* **shellcheck** (Bash script linter)
* **yamllint** (YAML syntax & structure linter)
* **ruff** (Python linter and formatter)

---

## 🚀 Quick Start (Local Pre-Commit Checks)

We use `pre-commit` hooks configured via `.pre-commit-config.yaml` to enforce static code analysis, syntax checking, secret prevention (Gitleaks), and cleanups across Python, Shell scripts, Dockerfiles, and YAML configurations.

### 1. Pre-Commit Hook Configuration (`.pre-commit-config.yaml`)
The repository includes checks for:
* **Standard pre-commit-hooks**: Trailing whitespaces, EOF fixes, YAML/JSON validation, large file checks, merge conflict indicators, and LF line-ending enforcement.
* **Cleanup hook**: Automatic removal of temporary test/build artifacts (e.g., `.package_dir.*.yml`, `__pycache__`, build/dist directories).
* **Hadolint (`hadolint-bin`)**: Enforces Dockerfile best practices.
* **Yamllint**: YAML formatting and syntax verification against `.yamllint`.
* **Shellcheck (`shellcheck-py`)**: Bash script linter for helper scripts and test drivers.
* **Ruff**: Fast Python linting and formatting.
* **Gitleaks**: Credential and secret leak prevention.

### 2. Running Pre-Commit Locally
1. Install git hooks in your local clone:
   ```bash
   pre-commit install
   ```
2. Run all checks manually across the repository:
   ```bash
   pre-commit run --all-files
   ```

---

## 🔍 Static Code Analysis & Linting

### 1. Dockerfile Linting
To check `image/Dockerfile` against Docker best practices (multi-stage verification, package pinning, layer reduction):

```bash
hadolint image/Dockerfile
```

### 2. Shell Script Validation
All `.sh` helper scripts (e.g., `image/retry_command.sh` and `build-push-images.sh`) are linted with `shellcheck`:

```bash
shellcheck image/retry_command.sh build-push-images.sh
```

### 3. YAML Syntax & Ansible Galaxy Requirements
Validate configuration syntax for `.continue/config.yaml`, `.jenkins/docker-build-config.yml`, and `image/requirements.yml`:

```bash
yamllint .
ansible-lint image/requirements.yml
```

---

## 🐳 Container Build Verification

### Local Single Image Build Test
To test a build locally using default arguments:

```bash
docker build \
  --build-arg OPENBAO_VERSION="2.7" \
  -t local/openbao-ansible:test image/
```

---

## 🐳 Container Test Suites

This guide details the process for running the OpenBao container test suite. The framework has been designed for portability and consistency by dynamically mapping your host user's ID to the container's user. This eliminates the need for manual file editing and ensures tests run correctly regardless of your host environment.

Run container functional tests and migration validation suites (such as test/test-openbao-container.sh) to verify container health, auto-unseal behavior, data integrity, and upgrade paths.

```bash
./test/test-openbao-container.sh
```

### **1. The Testing Workflow**

The testing workflow is managed by a single script, test/test_openbao_container.sh, which acts as the orchestrator. The key steps are:

1. **UID/GID Detection**: The test script automatically detects the UID (User ID) and GID (Group ID) of the host user running the script.
2. **File Generation**: It dynamically generates passwd and group files, ensuring the openbao user inside the container is correctly mapped to your host user's UID and GID.
3. **Volume Permissions**: It uses sudo chown to set the correct permissions on the host volumes (openbao/home/) before they are mounted. This is a critical step for non-root container operation.
4. **Docker Compose Execution**: The script then executes docker compose while passing the detected UID and GID as environment variables. The docker-compose.test.yml file is configured to receive these values, so it remains static and universal.

### **2. Updated Docker Compose Configuration**

The docker-compose.test.yml file has been updated to use environment variables for the user ID, removing the hard-coded values and making the file portable.

```yaml
# In docker-compose.test.yml
services:
  openbao:
    # This user directive uses environment variables
    user: ${UID}:${GID}
    ...

```

### **3. The Test Script**

The `test/test-openbao-container.sh` script handles the entire dynamic process. It is the only command you need to run to prepare and execute the tests.

```shell
test/test-openbao-container.sh 2>&1 | tee test-log.txt
```

Run for specified version
```shell
env OPENBAO_VERSION="2.5" test/test-openbao-container.sh -j -k
env OPENBAO_VERSION="2.6" test/test-openbao-container.sh -j -k
env OPENBAO_VERSION="2.7" test/test-openbao-container.sh -j -k
env OPENBAO_VERSION="latest" test/test-openbao-container.sh -j -k
```

Run for specified version and test
```shell
env OPENBAO_VERSION="2.7" test/test-openbao-container.sh -j -k -t 6
```

Or run with full debugging
```shell
bash -x test/test-openbao-container.sh 2>&1 | tee test-log.txt
```

### **4. Detailed Test Scenarios**

The test suite is designed to cover the entire lifecycle of the container, from its initial cold start to continuous operation. It's not just a single health check; it's a series of integrated tests that validate the most critical features of the non-root compliant OpenBao container.

#### **Initial Container Startup and State Management**

This scenario tests the "cold start" behavior of the container. It's the very first time the container runs and encounters a completely empty configuration.

* **What it covers**: The test verifies that the docker-entrypoint.sh script correctly detects the uninitialized state of the OpenBao vault. It then triggers the openbao operator init command, which generates a new root token and a set of unseal keys.
* **Why it's important**: This validates that the container can perform its essential one-time setup without manual intervention. The ability to automatically generate and securely manage these critical secrets is a cornerstone of this solution.
* **Expected outcome**: The logs should show openbao operator init executing successfully. Crucially, a new file, init.json.enc, should be created in the mounted volume openbao/home/config, containing the encrypted unseal keys and root token.

#### **Auto-Unseal and Container Resilience**

This scenario simulates a real-world event, such as a container restart. The test script removes the running container, but leaves the data volumes intact.

* **What it covers**: Upon restart, the docker-entrypoint.sh script checks the state of the vault again. This time, it finds the encrypted init.json.enc file from the previous step. It automatically decrypts this file and uses the unseal keys to unseal the vault without requiring any user input.
* **Why it's important**: This is a crucial test for production environments. It proves that the container is resilient and can recover from a restart automatically. It ensures that the auto-unseal functionality is working as designed and that the vault becomes available for use almost immediately after boot.
* **Expected outcome**: The logs should clearly indicate that the container found the init.json.enc file, decrypted its contents, and successfully unsealed the vault.

#### **Data Integrity and Accessibility**

This test verifies that the sensitive data generated during the initialization phase is both securely stored and accessible when needed.

* **What it covers**: The test uses a dedicated utility script, openbao_info, that runs inside the container to decrypt the init.json.enc file. The test suite validates two key scenarios:
  1. Fetching and displaying the entire decrypted content.
  2. Fetching only the root token, isolated from the rest of the file.
* **Why it's important**: This confirms that the ansible-vault decryption process is working as intended and that the root token can be programmatically retrieved for use in other scripts or automations. This is essential for securely bootstrapping other services that need to authenticate with OpenBao.

#### **External Service Connectivity**

The final tests check that the container is not only internally healthy but also fully accessible and operational from the host machine.

* **What it covers**: The test suite uses curl to make API calls from the host to the container's exposed endpoint. It verifies both an unauthenticated endpoint (/v1/sys/health) and an authenticated one (/v1/sys/mounts) using the root token fetched in the previous step.
* **Why it's important**: This validates that the container is properly networking and that its API is correctly serving both public and authenticated requests. It's a final sanity check that everything is working as expected from an external perspective.

By using this framework, you can be confident that your tests are running in a consistent and secure manner every time.

---

## ⚙️ Automated Continuous Integration (CI)

### GitHub Actions Pipeline
The GitHub Actions workflow (`.github/workflows/build-config.yml`) automatically executes on pull requests and pushes to `main`. It builds a test matrix across multiple OpenBao versions (`2.7`, `2.6`, `2.5`).

Matrix verification includes:
* Automated multi-arch build capability checks using `QEMU` and `Buildx`.
* Tag generation and image layer caching.

### Jenkins Build Automation
Internal verification runs via `Jenkinsfile` utilizing the shared library (`pipelineAutomationLib`) against `.jenkins/docker-build-config.yml` configuration targets.
