#!/bin/sh
set -e

# Source env
# shellcheck disable=SC1091
. /usr/local/bin/env_secrets_expand.sh

## Source encrypt function from entrypoint for Python use
#. /usr/local/bin/docker-entrypoint.sh  # Sources encrypt_init_json_file

# Wait for server API readiness
sleep 2

# Activate virtualenv for hvac
# shellcheck disable=SC1091
. /opt/venv/bin/activate

ROOT_TOKEN_VAL=$(openbao_info --root-token)

# Invoke Python idempotent setup
# shellcheck disable=SC2154
python /usr/local/bin/openbao_idempotent_setup.py \
  --config /vault/config/openbao_config.yml \
  --vault-addr "${VAULT_ADDR}" \
  --root-token "${ROOT_TOKEN_VAL}" \
  --vault-json /vault/config/init.json \
  || local_py_exit=$?

if [ "${local_py_exit:-0}" -ne 0 ]; then
    echo "ERROR: Python setup fatal exit ${local_py_exit}"
    exit 1
fi

echo "Idempotent setup completed."
