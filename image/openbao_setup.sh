#!/bin/sh
set -e

# Source env
. /usr/local/bin/env_secrets_expand.sh

## Source encrypt function from entrypoint for Python use
#. /usr/local/bin/docker-entrypoint.sh  # Sources encrypt_init_json_file

# Wait for server API readiness
sleep 2

# Activate virtualenv for hvac
. /opt/venv/bin/activate

# Invoke Python idempotent setup
python /usr/local/bin/openbao_idempotent_setup.py \
  --config /vault/config/openbao_config.yml \
  --vault-addr "${VAULT_ADDR}" \
  --root-token "$(openbao_info --root-token)" \
  --vault-json /vault/config/init.json \
  || echo "Idempotent setup failed, but server up"

local_py_exit=$?
if [ $local_py_exit -ne 0 ]; then
    echo "ERROR: Python setup fatal exit $local_py_exit"
    exit 1
fi

echo "Idempotent setup completed."
