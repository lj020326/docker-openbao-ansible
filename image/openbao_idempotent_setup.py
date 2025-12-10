#!/usr/bin/env python3

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import yaml
from datetime import datetime
from hvac import Client
#from hvac.exceptions import InvalidPath, InvalidRequest
#import hvac.exceptions

# Existing hvac exceptions (expand as needed)
from hvac.exceptions import (
    Forbidden,
    InvalidRequest,
    InvalidPath,
    # Add others if needed: InternalServerError, etc.
)

# __scriptName__ = sys.argv[0]
__scriptName__ = os.path.basename(sys.argv[0])

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(name)s: %(message)s', stream=sys.stdout)
logger = logging.getLogger(__scriptName__)


# DRY helper: Run bao CLI command and return output as dict (fallback for some ops)
def run_bao_cmd(cmd_parts, vault_addr, token):
    env = os.environ.copy()
    env['VAULT_ADDR'] = vault_addr
    result = subprocess.run(['bao'] + cmd_parts, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        logger.error(f"Bao command failed: {result.stderr}")
        return None  # Indicates not found/failure
    if result.stdout.strip():
        return json.loads(result.stdout)
    return {}


# === NEW IDEMPOTENCY CHECK HELPERS ===
def is_auth_method_enabled(client, auth_method_path):
    """Checks if a given auth method is already enabled using the client API."""
    try:
        # Note: list_auth_methods returns a dictionary where keys are the paths with a trailing slash.
        methods = client.sys.list_auth_methods()
        return f'{auth_method_path}/' in methods['data']
    except Exception as e:
        logger.warning(f"Failed to check auth method status for '{auth_method_path}'. Error: {e}")
        # Assume not enabled if we can't confirm due to error, to allow setup attempt
        return False

def is_secrets_engine_enabled(client, mount_point):
    """Checks if a given secrets engine mount point is already enabled using the client API."""
    try:
        # Note: list_mounted_secrets_engines returns a dictionary where keys are the paths with a trailing slash.
        mounts = client.sys.list_mounted_secrets_engines()
        return f'{mount_point}/' in mounts['data']
    except Exception as e:
        logger.warning(f"Failed to check secrets engine status for '{mount_point}'. Error: {e}")
        # Assume not enabled if we can't confirm due to error, to allow setup attempt
        return False
# === END IDEMPOTENCY CHECK HELPERS ===


# Load existing vault data from decrypted .enc (via openbao_info)
def load_existing_vault_data(vault_json_path):
    enc_path = vault_json_path + '.enc'
    if not os.path.exists(enc_path):
        logger.warning(f"Encrypted file {enc_path} not found; starting with empty users/tokens.")
        return {'users': {}, 'tokens': {}}  # Default empty if no .enc
    # Use openbao_info to decrypt and load full JSON (unseal/root + users/tokens)
    result = subprocess.run(['openbao_info', '--content'], capture_output=True, text=True, check=True)
    if result.stdout.strip():
        data = json.loads(result.stdout)
        logger.info("Loaded existing vault data from encrypted file.")
        return data
    logger.error("Failed to parse decrypted content from openbao_info.")
    return {'users': {}, 'tokens': {}}


# Source encrypt function from entrypoint (assume sourced)
def encrypt_json_file(unencrypted_file, encrypted_file):
    # --- 1. Early Environment Variable Check (Crucial Improvement) ---
    vault_password = os.getenv('ANSIBLE_VAULT_PASSWORD')
    if not vault_password:
        # Fail fast and explicitly state the requirement
        raise ValueError("ANSIBLE_VAULT_PASSWORD environment variable must be set to encrypt the file.")

    logger.info("Starting encryption process.")
    logger.info(f"Vault password length: {len(vault_password)} (not printing content for security)")

    encrypt_command = [
                'ansible-vault', 'encrypt', unencrypted_file,
                '--vault-password-file', '/bin/cat',
                '--output', encrypted_file
            ]
    logger.info(f"Executing {encrypt_command}")

    try:
        result = subprocess.run(encrypt_command,
            input=vault_password,  # Password fed via stdin to /bin/cat
            capture_output=True,
            text=True,
            timeout=30)
        logger.info(f"Subprocess completed. Return code: {result.returncode}")
        if result.stderr:
            logger.warning(f"STDERR (non-fatal): {result.stderr}")
        if result.returncode == 0:
            logger.info(f"Encrypted file exists after run: {os.path.exists(encrypted_file)}")
            # Securely remove unencrypted file after successful encryption
            os.remove(unencrypted_file)
            logger.info(f"Unencrypted file {unencrypted_file} securely removed.")
            logger.info(f"Successfully re-encrypted {unencrypted_file} to {encrypted_file}.")
        else:
            raise subprocess.CalledProcessError(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        logger.error("Encryption timed out after 30 seconds.")
        raise
    except subprocess.CalledProcessError as e:
        # Robustly display shell command failure details
        logger.error(f"Encryption command failed with exit status: {e.returncode}")
        logger.error("-" * 20 + " STDOUT " + "-" * 20)
        logger.error(e.stdout)
        logger.error("-" * 20 + " STDERR " + "-" * 20)
        logger.error(e.stderr)
        logger.error("-" * 48)
        raise
    except Exception as e:
        # Catch any other unexpected exceptions
        logger.error(f"Unexpected error during encryption: {e}")
        logger.exception("Full stack trace for unexpected encryption error:")
        raise


# Source decrypt function from entrypoint (assume sourced)
def decrypt_json_file(encrypted_file, decrypted_file):
    vault_password = os.getenv('ANSIBLE_VAULT_PASSWORD')
    if not vault_password:
        raise ValueError("ANSIBLE_VAULT_PASSWORD environment variable must be set to decrypt the file.")

    env = os.environ.copy()
    env['ANSIBLE_VAULT_PASSWORD'] = vault_password

    command = (
        f'source /usr/local/bin/docker-entrypoint.sh && '
        f'decrypt_init_json_file "{encrypted_file}" "{decrypted_file}"'
    )

    try:
        subprocess.run(
            ['sh', '-c', command],
            env=env,
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Decryption command failed with exit status {e.returncode}")
        logger.error(f"Error output:\n{e.stderr}")
        raise


# Idempotent policy creation/update
def ensure_policy(client, name, hcl_content):
    try:
        policies = client.sys.list_policies()['data']['keys']
    except Exception as e:
        logger.warning(f"Failed to list policies: {e}; assuming none.")
        policies = []

    if name not in policies:
        client.sys.create_or_update_policy(name, hcl_content)
        logger.info(f"Created policy: {name}")
    else:
        try:
            response = client.sys.read_policy(name)
            existing = response['data']['rules']
            if existing != hcl_content:
                client.sys.create_or_update_policy(name, hcl_content)
                logger.info(f"Updated policy: {name}")
            else:
                logger.info(f"Policy {name} unchanged")
        except (InvalidPath, KeyError) as e:
            logger.warning(f"Error reading policy {name}: {e}; recreating.")
            # Handle missing policy or unexpected response structure; recreate
            client.sys.create_or_update_policy(name, hcl_content)
            logger.info(f"Recreated policy: {name}")


# Idempotent user creation/update (userpass auth)
def ensure_user(client, vault_data, username, password, policies):
    vault_data['users'] = vault_data.get('users', {})

    if username in vault_data['users']:
        # Verify user exists via API with stored password
        try:
            # Use hvac to login and check
            user_client = Client(url=client.url)
            user_client.auth.userpass.login(username=username, password=vault_data['users'][username])
            logger.info(f"User {username} verified")
            return vault_data  # Return unchanged
        except InvalidRequest:
            logger.warning(f"User {username} password invalid; recreating...")
            # Delete and recreate
            client.auth.userpass.delete_user(username)
        except Exception as e:
            logger.warning(f"Unexpected error verifying user {username}: {e}; recreating.")
            pass  # Fall through to recreate

    # Create if not exists or invalid
    try:
        client.auth.userpass.read_user(username)
        logger.info(f"User {username} exists; updating password/policies if needed")
        # Update (hvac doesn't have direct update; delete/recreate for simplicity)
        client.auth.userpass.delete_user(username)
        raise InvalidPath  # Force recreate
    except InvalidPath:
        client.auth.userpass.create_or_update_user(username=username, policies=policies, password=password)
        logger.info(f"Created user: {username}")

    # Merge into vault_data and return
    vault_data['users'][username] = password
    logger.info(f"Updated vault_data with user {username}")
    return vault_data


# Idempotent token role creation
def ensure_token_role(client, role_name, token_policies, token_ttl='768h'):
    try:
        client.create_token_role(
            role_name=role_name,
            allowed_policies=token_policies,
            token_ttl=token_ttl
        )
        logger.info(f"Token role '{role_name}' created/updated.")
    except Exception as e:
        logger.error(f"Failed to create/update token role '{role_name}': {e}")
        sys.exit(1)


# Idempotent token creation
def ensure_token(client, vault_data, token_name, policies, ttl='24h'):
    """
        Ensure a token exists and is valid. Recreate if lookup fails (e.g., expired).
    """
    vault_data['tokens'] = vault_data.get('tokens', {})

    if token_name in vault_data['tokens']:
        if 'token' in vault_data['tokens'][token_name]:
            token = vault_data['tokens'][token_name]['token']
        else:
            logger.warning(f"using older formatting; upgrading to latest configuration format")
            token = vault_data['tokens'][token_name]
        try:
            # Verify via hvac lookup_token
            client.auth.token.lookup(token)
            logger.info(f"Token verified")
            return vault_data  # Return unchanged
        except (Forbidden, InvalidRequest) as e:
            logger.warning(f"Token invalid; recreating...")
            if "bad token" in str(e):
                logger.warning(f"Token '{token_name}' invalid (bad/expired). Recreating...")
            else:
                raise  # Re-raise non-bad-token errors

    logger.info(f"Create new token")
    create_params = {
        'policies': policies,
        'ttl': ttl,
        'display_name': f"{token_name}"
    }
    create_token_result = client.auth.token.create(**create_params)
    new_token = create_token_result['auth']['client_token']
    
    # # Merge into vault_data and return
    # vault_data['tokens'][token_name] = new_token
    logger.info(f"Update vault_data")
    vault_data['tokens'][token_name] = {
        'token': new_token,
        'created_at': datetime.utcnow().isoformat()
    }
    logger.info(f"Created token: {new_token}")
    return vault_data


def main():
    parser = argparse.ArgumentParser(description="Idempotent OpenBao setup from YAML")
    parser.add_argument('--config', required=True, help="Path to openbao_config.yml")
    parser.add_argument('--vault-addr', default='http://127.0.0.1:8200', help="Vault address")
    parser.add_argument('--root-token', required=True, help="Root token")
    parser.add_argument('--vault-json', default='/vault/config/init.json', help="Vaulted JSON path")
    args = parser.parse_args()

    logger.info("Starting idempotent OpenBao setup from YAML config.")

    logger.info("Load configuration data")
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
        logger.info(f"Loaded config from {args.config}")
    if not config:
        logger.error(f"No configuration data found at {args.config}, exiting")
        sys.exit(1)

    logger.info("Load existing vault data")
    vault_data = load_existing_vault_data(args.vault_json)
    logger.info("Loaded existing vault data (unseal/root/users/tokens).")

    logger.info("Initialize OpenBao Client")
    client = None
    try:
        client = Client(url=args.vault_addr, token=args.root_token)
        client.sys.read_health_status()
        logger.info(f"OpenBao connection established at {args.vault_addr}.")
    except Exception as e:
        logger.error(f"Failed to establish connection to OpenBao at {args.vault_addr}: {e}")
        sys.exit(1)

    # 4. Idempotently Enable userpass Auth Method
    logger.info("Ensuring auth methods...")
    USERPASS_MOUNT = 'userpass'
    if not is_auth_method_enabled(client, USERPASS_MOUNT):
        logger.info(f"Enabling '{USERPASS_MOUNT}' auth method...")
        try:
            # client.sys.enable_auth_method(mount_point='userpass', method_type='userpass')
            client.sys.enable_auth_method('userpass', path=USERPASS_MOUNT)
            # Using CLI for robustness in this setup environment:
            # run_bao_cmd(['auth', 'enable', USERPASS_MOUNT], args.vault_addr, args.root_token)
            logger.info(f"'{USERPASS_MOUNT}' auth method enabled.")
        except Exception as e:
            logger.error(f"Failed to enable '{USERPASS_MOUNT}' auth method: {e}")
            # Do not exit here; proceed with other setup steps if this is recoverable
    else:
        logger.info(f"'{USERPASS_MOUNT}' auth method already enabled. Skipping.")

    # 5. Apply Policies (from config YAML)
    if 'policies' in config:
        logger.info("Ensuring policies...")
        for policy_name, policy_rules in config.get('policies', {}).items():
            ensure_policy(client, policy_name, policy_rules['hcl_content'])

    # 6. Apply Token Roles (from config YAML)
    if 'token_roles' in config:
        logger.info("Ensuring token roles...")
        for token_cfg in config['token_roles']:
            ensure_token_role(client, token_cfg['display_name'], token_cfg['policies'], token_cfg['ttl'])

    # 7. Apply Tokens (from config YAML)
    if 'tokens' in config:
        logger.info("Ensuring tokens...")
        for token_cfg in config['tokens']:
            vault_data = ensure_token(client, vault_data, token_cfg['display_name'], token_cfg['policies'], token_cfg['ttl'])

    # 8. Create/Update Userpass Users
    if 'users' in config:
        logger.info("Ensuring users...")
        for user_cfg in config['users']:
            vault_data = ensure_user(client, vault_data, user_cfg['display_name'], user_cfg['password'], user_cfg['policies'])

    # 9. Final single write of merged vault_data
    with open(args.vault_json, 'w') as f:
        json.dump(vault_data, f, indent=2)
    logger.info(f"Final vault data written to {args.vault_json}")

    # 10. Re-encrypt JSON after updates (sync with .enc for tests)
    unencrypted = args.vault_json
    encrypted = unencrypted + '.enc'
    try:
        encrypt_json_file(unencrypted, encrypted)  # Use the dedicated function
    except Exception as e:
        logger.warning(f"Re-encryption failed: {e}; using unencrypted for dev. Ensure ANSIBLE_VAULT_PASSWORD set.")

    # 11. Idempotently Enable KV Secrets Engine (if configured)
    logger.info("Ensuring secret engines...")
    KV_MOUNT = 'secret'
    mounts = client.sys.list_mounted_secrets_engines()['data']
    if 'secret/' not in mounts or mounts['secret/']['type'] != 'kv' or mounts['secret/']['options'].get('version') != '2':
        client.sys.enable_secrets_engine(backend_type='kv', path='secret', options={'version': '2'})
        logger.info("Enabled KV v2 at secret/")
    else:
        logger.info("KV v2 at secret/ already configured")

    # 12. Ensure test secret for regression tests (using root for reliability)
    logger.info("Ensuring test secret for regression...")
    try:
        client.secrets.kv.v2.create_or_update_secret(path='test', secret={'value': 'test_data'}, mount_point='secret')
        read_back = client.secrets.kv.v2.read_secret_version(path='test', mount_point='secret', raise_on_deleted_version=False)
        if read_back['data']['data']['value'] != 'test_data':
            raise ValueError("Test secret mismatch")
        logger.info("Test secret written/read successfully for regression.")
    except (InvalidPath, ValueError) as e:
        client.secrets.kv.v2.create_or_update_secret(path='test', secret={'value': 'test_data'}, mount_point='secret')
        logger.warning(f"Test secret recreated due to {e}")

    logger.info("OpenBao idempotent setup complete.")


if __name__ == '__main__':
    try:
        main()
    except (argparse.ArgumentError, ValueError, InvalidRequest, subprocess.CalledProcessError, Forbidden) as e:
        logger.critical(f"A critical error occurred: {e}")
        logger.exception("Full traceback:")
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    # except Exception as e:
    #     logger.critical(f"A critical error occurred: {e}")
    #     # Print stack trace only for unexpected errors
    #     if not isinstance(e, (argparse.ArgumentError, ValueError, InvalidPath, InvalidRequest, subprocess.CalledProcessError)):
    #          traceback.print_exc(file=sys.stderr)
    #     sys.exit(1)
