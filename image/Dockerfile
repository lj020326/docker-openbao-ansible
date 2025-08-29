# ARG instructions used in FROM must come before the FROM instruction
ARG OPENBAO_VERSION="2.3.2"

# Use a OpenBAO base image that matches the desired OpenBAO version
# Extend the official OpenBao image
#FROM ghcr.io/openbao/openbao:latest
#FROM ghcr.io/openbao/openbao:2.2
#FROM ghcr.io/openbao/openbao:2.3.2
FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}

# Install curl
RUN apk add --no-cache curl

# install ansible
RUN apk add --no-cache ansible

# Install jq for JSON parsing in entrypoint script
RUN apk add --no-cache jq

# Copy the custom entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
COPY fetch_openbao_info.sh /usr/local/bin/fetch_openbao_info.sh

# Set permissions
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh \
  /usr/local/bin/env_secrets_expand.sh \
  /usr/local/bin/fetch_openbao_info.sh

## Expose the config directory as a volume to allow mounting init.txt and config
#VOLUME /openbao/config

USER openbao

## Use file-based configuration to align with volume mounts
#CMD ["server", "-config=/openbao/config/local.json"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
#ENTRYPOINT ["/usr/local/bin/docker-entrypoint-wrapper.sh"]
# No CMD, let docker-entrypoint.sh handle it
# CMD ["bao", "server", "-config=/vault/config/local.json"]
