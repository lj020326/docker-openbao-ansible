# ARG instructions used in FROM must come before the FROM instruction
ARG OPENBAO_VERSION="2.3.2"

## ref: https://github.com/openbao/openbao/blob/main/scripts/docker/Dockerfile

# Use a OpenBAO base image that matches the desired OpenBAO version
# Extend the official OpenBao image
#FROM ghcr.io/openbao/openbao:latest
#FROM ghcr.io/openbao/openbao:2.2
#FROM ghcr.io/openbao/openbao:2.3.2
FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}

ARG BUILD_DATE
ARG BUILD_ID=devel
LABEL build=$BUILD_ID

# Install curl
RUN apk add --no-cache curl

# install ansible
RUN apk add --no-cache ansible

# Install jq for JSON parsing in entrypoint script
RUN apk add --no-cache jq

# Copy the custom entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
COPY openbao_info.sh /usr/local/bin/openbao_info
COPY openbao_setup.sh /usr/local/bin/openbao_setup.sh

# Set permissions
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh \
  /usr/local/bin/env_secrets_expand.sh \
  /usr/local/bin/openbao_info \
  /usr/local/bin/openbao_setup.sh

COPY configs/policy_admin.hcl /
COPY configs/policy_user.hcl /

USER openbao

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
