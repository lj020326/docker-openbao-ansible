# Use build args to allow custom tags or digests
ARG OPENBAO_VERSION="latest"

# ref: https://github.com/openbao/openbao/blob/main/scripts/docker/Dockerfile
# Use a OpenBAO base image that matches the desired OpenBAO version
# Extend the official OpenBao image
FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}

# Switch to root user to perform package installation and configuration
USER root

ARG BUILD_DATE
ARG BUILD_ID=devel

LABEL build="${BUILD_ID}"

# Install dependencies
# hadolint ignore=DL3018
RUN apk add --no-cache \
    curl \
    ansible \
    jq \
    python3 \
    py3-pip \
    py3-yaml \
    bash \
    openssl

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir hvac pyyaml

# Copy scripts
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY env_secrets_expand.sh /usr/local/bin/env_secrets_expand.sh
COPY openbao_info.sh /usr/local/bin/openbao_info
COPY openbao_setup.sh /usr/local/bin/openbao_setup.sh
COPY openbao_idempotent_setup.py /usr/local/bin/openbao_idempotent_setup.py

# Set permissions
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/env_secrets_expand.sh \
    /usr/local/bin/openbao_info \
    /usr/local/bin/openbao_setup.sh \
    /usr/local/bin/openbao_idempotent_setup.py

# Ensure /usr/local/bin is in PATH for openbao user
ENV PATH="/opt/venv/bin:/usr/local/bin:$PATH"
ENV BUILD_DATE="${BUILD_DATE}"
ENV BUILD_ID="${BUILD_ID}"

# Return to non-root openbao user for runtime execution
# prefer to use the logical owner name instead of numeric
USER openbao

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
LABEL com.docker.compose.image.builder="classic"
