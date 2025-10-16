ARG OPENBAO_VERSION="2.3.2"
ARG OPENBAO_BUILD_IMAGE="openbao:${OPENBAO_VERSION}"

# ref: https://github.com/openbao/openbao/blob/main/scripts/docker/Dockerfile
# Use a OpenBAO base image that matches the desired OpenBAO version
# Extend the official OpenBao image
FROM ghcr.io/openbao/openbao:${OPENBAO_VERSION}

ARG BUILD_DATE
ARG BUILD_ID=devel

LABEL build=$BUILD_ID

# Install dependencies
RUN apk add --no-cache curl
RUN apk add --no-cache ansible
RUN apk add --no-cache jq
RUN apk add --no-cache python3 py3-pip py3-yaml
RUN apk add --no-cache bash  # Added: For re-encryption subprocess
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
#ENV PATH="/usr/local/bin:$PATH"
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV BUILD_DATE="${BUILD_DATE}"
ENV BUILD_ID="${BUILD_ID}"

USER openbao
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
LABEL com.docker.compose.image.builder=classic
