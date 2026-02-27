# Sample Dockerfile with INTENTIONAL security issues for testing
# These issues will be detected by:
# - Hadolint (Dockerfile linter)
# - Trivy (misconfiguration scanning)
#
# DO NOT use this Dockerfile in production - it exists only for testing

# DL3006: Always tag the version of an image explicitly
FROM ubuntu

# DL3008: Pin versions in apt get install
RUN apt-get update && apt-get install -y curl wget python3

# DL3009: Delete the apt-get lists after installing
RUN apt-get update && apt-get install -y nginx

# DL3020: Use COPY instead of ADD for files
ADD ./app /app

# DL3007: Using latest is prone to errors
FROM python:latest as builder

# DL3013: Pin pip packages to specific versions
RUN pip install flask requests django

# DL3002: Last USER should not be root (missing USER instruction)
# DL3025: Use arguments JSON notation for CMD
CMD python /app/server.py

# DL4006: Set SHELL option -o pipefail
RUN curl -s https://example.com/script.sh | bash

# DL3003: Use WORKDIR to switch directories
RUN cd /app && npm install

# DL3045: COPY should use --chown flag
COPY package.json /app/

# Missing HEALTHCHECK (Trivy DS002)
# Running as root (Trivy DS001, Hadolint DL3002)
