# Intentionally insecure Dockerfile for scanner fixtures
FROM ubuntu:latest

# Hadolint: using latest tag and sudo/root context without pinning packages
RUN apt-get update && apt-get install -y curl \
    && echo "export PATH=/opt/bin:$PATH" >> /etc/profile

# Missing cleanup and version pinning to trigger hadolint warnings
CMD ["/bin/bash"]
