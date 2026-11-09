# ====================================================================
# Secure Task Management System
# Production Dockerfile for Red Hat OpenShift & Developer Sandbox
# Base Image: Red Hat Universal Base Image 9 (UBI 9) PHP 8.2
# ====================================================================

FROM registry.access.redhat.com/ubi9/php-82:latest

# Metadata for OpenShift Service Catalog & Inspection
LABEL maintainer="Secure Task Management System Team" \
      io.k8s.description="Secure Task Management System on Red Hat Enterprise Linux & PHP 8.2" \
      io.k8s.display-name="Secure Task Manager" \
      io.openshift.expose-services="8080:http" \
      io.openshift.tags="php,php82,ubi9,task-manager,devsecops"

# Working directory within the official Red Hat S2I / Apache document root
WORKDIR /opt/app-root/src

# Copy application source code into the container
COPY --chown=1001:0 . /opt/app-root/src/

# OpenShift Compliance (Arbitrary UID / restricted-v2 SCC):
# OpenShift runs containers under random UIDs that belong to GID 0 (root group).
# Ensure all files and directories have group read/write permissions matching user permissions.
RUN chgrp -R 0 /opt/app-root/src && \
    chmod -R g=u /opt/app-root/src

# Expose OpenShift default unprivileged HTTP port
EXPOSE 8080

# Switch to non-root user (UID 1001 in Red Hat UBI)
USER 1001

# Start Apache HTTP Server via the official Red Hat S2I runner
CMD ["/usr/libexec/s2i/run"]
