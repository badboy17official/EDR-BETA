FROM ubuntu:22.04

# Avoid tzdata interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary monitoring tools
RUN apt-get update && apt-get install -y \
    strace \
    iproute2 \
    tcpdump \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged user to run the malware (if needed for testing privileges, though some malware might require root to fully explode)
# By default, we will run the tracer as root to trace, but the workload can be dropped.
RUN useradd -m -s /bin/bash sandbox_user

# Setup working directory for the sandbox
WORKDIR /sandbox

# Copy the tracer script
COPY tracer.sh /sbin/tracer.sh
RUN chmod +x /sbin/tracer.sh

# The entrypoint will be our tracer script
ENTRYPOINT ["/sbin/tracer.sh"]
