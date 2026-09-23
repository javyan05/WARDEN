# Intentionally vulnerable Dockerfile for demoing Warden.
FROM ubuntu:latest

# apt install without cleanup, and no pinned versions
RUN apt-get update && apt-get install -y curl python3

# Fetch a script over the network at build time
ADD https://example.com/install.sh /tmp/install.sh
RUN sh /tmp/install.sh

COPY app/ /app
WORKDIR /app

EXPOSE 8080

# No USER instruction -> container runs as root
CMD ["python3", "server.py"]
