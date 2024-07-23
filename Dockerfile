# Start from the latest golang base image
FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Install jq for JSON manipulation and openssl for PSK generation
RUN apt-get update && apt-get install -y jq openssl

# Build the Go app
RUN go build -o main .

# Create a script to update the config file with environment variables and generate defaults
RUN echo '#!/bin/sh\n\
# Generate PROXY_LISTEN if not provided\n\
if [ -z "$PROXY_LISTEN" ]; then\n\
    PROXY_LISTEN=":$(shuf -i 10000-65535 -n 1)"\n\
    echo "Generated PROXY_LISTEN: $PROXY_LISTEN"\n\
fi\n\
# Generate PROXY_PSK if not provided\n\
if [ -z "$PROXY_PSK" ]; then\n\
    PROXY_PSK=$(openssl rand -base64 32)\n\
    echo "Generated PROXY_PSK: $PROXY_PSK"\n\
fi\n\
# Generate MTU if not provided\n\
if [ -z "$MTU" ]; then\n\
    MTU=$(shuf -i 1280-1500 -n 1)\n\
    echo "Generated MTU: $MTU"\n\
fi\n\
# Generate WG_ENDPOINT if not provided\n\
if [ -z "$WG_ENDPOINT" ]; then\n\
    WG_PORT=$(shuf -i 10000-65535 -n 1)\n\
    WG_ENDPOINT="[::1]:$WG_PORT"\n\
    echo "Generated WG_ENDPOINT: $WG_ENDPOINT"\n\
fi\n\
# Update config file\n\
jq ".servers[0].proxyListen = \"$PROXY_LISTEN\" | \
    .servers[0].proxyPSK = \"$PROXY_PSK\" | \
    .servers[0].mtu = $MTU | \
    .servers[0].wgEndpoint = \"$WG_ENDPOINT\"" config.json > config_updated.json && \
mv config_updated.json config.json\n\
# Expose the port from PROXY_LISTEN\n\
EXPOSE_PORT=$(echo $PROXY_LISTEN | cut -d: -f2)\n\
echo "Exposing port: $EXPOSE_PORT"\n\
# Run the main application\n\
exec ./main' > /entrypoint.sh && chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

CMD ["./main "]