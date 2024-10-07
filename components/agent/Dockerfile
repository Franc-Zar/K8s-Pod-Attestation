# Use a Golang base image for building the binary
FROM golang:1.22 as builder

# Install OpenSSL library before building
RUN apt-get update && apt-get install -y libssl-dev

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go binary with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -o agent .

# Use Debian Bookworm as the base image for the final container
FROM debian:bookworm-slim

# Install OpenSSL 3 libraries and ca-certificates
RUN apt-get update && apt-get install -y libssl3 libssl-dev ca-certificates

# Set the working directory inside the container
WORKDIR /app

# Copy the binary built in the previous stage
COPY --from=builder /app/agent .

# Ensure the library path is set for OpenSSL
ENV LD_LIBRARY_PATH=/usr/lib:/usr/local/lib

# Run the controller binary
CMD ["./agent"]
