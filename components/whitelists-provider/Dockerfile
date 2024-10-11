# Use the official Go image to build the application
FROM golang:1.22 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the workspace
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the rest of the application's source code
COPY . .

# Build the Go application
RUN go build -o whitelists-provider .

# Use a minimal Docker image for running the application
FROM alpine:latest

# Install required packages (MongoDB dependencies)
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder image
COPY --from=build /app/main /whitelists-provider

# Expose the port the app will run on
# Command to run the executable
CMD ["./whitelists-provider"]
