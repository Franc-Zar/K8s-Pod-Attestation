# Stage 1: Build the Go application
FROM golang:1.22 AS builder

# Create and set the working directory
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o whitelist_service .

# Stage 2: Run the Go application
FROM alpine:latest

# Install MongoDB client and bash
RUN apk add --no-cache mongodb-tools bash

# Set the working directory
WORKDIR /app/

# Copy the built binary from the builder container
COPY --from=builder /app/whitelist_service .

# Set the environment variable for MongoDB URI
ENV MONGODB_URI="mongodb://mongo:27017"

# Expose the application's port
EXPOSE 8080

# Run the application
CMD ["./whitelist_service"]
