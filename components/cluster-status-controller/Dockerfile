# Use a Golang base image
FROM golang:1.23 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o cluster-status-controller .

# Use a minimal base image for the final container
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the binary built in the previous stage
COPY --from=builder /app/cluster-status-controller .

# Run the controller binary
CMD ["./cluster-status-controller"]
