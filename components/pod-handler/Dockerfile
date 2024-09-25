# Use the official Golang image as the base image
FROM golang:1.22 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the application source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o pod-handler .

# Start a new image for the final container
FROM alpine:latest

# Set the working directory in the final image
WORKDIR /app

# Copy the compiled Go application from the builder stage
COPY --from=builder /app/pod-handler .

# Expose the port that the application will run on
EXPOSE 8081

# Run the Go application
CMD ["./pod-handler"]
