# Use the official Golang image as the base image
FROM golang:1.22 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire application source code into the container
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o registrar .

# Start a new image for the final container
FROM alpine:latest

# Install SQLite in the final image
RUN apk add --no-cache sqlite

# Set the working directory for the final image
WORKDIR /app

# Copy the compiled Go application from the builder stage
COPY --from=builder /app/registrar /app/registrar

# Copy any necessary non-Go files (if needed)
COPY registrar.db /app/registrar.db

# Expose the port that the application will run on
EXPOSE 8080

# Run the application
CMD ["./registrar"]
