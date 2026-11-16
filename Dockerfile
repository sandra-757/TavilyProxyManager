# Stage 1: Build the frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# Stage 2: Build the backend
FROM golang:1.23-alpine AS backend-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Remove existing public files and copy built frontend
RUN rm -rf server/public/*
COPY --from=frontend-builder /web/dist/ server/public/
RUN go build -o tavily-proxy server/main.go

# Stage 3: Final image
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=backend-builder /app/tavily-proxy .

# Run as an unprivileged user; /app/data holds the SQLite DB, the
# encryption key file and the one-time initial key files.
RUN addgroup -S app && adduser -S app -G app && mkdir -p /app/data && chown -R app:app /app
USER app

VOLUME /app/data
ENV DATABASE_PATH=/app/data/proxy.db

EXPOSE 8080

CMD ["./tavily-proxy"]
