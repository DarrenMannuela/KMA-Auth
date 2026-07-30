# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# gcc + musl-dev needed for the sqlite CGO driver
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o kma-auth-server .

# ── Stage 2: Run ─────────────────────────────────────────────────────────────
FROM alpine:latest AS runner

RUN apk add --no-cache sqlite-libs

WORKDIR /app

COPY --from=builder /app/kma-auth-server .

EXPOSE 8001

CMD ["./kma-auth-server"]
