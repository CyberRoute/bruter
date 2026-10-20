# Stage 1: build the React UI that gets embedded into the Go binary.
FROM node:20-alpine AS ui-stage

WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build the Go binary with the UI embedded (web/dist).
FROM golang:alpine AS build-stage

WORKDIR /go/src/github.com/CyberRoute/bruter

COPY . .
# Bring in the freshly built UI so go:embed in web/embed.go finds web/dist.
COPY --from=ui-stage /app/web/dist ./web/dist

RUN CGO_ENABLED=0 GOOS=linux go build -a -o /bruter ./cmd/bruter/*.go

FROM scratch

COPY --from=build-stage /bruter /bruter

ADD db/apache-list db/apache-list

EXPOSE 8080

ENTRYPOINT ["/bruter"]
