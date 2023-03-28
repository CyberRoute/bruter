FROM golang:alpine as build-stage

WORKDIR /go/src/github.com/CyberRoute/bruter

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -o /bruter ./cmd/bruter/*.go

FROM scratch

COPY --from=build-stage /bruter /bruter

ADD pkg/fuzzer/apache-list pkg/fuzzer/apache-list
ADD templates/ templates/
ADD static/ static/

EXPOSE 8080

ENTRYPOINT ["/bruter"]
