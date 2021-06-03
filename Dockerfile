#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git


RUN mkdir -p "$GOPATH/src/acr-kube-image-scan"
ADD ./src "$GOPATH/src/acr-kube-image-scan"

RUN cd "$GOPATH/src/acr-kube-image-scan" && rm config.yaml

RUN cd "$GOPATH/src/acr-kube-image-scan" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a --installsuffix cgo --ldflags="-s" -o /acr-kube-image-scan

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /acr-kube-image-scan /app

ARG uid=1000
ARG gid=1000
RUN addgroup -g $gid acrscan && \
    adduser -D -u $uid -G acrscan acrscan

USER acrscan

ENTRYPOINT /app
