ARG ARCH="amd64"
ARG OS="linux"

# compiler image
FROM golang:1.20-alpine as builder
ENV GOPROXY=https://goproxy.cn \
    GOPATH="/go/release:/go/release/src/gopathlib/"

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk add build-base
RUN apk add libpcap libpcap-dev

ADD . /go/release/src
WORKDIR /go/release/src
RUN GOOS=linux CGO_ENABLED=1 GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/ipscanner

# runner image
FROM alpine

COPY --from=builder /go/release/src/bin/ipscanner /ipscanner
COPY manuf.txt /manuf.txt
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update
RUN apk add libpcap libpcap-dev

EXPOSE      9921
ENTRYPOINT  [ "/ipscanner" ]