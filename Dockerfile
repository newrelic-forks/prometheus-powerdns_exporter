FROM golang:alpine

RUN apk add --update ca-certificates

ADD . /go/src/powerdns_exporter
WORKDIR /go/src/powerdns_exporter

RUN set -ex \
 && apk add --update git \
 && go install -v -ldflags "-X main.programVersion=$(git describe --tags || git rev-parse --short HEAD || echo dev)" ./... \
 && apk del --purge git

ENTRYPOINT ["powerdns_exporter"]

EXPOSE 9120