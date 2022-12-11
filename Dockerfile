FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM golang:1.19-alpine AS builder
# copy xx scripts to your build stage
COPY --from=xx / /

RUN apk add clang lld
# copy source
ARG TARGETPLATFORM
RUN xx-apk add gcc musl-dev libpcap-dev

ADD . /src
WORKDIR /src

ENV CGO_ENABLED=1
RUN xx-go build -v && xx-verify utlster

FROM alpine:latest

WORKDIR /bin/

RUN apk add libpcap-dev
COPY --from=builder /src/utlster .
COPY ./example /example
ENTRYPOINT ["/bin/utlster"]