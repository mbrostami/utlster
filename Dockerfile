FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM alpine AS builder
# copy xx scripts to your build stage
COPY --from=xx / /

RUN apk add clang lld
# copy source
ARG TARGETPLATFORM
RUN xx-apk add gcc musl-dev

ADD . /src
WORKDIR /src

RUN xx-go build -v && xx-verify utlster


FROM alpine:latest

WORKDIR /bin/

COPY --from=builder /src/utlster .

ENTRYPOINT ["/bin/utlster"]