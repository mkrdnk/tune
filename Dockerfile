ARG CRYSTAL_VERSION=1.21.1
FROM crystallang/crystal:${CRYSTAL_VERSION}-alpine AS builder

RUN apk add --no-cache build-base gc-dev libevent-dev openssl-dev pcre2-dev yaml-dev zlib-dev
WORKDIR /src
COPY shard.yml shard.lock ./
COPY src/ src/
RUN shards build --release --production --no-debug

FROM alpine:3.22
RUN apk add --no-cache ca-certificates gc libgcc libssl3 pcre2 yaml zlib \
    && addgroup -g 10001 tune \
    && adduser -D -H -u 10001 -G tune tune
COPY --from=builder /src/bin/tune /src/bin/tune-server /usr/local/bin/
COPY LICENSE /usr/share/doc/tune/LICENSE
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/tune-server"]
CMD ["--help"]
