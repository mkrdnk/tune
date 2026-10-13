FROM goacme/lego:v4.26.0 AS lego
FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl tzdata
COPY --from=lego /lego /usr/bin/lego
COPY acme-loop.sh /usr/local/bin/acme-loop
RUN chmod 0755 /usr/local/bin/acme-loop
ENTRYPOINT ["/usr/local/bin/acme-loop"]
