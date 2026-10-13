#!/bin/sh
set -eu
umask 077

: "${TUNE_DOMAIN:?TUNE_DOMAIN is required}"
# Keep paths and wildcard requests within one DNS name, matching Tune's limits.
[ "${#TUNE_DOMAIN}" -le 180 ] || exit 1
printf '%s\n' "$TUNE_DOMAIN" | awk -F. '
  NF < 2 { exit 1 }
  { for (i = 1; i <= NF; i++)
      if (length($i) > 63 || $i !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) exit 1 }
' || { echo 'acme: TUNE_DOMAIN must be a lowercase DNS name' >&2; exit 1; }

state_root=${ACME_STATE_DIR:-/var/lib/acme}
certificate_root=${ACME_CERTIFICATES_DIR:-/certificates}
destination=$certificate_root/$TUNE_DOMAIN
pem=$destination/tls.pem

if [ "${1:-}" = health ]; then
    openssl x509 -in "$pem" -noout -checkend 86400 >/dev/null 2>&1
    exit $?
fi

: "${ACME_EMAIL:?ACME_EMAIL is required}"
: "${DNS_PROVIDER:?DNS_PROVIDER is required}"
: "${ACME_DIRECTORY_URL:=https://acme-v02.api.letsencrypt.org/directory}"
[ "${ACME_ACCEPT_TOS:-false}" = true ] || {
    echo 'acme: set ACME_ACCEPT_TOS=true after accepting the CA terms' >&2
    exit 1
}
case "${1:-}" in
    ''|once) ;;
    *) echo 'usage: acme-loop [once|health]' >&2; exit 1 ;;
esac

# Separate CA/account state; staging still requires a separate Compose project
# so that its untrusted certificate cannot replace the production PEM.
directory_id=$(printf '%s' "$ACME_DIRECTORY_URL" | sha256sum | cut -d ' ' -f 1)
state=$state_root/$directory_id
mkdir -p "$state" "$destination"
chmod 0700 "$state_root" "$state"
# Via runs as uid/gid 10001. It sees only this deployed copy, not ACME accounts.
chown 0:10001 "$certificate_root" "$destination"
chmod 0750 "$certificate_root" "$destination"

child=
staged=
cleanup() {
    [ -z "$staged" ] || rm -f "$staged"
}
stop() {
    trap '' INT TERM
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup EXIT
trap stop INT TERM

run_lego() {
    lego --path "$state" --server "$ACME_DIRECTORY_URL" \
        --email "$ACME_EMAIL" --accept-tos --dns "$DNS_PROVIDER" \
        --domains "$TUNE_DOMAIN" --domains "*.$TUNE_DOMAIN" "$@" &
    child=$!
    result=0
    wait "$child" || result=$?
    child=
    return "$result"
}

deploy_certificate() {
    staged=$(mktemp "$destination/.tls.pem.XXXXXX")
    cat "$state/certificates/$TUNE_DOMAIN.crt" \
        "$state/certificates/$TUNE_DOMAIN.key" > "$staged" || return 1
    openssl x509 -in "$staged" -noout -checkend 0 >/dev/null || return 1
    openssl x509 -in "$staged" -noout -checkhost "$TUNE_DOMAIN" >/dev/null || return 1
    openssl x509 -in "$staged" -noout -checkhost "*.$TUNE_DOMAIN" >/dev/null || return 1
    openssl crl2pkcs7 -nocrl -certfile "$staged" -out /dev/null || return 1
    openssl pkey -in "$staged" -passin pass: -check -noout >/dev/null || return 1
    cert_key=$(openssl x509 -in "$staged" -pubkey -noout) || return 1
    private_key=$(openssl pkey -in "$staged" -passin pass: -pubout) || return 1
    [ "$cert_key" = "$private_key" ] || return 1
    chown 0:10001 "$staged" || return 1
    chmod 0640 "$staged" || return 1
    if cmp -s "$staged" "$pem"; then
        rm -f "$staged"
    else
        mv -f "$staged" "$pem" || return 1
        echo "acme: deployed certificate for $TUNE_DOMAIN"
    fi
    staged=
}

cycle() {
    if [ -s "$state/certificates/$TUNE_DOMAIN.crt" ]; then
        # Restore the last usable certificate before contacting the CA. This
        # permits startup during a CA outage and retries a previously failed copy.
        deploy_certificate || { cleanup; staged=; }
        run_lego renew --dynamic || return 1
    else
        run_lego run || return 1
    fi
    deploy_certificate
}

while :; do
    result=0
    cycle || result=$?
    cleanup
    staged=
    [ "${1:-}" != once ] || exit "$result"
    if [ "$result" -eq 0 ]; then
        delay=43200
    else
        echo 'acme: issuance/renewal/deployment failed; retrying in one hour' >&2
        delay=3600
    fi
    sleep "$delay" &
    child=$!
    wait "$child" || true
    child=
done
