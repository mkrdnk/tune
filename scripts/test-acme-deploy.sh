#!/bin/sh
# Run inside the ACME image; requires root for the deployed PEM ownership check.
# docker run --rm --network none --entrypoint sh -i tune-acme:test < scripts/test-acme-deploy.sh
set -eu

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export ACME_STATE_DIR=$work/state ACME_CERTIFICATES_DIR=$work/deployed
export TUNE_DOMAIN=tune.test ACME_EMAIL=test@example.com DNS_PROVIDER=mock
export ACME_DIRECTORY_URL=https://ca.invalid/directory ACME_ACCEPT_TOS=true
export MOCK_FIXTURES=$work/fixtures MOCK_LOG=$work/calls MOCK_MODE=issue
mkdir -p "$work/bin" "$MOCK_FIXTURES"
export PATH=$work/bin:$PATH

# Replace only the external CA/DNS operation. Exercise the real deployment,
# certificate parsing, permissions, persistence, and failure handling.
cat > "$work/bin/lego" <<'MOCK'
#!/bin/sh
set -eu
state=
operation=
domains=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --path) state=$2; shift ;;
        --domains) domains="$domains $2"; shift ;;
        run|renew) operation=$1 ;;
    esac
    shift
done
[ "$domains" = ' tune.test *.tune.test' ]
echo "$operation" >> "$MOCK_LOG"
case "$MOCK_MODE" in
    fail) exit 1 ;;
    noop) exit 0 ;;
esac
mkdir -p "$state/certificates"
cp "$MOCK_FIXTURES/cert.pem" "$state/certificates/tune.test.crt"
cp "$MOCK_FIXTURES/key.pem" "$state/certificates/tune.test.key"
MOCK
chmod +x "$work/bin/lego"

certificate() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -days 7 -subj /CN=tune.test -addext 'subjectAltName=DNS:tune.test,DNS:*.tune.test' \
        -keyout "$MOCK_FIXTURES/key.pem" -out "$MOCK_FIXTURES/cert.pem" 2>/dev/null
}
expect_failure() {
    if "$@" >"$work/expected-error.log" 2>&1; then
        echo "unexpected success: $*" >&2
        exit 1
    fi
}

pem=$ACME_CERTIFICATES_DIR/tune.test/tls.pem
expect_failure env ACME_ACCEPT_TOS=false acme-loop once
[ ! -f "$MOCK_LOG" ]
expect_failure env TUNE_DOMAIN=../../escape acme-loop once
expect_failure env MOCK_MODE=fail acme-loop once
[ ! -e "$pem" ]
expect_failure acme-loop health

certificate
acme-loop once
acme-loop health
[ "$(tail -n 1 "$MOCK_LOG")" = run ]
[ "$(stat -c '%a:%u:%g' "$pem")" = 640:0:10001 ]
[ "$(stat -c '%a' "$ACME_STATE_DIR")" = 700 ]
cp "$pem" "$work/original.pem"
inode=$(stat -c '%i' "$pem")

MOCK_MODE=noop acme-loop once
[ "$(tail -n 1 "$MOCK_LOG")" = renew ]
[ "$(stat -c '%i' "$pem")" = "$inode" ]
cmp "$pem" "$work/original.pem"

# A real replacement must change the deployed PEM, retaining ownership/mode.
certificate
acme-loop once
if cmp -s "$pem" "$work/original.pem"; then exit 1; fi
[ "$(stat -c '%a:%u:%g' "$pem")" = 640:0:10001 ]
cp "$pem" "$work/renewed.pem"

expect_failure env MOCK_MODE=fail acme-loop once
cmp "$pem" "$work/renewed.pem"

# A valid key belonging to another certificate must never reach Via.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$MOCK_FIXTURES/key.pem" 2>/dev/null
expect_failure acme-loop once
cmp "$pem" "$work/renewed.pem"
[ -z "$(find "$ACME_CERTIFICATES_DIR" -name '.tls.pem.*' -print)" ]

# Recover from bad saved state, then restore a lost deployment while CA is down.
certificate
acme-loop once
cp "$pem" "$work/renewed.pem"
rm "$pem"
expect_failure env MOCK_MODE=fail acme-loop once
cmp "$pem" "$work/renewed.pem"
acme-loop health
echo 'ACME deployment tests passed: bootstrap, renew, restart, failure, key mismatch, permissions'
