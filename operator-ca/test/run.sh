#!/usr/bin/env bash
# Offline checks for the operator-ca/ tooling: shellcheck, a throwaway operator
# CA built with the real scripts, the level extension DER, the delegated OCSP
# signer, the CRL, a local openssl ocsp responder answering good and revoked,
# and the publish step in dry-run mode. No cluster or docker is needed.
# ok and not_ok always succeed, so 'A && ok || not_ok' is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
opca="$(cd "$here/.." && pwd)"
root="$(cd "$opca/.." && pwd)"

work="$(mktemp -d)"
responder_pid=""
cleanup() {
  [ -z "$responder_pid" ] || kill "$responder_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
not_ok() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; [ -z "${2:-}" ] || printf '     %s\n' "$2"; }
contains() { case "$2" in *"$3"*) ok "$1" ;; *) not_ok "$1" "missing: $3" ;; esac; }
lacks() { case "$2" in *"$3"*) not_ok "$1" "unexpected: $3" ;; *) ok "$1" ;; esac; }

# Every run is isolated from the operator's real .env, state and tools.
export LAB_ENV_FILE=/dev/null
export LAB_K8S_STATE="$work/state"
export LAB_TOOLS_DIR="$work/tools"
export LAB_OPCA_DIR="$work/ca"
export LAB_OPCA_OCSP_URL="http://ocsp.lab.example.org/"
export LOG_LEVEL=debug
unset LAB_OPCA_P12_PASS LAB_OPCA_P12_PASS_FILE 2>/dev/null || true

ca() { "$opca/ca.sh" "$@" 2>&1; }

# The level extension DER, as printed by the manager's cmd/opext.
der_of() {
  case "$1" in
    admin) echo 130561646D696E ;;
    operator) echo 13086F70657261746F72 ;;
    viewer) echo 1306766965776572 ;;
  esac
}
oid=1.3.6.1.4.1.59999.1.1

# ext_parse CERT prints the asn1parse lines from the level OID onwards.
ext_parse() {
  openssl x509 -in "$1" -outform DER | openssl asn1parse -inform DER | grep -A2 ":$oid\$"
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || echo missing; }

# --- shellcheck -------------------------------------------------------------
if command -v shellcheck >/dev/null; then
  if out="$(shellcheck -x -P SCRIPTDIR "$opca"/*.sh "$here"/*.sh 2>&1)"; then
    ok "shellcheck operator-ca/*.sh"
  else
    not_ok "shellcheck operator-ca/*.sh" "$out"
  fi
else
  not_ok "shellcheck operator-ca/*.sh" "shellcheck not installed"
fi

# --- init -------------------------------------------------------------------
out="$(ca init)" && ok "init exits 0" || not_ok "init exits 0" "$out"
[ "$(mode_of "$LAB_OPCA_DIR")" = 700 ] && ok "CA folder is mode 700" || not_ok "CA folder is mode 700" "$(mode_of "$LAB_OPCA_DIR")"
[ "$(mode_of "$LAB_OPCA_DIR/operator-ca.key")" = 600 ] && ok "CA key is mode 600" || not_ok "CA key is mode 600"
[ "$(mode_of "$LAB_OPCA_DIR/ocsp.key")" = 600 ] && ok "OCSP signer key is mode 600" || not_ok "OCSP signer key is mode 600"

cacrt="$LAB_OPCA_DIR/operator-ca.crt"
t="$(openssl x509 -in "$cacrt" -noout -text)" || true
contains "CA key is P-384" "$t" "NIST CURVE: P-384"
contains "CA is CA:TRUE with pathlen:0, critical" "$t" "X509v3 Basic Constraints: critical"
contains "CA pathlen is 0" "$t" "CA:TRUE, pathlen:0"
contains "CA key usage is critical" "$t" "X509v3 Key Usage: critical"
contains "CA key usage is keyCertSign and cRLSign" "$t" "Certificate Sign, CRL Sign"
contains "CA has a subject key identifier" "$t" "X509v3 Subject Key Identifier"
contains "CA is signed with SHA-384" "$t" "ecdsa-with-SHA384"
contains "init prints the CA SHA-256 fingerprint" "$out" "$(openssl x509 -in "$cacrt" -noout -fingerprint -sha256 | cut -d= -f2)"
lacks "init never prints the CA key" "$out" "PRIVATE KEY"

cnf="$(cat "$LAB_OPCA_DIR/operator-ca.cnf")" || true
lacks "cnf has no .include_section (OpenSSL has none)" "$cnf" ".include_section"
contains "cnf never copies CSR extensions" "$cnf" "copy_extensions  = none"
contains "cnf keeps only the CN" "$cnf" "policy           = policy_cn_only"
contains "cnf CRLs are valid for 7 days" "$cnf" "default_crl_days = 7"
for lvl in admin operator viewer; do
  sect="$(awk -v s="[ op_$lvl ]" '$0 == s {p=1; next} /^\[/ {p=0} p' "$LAB_OPCA_DIR/operator-ca.cnf")"
  contains "op_$lvl is CA:FALSE, critical" "$sect" "basicConstraints       = critical, CA:FALSE"
  contains "op_$lvl is clientAuth only" "$sect" "extendedKeyUsage       = clientAuth"
  contains "op_$lvl carries the OCSP AIA" "$sect" "authorityInfoAccess    = OCSP;URI:$LAB_OPCA_OCSP_URL"
  contains "op_$lvl level DER" "$sect" "$oid = DER:$(printf '%s' "$(der_of "$lvl")" | sed 's/../&:/g; s/:$//')"
done

out="$(ca init)" && not_ok "init refuses to overwrite an existing CA" || ok "init refuses to overwrite an existing CA"
contains "the refusal says why" "$out" "already holds an operator CA"

# --- the delegated OCSP signer ----------------------------------------------
t="$(openssl x509 -in "$LAB_OPCA_DIR/ocsp.crt" -noout -text)" || true
contains "OCSP signer EKU is OCSPSigning" "$t" "OCSP Signing"
contains "OCSP signer carries noCheck" "$t" "OCSP No Check"
contains "OCSP signer is CA:FALSE" "$t" "CA:FALSE"
openssl verify -CAfile "$cacrt" "$LAB_OPCA_DIR/ocsp.crt" >/dev/null 2>&1 \
  && ok "OCSP signer verifies to the CA" || not_ok "OCSP signer verifies to the CA"
days=$((($(date -d "$(openssl x509 -in "$LAB_OPCA_DIR/ocsp.crt" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400))
[ "$days" -ge 29 ] && [ "$days" -le 30 ] && ok "OCSP signer is valid for 30 days" || not_ok "OCSP signer is valid for 30 days" "$days"

# --- the first CRL ----------------------------------------------------------
crl="$LAB_OPCA_DIR/fleetos-operator.crl.pem"
openssl crl -in "$crl" -CAfile "$cacrt" -noout 2>&1 | grep -q "verify OK" \
  && ok "CRL verifies against the CA" || not_ok "CRL verifies against the CA"
t="$(openssl crl -in "$crl" -noout -text)" || true
contains "CRL has a nextUpdate" "$t" "Next Update:"
contains "CRL has a CRL number" "$t" "X509v3 CRL Number"
contains "CRL has an AKI" "$t" "X509v3 Authority Key Identifier"

# --- issue ------------------------------------------------------------------
out="$(LAB_OPCA_P12_PASS=short ca issue admin admin@lab.example.org)" \
  && not_ok "issue refuses a passphrase under 18 bytes" || ok "issue refuses a passphrase under 18 bytes"
out="$(ca issue admin admin@lab.example.org)" \
  && not_ok "issue refuses without a passphrase" || ok "issue refuses without a passphrase"
out="$(LAB_OPCA_P12_PASS=correct-horse-battery-1 ca issue root admin@lab.example.org)" \
  && not_ok "issue refuses an unknown level" || ok "issue refuses an unknown level"
out="$(LAB_OPCA_P12_PASS=correct-horse-battery-1 ca issue admin 'not an email')" \
  && not_ok "issue refuses a CN that isn't an email" || ok "issue refuses a CN that isn't an email"

pass1="correct-horse-battery-staple-1"
printf '%s\n' "$pass1" >"$work/pass"
chmod 600 "$work/pass"
for lvl in admin operator viewer; do
  email="$lvl@lab.example.org"
  if [ "$lvl" = admin ]; then
    out="$(LAB_OPCA_P12_PASS_FILE="$work/pass" ca issue "$lvl" "Admin@Lab.Example.org")" \
      && ok "issue $lvl exits 0 (passphrase from a file)" || not_ok "issue $lvl exits 0 (passphrase from a file)" "$out"
  else
    out="$(LAB_OPCA_P12_PASS="$pass1" ca issue "$lvl" "$email")" \
      && ok "issue $lvl exits 0 (passphrase from the environment)" || not_ok "issue $lvl exits 0 (passphrase from the environment)" "$out"
  fi
  lacks "issue $lvl never prints the passphrase" "$out" "$pass1"
  d="$LAB_OPCA_DIR/issued/$email"
  crt="$d/$email.crt"
  [ -f "$crt" ] && ok "issue $lvl writes $email.crt (CN lower-cased)" || { not_ok "issue $lvl writes $email.crt" "$(ls "$LAB_OPCA_DIR/issued" 2>&1)"; continue; }
  p="$(ext_parse "$crt")" || true
  lacks "$lvl level extension is NOT critical" "$p" "BOOLEAN"
  contains "$lvl level extension DER matches cmd/opext" "$p" "[HEX DUMP]:$(der_of "$lvl")"
  lacks "$lvl text shows no critical level extension" "$(openssl x509 -in "$crt" -noout -text)" "$oid: critical"
  t="$(openssl x509 -in "$crt" -noout -text)" || true
  contains "$lvl subject is exactly CN=<email>" "$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253)" "subject=CN=$email"
  contains "$lvl key is P-384" "$t" "NIST CURVE: P-384"
  contains "$lvl EKU is clientAuth" "$t" "TLS Web Client Authentication"
  lacks "$lvl EKU has nothing else" "$t" "TLS Web Server Authentication"
  contains "$lvl KU is critical" "$t" "X509v3 Key Usage: critical"
  contains "$lvl basic constraints are present and critical" "$t" "X509v3 Basic Constraints: critical"
  contains "$lvl carries the OCSP URI" "$t" "OCSP - URI:$LAB_OPCA_OCSP_URL"
  openssl verify -CAfile "$cacrt" -purpose sslclient "$crt" >/dev/null 2>&1 \
    && ok "$lvl verifies to the CA as a client cert" || not_ok "$lvl verifies to the CA as a client cert"
  p12="$d/$email.p12"
  if openssl pkcs12 -in "$p12" -passin "pass:$pass1" -nodes 2>/dev/null >"$work/p12.txt"; then
    ok "$lvl PKCS#12 opens with the passphrase"
    [ "$(grep -c 'BEGIN CERTIFICATE' "$work/p12.txt")" = 2 ] && ok "$lvl PKCS#12 holds the cert and the CA" || not_ok "$lvl PKCS#12 holds the cert and the CA"
    grep -q 'BEGIN PRIVATE KEY' "$work/p12.txt" && ok "$lvl PKCS#12 holds the key" || not_ok "$lvl PKCS#12 holds the key"
  else
    not_ok "$lvl PKCS#12 opens with the passphrase"
  fi
  openssl pkcs12 -in "$p12" -passin "pass:wrong-passphrase-xyz" -nodes >/dev/null 2>&1 \
    && not_ok "$lvl PKCS#12 refuses a wrong passphrase" || ok "$lvl PKCS#12 refuses a wrong passphrase"
  [ "$(mode_of "$p12")" = 600 ] && ok "$lvl PKCS#12 is mode 600" || not_ok "$lvl PKCS#12 is mode 600"
done
if grep -rqF "$pass1" "$LAB_OPCA_DIR" "$LAB_K8S_STATE" 2>/dev/null; then
  not_ok "the passphrase is written nowhere"
else
  ok "the passphrase is written nowhere"
fi

# --- check ------------------------------------------------------------------
admin="$LAB_OPCA_DIR/issued/admin@lab.example.org/admin@lab.example.org.crt"
ca check "$admin" admin >/dev/null && ok "check accepts the admin cert as admin" || not_ok "check accepts the admin cert as admin"
ca check "$admin" viewer >/dev/null && not_ok "check refuses the admin cert as viewer" || ok "check refuses the admin cert as viewer"
# A critical level extension is what Go's verifier refuses; check must catch it.
openssl ecparam -name secp384r1 -genkey -noout -out "$work/crit.key" 2>/dev/null
openssl req -new -key "$work/crit.key" -subj "/CN=crit@lab.example.org" -out "$work/crit.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n%s=critical,DER:13:05:61:64:6D:69:6E\n' "$oid" >"$work/crit.ext"
(cd "$LAB_OPCA_DIR" && openssl x509 -req -in "$work/crit.csr" -CA operator-ca.crt -CAkey operator-ca.key -CAcreateserial \
  -CAserial "$work/crit.srl" -days 1 -extfile "$work/crit.ext" -out "$work/crit.crt" 2>/dev/null)
out="$(ca check "$work/crit.crt" admin)" && not_ok "check refuses a critical level extension" || ok "check refuses a critical level extension"
contains "the refusal names the criticality" "$out" "critical"

# --- revoke and the CRL -----------------------------------------------------
viewer="$LAB_OPCA_DIR/issued/viewer@lab.example.org/viewer@lab.example.org.crt"
vserial="$(openssl x509 -in "$viewer" -noout -serial | cut -d= -f2)"
out="$(ca revoke "$viewer" superseded)" && ok "revoke exits 0" || not_ok "revoke exits 0" "$out"
t="$(openssl crl -in "$crl" -noout -text)" || true
contains "the new CRL lists the revoked serial" "$t" "Serial Number: $vserial"
contains "the new CRL carries the reason" "$t" "Superseded"
openssl crl -in "$crl" -CAfile "$cacrt" -noout 2>&1 | grep -q "verify OK" \
  && ok "the new CRL verifies against the CA" || not_ok "the new CRL verifies against the CA"
out="$(ca revoke "$work/missing.crt")" && not_ok "revoke refuses a missing cert" || ok "revoke refuses a missing cert"

# --- a local openssl ocsp responder -----------------------------------------
port=""
for _ in 1 2 3 4 5; do
  p=$((20000 + RANDOM % 20000))
  (cd "$LAB_OPCA_DIR" && exec openssl ocsp -index index.txt -port "$p" -rsigner ocsp.crt -rkey ocsp.key \
    -CA operator-ca.crt -nmin 60 -ignore_err) >"$work/responder.log" 2>&1 &
  responder_pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -qi "waiting for OCSP client connections" "$work/responder.log" && { port=$p; break; }
    kill -0 "$responder_pid" 2>/dev/null || break
    sleep 0.3
  done
  [ -n "$port" ] && break
  kill "$responder_pid" 2>/dev/null || true
  responder_pid=""
done
if [ -n "$port" ]; then
  ok "local openssl ocsp responder started"
  q() { openssl ocsp -issuer "$cacrt" -cert "$1" -url "http://127.0.0.1:$port" -CAfile "$cacrt" -resp_text 2>&1; }
  out="$(q "$admin")"
  contains "responder: the admin cert is good" "$out" ": good"
  contains "responder: the response verifies (delegated signer)" "$out" "Response verify OK"
  contains "responder: signed by the delegated signer" "$out" "Responder Id: CN = "
  contains "responder: the response carries a nextUpdate" "$out" "Next Update:"
  out="$(q "$viewer")"
  contains "responder: the revoked viewer cert is revoked" "$out" ": revoked"
else
  not_ok "local openssl ocsp responder started" "$(cat "$work/responder.log")"
fi

# --- ocsp-signer renewal ----------------------------------------------------
old="$(openssl x509 -in "$LAB_OPCA_DIR/ocsp.crt" -noout -serial)"
out="$(ca ocsp-signer)" && ok "ocsp-signer exits 0" || not_ok "ocsp-signer exits 0" "$out"
[ "$(openssl x509 -in "$LAB_OPCA_DIR/ocsp.crt" -noout -serial)" != "$old" ] \
  && ok "ocsp-signer renews the signer cert" || not_ok "ocsp-signer renews the signer cert"

# --- publish (dry run) ------------------------------------------------------
out="$(DRY_RUN=1 "$opca/publish.sh" 2>&1)" && ok "publish dry run exits 0" || not_ok "publish dry run exits 0" "$out"
contains "publish applies server-side" "$out" "kubectl apply --server-side"
lacks "publish never prints the CA key" "$out" "BEGIN EC PRIVATE KEY"
lacks "publish never prints a private key" "$out" "PRIVATE KEY"
m="$LAB_K8S_STATE/operator-ca.yaml"
s="$LAB_K8S_STATE/operator-ocsp-secret.yaml"
if [ -f "$m" ] && [ -f "$s" ]; then
  y="$(cat "$m")" || true
  # shellcheck source=../../k8s/versions.env
  source "$root/k8s/versions.env"
  [[ ${OPENSSL_IMAGE:-} =~ ^alpine/openssl:[0-9.]+@sha256:[0-9a-f]{64}$ ]] \
    && ok "the openssl image is pinned by digest" || not_ok "the openssl image is pinned by digest" "${OPENSSL_IMAGE:-unset}"
  contains "responder uses the pinned image" "$y" "image: $OPENSSL_IMAGE"
  contains "responder runs openssl ocsp with a nextUpdate" "$y" "-nmin"
  contains "the FM operator CA ConfigMap is named for the chart" "$y" "name: fm-operator-ca"
  contains "the ConfigMap key is operator-ca.pem" "$y" "operator-ca.pem: |"
  contains "the CRL is published in a ConfigMap" "$y" "name: fm-operator-crl"
  contains "the responder Service is named operator-ocsp" "$y" "name: operator-ocsp"
  contains "the responder restarts when its data changes" "$y" "lab.cryptos.dev/ocsp-bundle-sha256:"
  lacks "responder probes never use a bare TCP connect (it wedges openssl ocsp)" "$y" "tcpSocket"
  contains "responder has a liveness probe" "$y" "livenessProbe:"
  [ "$(grep -c -- '- -noverify' "$m")" = 2 ] && ok "both probes send a real OCSP request" || not_ok "both probes send a real OCSP request"
  lacks "the manifest carries no private key" "$y" "PRIVATE KEY"
  sy="$(cat "$s")" || true
  lacks "the Secret never carries the CA key" "$sy" "$(base64 <"$LAB_OPCA_DIR/operator-ca.key" | tr -d '\n')"
  contains "the Secret carries the signer key" "$sy" "ocsp.key: $(base64 <"$LAB_OPCA_DIR/ocsp.key" | tr -d '\n')"
  [ "$(mode_of "$s")" = 600 ] && ok "the rendered Secret is mode 600" || not_ok "the rendered Secret is mode 600"
  if command -v kubeconform >/dev/null; then
    if o="$(kubeconform -strict -summary "$m" "$s" 2>&1)"; then ok "kubeconform operator-ca manifests"; else not_ok "kubeconform operator-ca manifests" "$o"; fi
  fi
else
  not_ok "publish renders its manifests" "$(ls "$LAB_K8S_STATE" 2>&1)"
fi

# --- Taskfile ---------------------------------------------------------------
if command -v task >/dev/null; then
  out="$(cd "$root" && task --list 2>&1)"
  for t in opca:init opca:issue opca:revoke opca:crl opca:ocsp-signer opca:publish opca:check; do
    contains "Taskfile lists $t" "$out" "$t"
  done
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
