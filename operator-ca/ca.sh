#!/usr/bin/env bash
# The lab Fleet Manager operator CA: an external OpenSSL CA, never a CryptOS
# node. Everything lives in LAB_OPCA_DIR (default .state/operator-ca, mode 700).
#
#   ca.sh init                  create the CA, the delegated OCSP signer and a CRL
#   ca.sh issue LEVEL EMAIL     key, CSR, cert and PKCS#12 for an operator
#   ca.sh check CERT LEVEL      check an operator cert against the FM's rules
#   ca.sh revoke CERT [REASON]  revoke a cert and publish a new CRL
#   ca.sh crl                   publish a new CRL (each is valid for 7 days)
#   ca.sh ocsp-signer           renew the delegated OCSP signer (30 days)
#
# The PKCS#12 passphrase comes from LAB_OPCA_P12_PASS_FILE (first line) or
# LAB_OPCA_P12_PASS, never from the command line, and is never logged.
set -euo pipefail
LAB_STEP=opca
# shellcheck source=../k8s/lib.sh
source "$(cd "$(dirname "$0")/.." && pwd)/k8s/lib.sh"

OPCA_SRC="$LAB_ROOT/operator-ca"
: "${LAB_OPCA_DIR:=$LAB_ROOT/.state/operator-ca}"
: "${LAB_OPCA_ORG:=Example Org}"
: "${LAB_OPCA_CN:=Example FleetOS Operator CA (lab)}"
: "${LAB_OPCA_OCSP_URL:=http://operator-ocsp.fleet.svc.cluster.local/}"
LEVEL_OID=1.3.6.1.4.1.59999.1.1
CRL_FILE=fleetos-operator.crl.pem

# level_der LEVEL prints the level extension DER, as cmd/opext prints it.
level_der() {
  case "$1" in
    admin) echo 130561646D696E ;;
    operator) echo 13086F70657261746F72 ;;
    viewer) echo 1306766965776572 ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

# in_ca CMD... runs CMD inside the CA folder, where operator-ca.cnf's
# relative paths resolve.
in_ca() { (cd "$LAB_OPCA_DIR" && "$@"); }

require_ca() {
  [ -f "$LAB_OPCA_DIR/operator-ca.crt" ] && [ -f "$LAB_OPCA_DIR/operator-ca.cnf" ] \
    || die "no operator CA in $LAB_OPCA_DIR; run: task opca:init"
}

fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }

gen_crl() {
  log info "publishing a new CRL"
  in_ca openssl ca -config operator-ca.cnf -gencrl -out "$CRL_FILE.part" 2>/dev/null \
    || die "openssl ca -gencrl failed"
  mv "$LAB_OPCA_DIR/$CRL_FILE.part" "$LAB_OPCA_DIR/$CRL_FILE"
  log info "CRL $LAB_OPCA_DIR/$CRL_FILE, next update $(openssl crl -in "$LAB_OPCA_DIR/$CRL_FILE" -noout -nextupdate | cut -d= -f2)"
}

gen_ocsp_signer() {
  log info "making the delegated OCSP signer (EKU OCSPSigning, noCheck, 30 days)"
  local tmp="$LAB_OPCA_DIR/ocsp.key.part"
  (umask 077 && openssl ecparam -name secp384r1 -genkey -noout -out "$tmp")
  openssl req -new -key "$tmp" -subj "/O=$LAB_OPCA_ORG/CN=$LAB_OPCA_CN OCSP" -out "$LAB_OPCA_DIR/ocsp.csr"
  in_ca openssl ca -config operator-ca.cnf -batch -extensions ocsp_signer -days 30 -notext \
    -in ocsp.csr -out ocsp.crt.part 2>/dev/null || die "signing the OCSP signer failed"
  mv "$tmp" "$LAB_OPCA_DIR/ocsp.key"
  mv "$LAB_OPCA_DIR/ocsp.crt.part" "$LAB_OPCA_DIR/ocsp.crt"
  rm -f "$LAB_OPCA_DIR/ocsp.csr"
  log info "OCSP signer valid until $(openssl x509 -in "$LAB_OPCA_DIR/ocsp.crt" -noout -enddate | cut -d= -f2)"
}

cmd_init() {
  need openssl
  if [ -e "$LAB_OPCA_DIR/operator-ca.key" ] || [ -e "$LAB_OPCA_DIR/operator-ca.crt" ]; then
    die "$LAB_OPCA_DIR already holds an operator CA; refusing to overwrite it"
  fi
  step "operator CA in $LAB_OPCA_DIR"
  (umask 077 && mkdir -p "$LAB_OPCA_DIR/newcerts" "$LAB_OPCA_DIR/issued")
  chmod 700 "$LAB_OPCA_DIR"
  (umask 077 && openssl ecparam -name secp384r1 -genkey -noout -out "$LAB_OPCA_DIR/operator-ca.key")
  chmod 600 "$LAB_OPCA_DIR/operator-ca.key"
  openssl req -x509 -new -key "$LAB_OPCA_DIR/operator-ca.key" -sha384 -days 3650 \
    -subj "/O=$LAB_OPCA_ORG/CN=$LAB_OPCA_CN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$LAB_OPCA_DIR/operator-ca.crt"
  : >"$LAB_OPCA_DIR/index.txt"
  openssl rand -hex 16 >"$LAB_OPCA_DIR/serial"
  echo 1000 >"$LAB_OPCA_DIR/crlnumber"
  render "$OPCA_SRC/operator-ca.cnf.tmpl" "$LAB_OPCA_DIR/operator-ca.cnf"
  log info "leaf OCSP URI (AIA): $LAB_OPCA_OCSP_URL"
  gen_ocsp_signer
  gen_crl
  log info "operator CA: $(openssl x509 -in "$LAB_OPCA_DIR/operator-ca.crt" -noout -subject)"
  echo "operator CA SHA-256: $(fingerprint "$LAB_OPCA_DIR/operator-ca.crt")"
}

# p12_passout prints the openssl -passout argument for the passphrase source,
# after checking the passphrase is at least 18 bytes. It never prints the
# passphrase itself.
p12_passout() {
  local pass
  if [ -n "${LAB_OPCA_P12_PASS_FILE:-}" ]; then
    [ -r "$LAB_OPCA_P12_PASS_FILE" ] || die "LAB_OPCA_P12_PASS_FILE is not readable"
    IFS= read -r pass <"$LAB_OPCA_P12_PASS_FILE" || true
    [ "${#pass}" -ge 18 ] || die "the PKCS#12 passphrase must be at least 18 bytes"
    echo "file:$LAB_OPCA_P12_PASS_FILE"
  elif [ -n "${LAB_OPCA_P12_PASS:-}" ]; then
    [ "${#LAB_OPCA_P12_PASS}" -ge 18 ] || die "the PKCS#12 passphrase must be at least 18 bytes"
    echo "env:LAB_OPCA_P12_PASS"
  else
    die "set LAB_OPCA_P12_PASS_FILE (preferred) or LAB_OPCA_P12_PASS for the PKCS#12 passphrase"
  fi
}

# check_cert CERT LEVEL applies the Fleet Manager's rules for an operator cert.
check_cert() {
  local crt=$1 level=$2 want parsed text errs=""
  want="$(level_der "$level")" || die "unknown level $level (admin, operator or viewer)"
  [ -r "$crt" ] || die "cannot read $crt"
  parsed="$(openssl x509 -in "$crt" -outform DER | openssl asn1parse -inform DER | grep -A2 ":$LEVEL_OID\$" || true)"
  text="$(openssl x509 -in "$crt" -noout -text)"
  if [ -z "$parsed" ]; then
    errs="$errs; no level extension $LEVEL_OID"
  else
    case "$parsed" in *BOOLEAN*) errs="$errs; the level extension is critical (Go's verifier refuses it)" ;; esac
    case "$parsed" in *"[HEX DUMP]:$want"*) ;; *) errs="$errs; the level extension is not $level ($want)" ;; esac
  fi
  case "$text" in *"TLS Web Client Authentication"*) ;; *) errs="$errs; EKU lacks clientAuth" ;; esac
  [ "$(printf '%s\n' "$text" | grep -A1 'Extended Key Usage' | tail -n 1 | tr -d ' ')" = "TLSWebClientAuthentication" ] \
    || errs="$errs; EKU is not exactly clientAuth"
  case "$text" in *"X509v3 Key Usage: critical"*) ;; *) errs="$errs; key usage is not critical" ;; esac
  case "$text" in *"X509v3 Basic Constraints: critical"*"CA:FALSE"*) ;; *) errs="$errs; basic constraints are not critical CA:FALSE" ;; esac
  if [ -f "$LAB_OPCA_DIR/operator-ca.crt" ]; then
    openssl verify -CAfile "$LAB_OPCA_DIR/operator-ca.crt" -purpose sslclient "$crt" >/dev/null 2>&1 \
      || errs="$errs; does not verify to $LAB_OPCA_DIR/operator-ca.crt"
  fi
  if [ -n "$errs" ]; then
    log error "$crt:${errs#;}"
    return 1
  fi
  log info "$crt: $level operator cert, level extension non-critical, EKU clientAuth only"
}

cmd_issue() {
  [ $# -eq 2 ] || usage
  local level=$1 email
  email="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  level_der "$level" >/dev/null || die "unknown level $level (admin, operator or viewer)"
  [[ $email =~ ^[a-z0-9._%+-]+@([a-z0-9-]+\.)+[a-z]{2,63}$ ]] || die "the CN must be an email address, got: $email"
  require_ca
  local passout d
  passout="$(p12_passout)"
  d="$LAB_OPCA_DIR/issued/$email"
  [ ! -e "$d/$email.crt" ] || die "$d/$email.crt exists; revoke it first, then move the folder aside"
  step "issue $email at level $level"
  (umask 077 && mkdir -p "$d")
  (umask 077 && openssl ecparam -name secp384r1 -genkey -noout -out "$d/$email.key")
  openssl req -new -key "$d/$email.key" -sha384 -subj "/CN=$email" -out "$d/$email.csr"
  in_ca openssl ca -config operator-ca.cnf -batch -extensions "op_$level" -notext \
    -in "$d/$email.csr" -out "$d/$email.crt" 2>/dev/null || die "openssl ca refused the CSR"
  check_cert "$d/$email.crt" "$level" || die "the issued cert fails the checks"
  (umask 077 && openssl pkcs12 -export -inkey "$d/$email.key" -in "$d/$email.crt" \
    -certfile "$LAB_OPCA_DIR/operator-ca.crt" -name "FleetOS $level ($email)" \
    -out "$d/$email.p12" -passout "$passout")
  chmod 600 "$d/$email.p12" "$d/$email.key"
  log info "serial $(openssl x509 -in "$d/$email.crt" -noout -serial | cut -d= -f2)"
  echo "PKCS#12: $d/$email.p12"
}

cmd_revoke() {
  [ $# -ge 1 ] && [ $# -le 2 ] || usage
  local crt=$1 reason=${2:-superseded}
  require_ca
  [ -r "$crt" ] || die "cannot read $crt"
  crt="$(cd "$(dirname "$crt")" && pwd)/$(basename "$crt")"
  step "revoke $(openssl x509 -in "$crt" -noout -subject) (serial $(openssl x509 -in "$crt" -noout -serial | cut -d= -f2), $reason)"
  in_ca openssl ca -config operator-ca.cnf -revoke "$crt" -crl_reason "$reason" 2>/dev/null \
    || die "openssl ca -revoke failed"
  gen_crl
  log info "run task opca:publish to update the CRL and the OCSP responder in the cluster"
}

cmd="${1:-}"
[ $# -eq 0 ] || shift
case "$cmd" in
  init) cmd_init ;;
  issue) cmd_issue "$@" ;;
  check)
    [ $# -eq 2 ] || usage
    check_cert "$1" "$2"
    ;;
  revoke) cmd_revoke "$@" ;;
  crl)
    require_ca
    gen_crl
    ;;
  ocsp-signer)
    require_ca
    gen_ocsp_signer
    ;;
  *) usage ;;
esac
