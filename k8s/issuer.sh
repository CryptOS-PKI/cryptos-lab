#!/usr/bin/env bash
# task k8s:issuer ACME_URL=... CA_BUNDLE=... HOST=...: an ACME ClusterIssuer for
# a CryptOS Intermediate's directory, trusting the CryptOS root, solving http-01
# through Traefik, and a P-384 Certificate for HOST served by a TLS Ingress.
# EAB_KID and EAB_HMAC (or LAB_ACME_EAB_KID / LAB_ACME_EAB_HMAC in .env) add an
# External Account Binding, which CryptOS requires unless the node allows
# anonymous accounts.
set -euo pipefail
LAB_STEP=k8s:issuer
# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

step "inputs"
ACME_URL="${ACME_URL:-${LAB_ACME_URL:-}}"
CA_BUNDLE="${CA_BUNDLE:-${LAB_CA_BUNDLE:-}}"
HOST="${HOST:-${LAB_K8S_HOST:-}}"
EAB_KID="${EAB_KID:-${LAB_ACME_EAB_KID:-}}"
EAB_HMAC="${EAB_HMAC:-${LAB_ACME_EAB_HMAC:-}}"

[[ $ACME_URL =~ ^https://[^/]+/.+ ]] || die "ACME_URL must be the Intermediate's https ACME directory URL (got '${ACME_URL}')"
[ -n "$CA_BUNDLE" ] || die "CA_BUNDLE must name the CryptOS root certificate (PEM)"
[ -f "$CA_BUNDLE" ] || die "CA_BUNDLE $CA_BUNDLE does not exist"
openssl x509 -noout -in "$CA_BUNDLE" >/dev/null 2>&1 || die "CA_BUNDLE $CA_BUNDLE is not a PEM certificate"
CA_BUNDLE="$(cd "$(dirname "$CA_BUNDLE")" && pwd)/$(basename "$CA_BUNDLE")"
valid_host "$HOST" || die "HOST must be a lower-case DNS name (got '${HOST}')"
if { [ -n "$EAB_KID" ] && [ -z "$EAB_HMAC" ]; } || { [ -z "$EAB_KID" ] && [ -n "$EAB_HMAC" ]; }; then
  die "set both EAB_KID and EAB_HMAC for an External Account Binding, or neither"
fi
log info "ACME directory $ACME_URL"
log info "trust root $(openssl x509 -noout -subject -in "$CA_BUNDLE") ($CA_BUNDLE)"
log info "certificate for $HOST in namespace $LAB_K8S_NAMESPACE, ECDSA P-384"

if ! dry_run; then
  need kind "run task k8s:up first"
  need kubectl "run task k8s:up first"
  cluster_exists || die "no kind cluster $LAB_K8S_CLUSTER; run task k8s:up first"
fi

# EAB_BLOCK and CA_BUNDLE_B64 are read by render.
# shellcheck disable=SC2034
EAB_BLOCK=""
# shellcheck disable=SC2034
if [ -n "$EAB_KID" ]; then
  step "external account binding"
  log info "EAB key id $EAB_KID (the HMAC key is never logged)"
  if dry_run; then
    printf '+ %s\n' "kubectl -n cert-manager create secret generic $LAB_ACME_ISSUER-eab --from-file=secret=<EAB_HMAC> --dry-run=client -o yaml | kubectl apply --server-side -f -"
  else
    # Process substitution keeps the key out of argv and off disk.
    kubectl -n cert-manager create secret generic "$LAB_ACME_ISSUER-eab" \
      --from-file=secret=<(printf '%s' "$EAB_HMAC") --dry-run=client -o yaml |
      kubectl apply --server-side --field-manager="$LAB_FIELD_MANAGER" -f - >/dev/null
    log info "secret cert-manager/$LAB_ACME_ISSUER-eab applied"
  fi
  EAB_BLOCK="    externalAccountBinding:
      keyID: $EAB_KID
      keySecretRef:
        name: $LAB_ACME_ISSUER-eab
        key: secret"
else
  log info "no External Account Binding (the node must set allow_anonymous_accounts)"
fi

step "ClusterIssuer, Certificate and TLS Ingress"
# shellcheck disable=SC2034
CA_BUNDLE_B64="$(base64 <"$CA_BUNDLE" | tr -d '\n')"
issuer="$LAB_K8S_STATE/issuer.yaml"
render "$K8S_DIR/manifests/issuer.yaml" "$issuer"
log info "rendered $issuer"
apply_manifest "$issuer" "issuer"
save_issuer_inputs

step "done"
log info "cert-manager is ordering a certificate for $HOST from $ACME_URL"
log info "the Intermediate must resolve $HOST to this box and reach it on port 80"
log info "next: task k8s:verify"
