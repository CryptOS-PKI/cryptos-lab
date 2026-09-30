#!/usr/bin/env bash
# task k8s:renew: forces cert-manager to renew certificate/whoami now, waits for
# a new serial in the secret, then runs k8s:verify to check the served chain.
set -euo pipefail
LAB_STEP=k8s:renew
# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

secret_serial() {
  kubectl -n "$LAB_K8S_NAMESPACE" get secret whoami-tls -o 'jsonpath={.data.tls\.crt}' 2>/dev/null |
    base64 -d >"$LAB_K8S_STATE/secret.pem" && leaf_serial "$LAB_K8S_STATE/secret.pem"
}

step "current serial"
old=""
if ! dry_run; then
  need cmctl "run task k8s:up first"
  old="$(secret_serial)" || die "no issued secret whoami-tls yet; run task k8s:issuer and task k8s:verify first"
  log info "secret whoami-tls holds serial $old"
fi

step "renew"
run cmctl renew -n "$LAB_K8S_NAMESPACE" whoami
if ! dry_run; then
  deadline=$((SECONDS + LAB_K8S_WAIT_SECONDS))
  new="$old"
  while [ "$new" = "$old" ]; do
    [ "$SECONDS" -lt "$deadline" ] || die "no new certificate within ${LAB_K8S_WAIT_SECONDS}s; see kubectl -n $LAB_K8S_NAMESPACE describe certificate whoami"
    sleep 5
    new="$(secret_serial || echo "$old")"
    log debug "secret serial $new"
  done
  log info "renewed: serial $old -> $new"
fi

step "verify"
run "$K8S_DIR/verify.sh"
if ! dry_run; then
  served="$(cat "$LAB_K8S_STATE/served-serial")"
  [ "$served" != "$old" ] || die "Traefik still serves the old serial $old"
  log info "the renewed certificate (serial $served) is served"
fi
