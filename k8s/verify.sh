#!/usr/bin/env bash
# task k8s:verify [HOST=...] [CA_BUNDLE=...]: waits for the Certificate to be
# Ready, reads the chain Traefik serves for HOST, checks it verifies to the
# CryptOS root and matches the issued secret, and prints the serial.
set -euo pipefail
LAB_STEP=k8s:verify
# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

load_issuer_inputs
valid_host "$HOST" || die "HOST must be a lower-case DNS name (got '${HOST}'); pass HOST= or run task k8s:issuer first"
[ -f "$CA_BUNDLE" ] || die "CA_BUNDLE must name the CryptOS root certificate (got '${CA_BUNDLE}')"
log info "host $HOST via $LAB_K8S_ADDR:443, root $(openssl x509 -noout -subject -in "$CA_BUNDLE")"

step "wait for certificate/whoami Ready"
if ! run kubectl -n "$LAB_K8S_NAMESPACE" wait certificate/whoami --for=condition=Ready --timeout="${LAB_K8S_WAIT_SECONDS}s"; then
  log error "certificate/whoami is not Ready; current state follows"
  kubectl -n "$LAB_K8S_NAMESPACE" describe certificate whoami >&2 || true
  kubectl -n "$LAB_K8S_NAMESPACE" get certificaterequests,orders.acme.cert-manager.io,challenges.acme.cert-manager.io -o wide >&2 || true
  kubectl -n "$LAB_K8S_NAMESPACE" describe challenges.acme.cert-manager.io >&2 || true
  kubectl describe clusterissuer "$LAB_ACME_ISSUER" >&2 || true
  die "certificate/whoami did not become Ready within ${LAB_K8S_WAIT_SECONDS}s"
fi

step "issued secret"
secret="$LAB_K8S_STATE/secret.pem"
if dry_run; then
  run kubectl -n "$LAB_K8S_NAMESPACE" get secret whoami-tls -o 'jsonpath={.data.tls\.crt}'
else
  kubectl -n "$LAB_K8S_NAMESPACE" get secret whoami-tls -o 'jsonpath={.data.tls\.crt}' | base64 -d >"$secret"
  want="$(leaf_serial "$secret")"
  log info "secret whoami-tls holds serial $want"
fi

step "served chain"
sclient="$LAB_K8S_STATE/s_client.txt"
served="$LAB_K8S_STATE/served.pem"
if dry_run; then
  run_to "$sclient" openssl s_client -connect "$LAB_K8S_ADDR:443" -servername "$HOST" -showcerts
  log info "dry run: the chain, SAN, key and serial checks run against the served chain"
  exit 0
fi
# Traefik can take a few seconds to pick up a new or renewed secret.
got=""
for i in $(seq 1 15); do
  openssl s_client -connect "$LAB_K8S_ADDR:443" -servername "$HOST" -showcerts </dev/null >"$sclient" 2>&1 || true
  split_pem <"$sclient" >"$served"
  if [ -s "$served" ]; then
    got="$(leaf_serial "$served")"
    [ "$got" = "$want" ] && break
    log debug "attempt $i: served serial $got, want $want; retrying"
  else
    log debug "attempt $i: no certificate served yet ($(tail -n 1 "$sclient")); retrying"
  fi
  sleep 2
done
[ "$got" = "$want" ] || die "Traefik serves serial '${got:-none}' for $HOST, not the issued $want"
log info "Traefik serves the issued certificate"
check_chain "$served" "$CA_BUNDLE" "$HOST" || die "the served chain failed its checks (see above)"
printf '%s\n' "$got" >"$LAB_K8S_STATE/served-serial"

step "result"
describe_leaf "$served"
log info "look for serial $got in the Intermediate's audit log and ListIssued"
