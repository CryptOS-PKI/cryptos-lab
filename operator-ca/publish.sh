#!/usr/bin/env bash
# Publishes the lab operator CA into the kind cluster, in LAB_FM_NAMESPACE:
# the CA cert as the Fleet Manager's operator CA ConfigMap (fm-operator-ca),
# the current CRL (fm-operator-crl), and an openssl ocsp responder
# (operator-ocsp) with the delegated signer. The CA key never leaves
# LAB_OPCA_DIR. Re-run it after every revoke, CRL or signer renewal.
set -euo pipefail
LAB_STEP=opca:publish
# shellcheck source=../k8s/lib.sh
source "$(cd "$(dirname "$0")/.." && pwd)/k8s/lib.sh"

: "${LAB_OPCA_DIR:=$LAB_ROOT/.state/operator-ca}"
: "${LAB_FM_NAMESPACE:=fleet}"
export LAB_FM_NAMESPACE OPENSSL_IMAGE

for f in operator-ca.crt ocsp.crt ocsp.key index.txt fleetos-operator.crl.pem; do
  [ -r "$LAB_OPCA_DIR/$f" ] || die "missing $LAB_OPCA_DIR/$f; run: task opca:init"
done

indent() { sed 's/^/    /' "$1"; }
b64() { base64 <"$1" | tr -d '\n'; }

OPCA_CA_PEM_INDENTED="$(indent "$LAB_OPCA_DIR/operator-ca.crt")"
OPCA_CRL_PEM_INDENTED="$(indent "$LAB_OPCA_DIR/fleetos-operator.crl.pem")"
OPCA_BUNDLE_SHA256="$(cat "$LAB_OPCA_DIR/operator-ca.crt" "$LAB_OPCA_DIR/ocsp.crt" "$LAB_OPCA_DIR/ocsp.key" \
  "$LAB_OPCA_DIR/index.txt" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)"
export OPCA_CA_PEM_INDENTED OPCA_CRL_PEM_INDENTED OPCA_BUNDLE_SHA256

manifest="$LAB_K8S_STATE/operator-ca.yaml"
secret="$LAB_K8S_STATE/operator-ocsp-secret.yaml"
render "$LAB_ROOT/operator-ca/manifests/operator-ca.yaml" "$manifest"
(
  umask 077
  cat >"$secret" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: operator-ocsp
  namespace: $LAB_FM_NAMESPACE
type: Opaque
data:
  operator-ca.crt: $(b64 "$LAB_OPCA_DIR/operator-ca.crt")
  ocsp.crt: $(b64 "$LAB_OPCA_DIR/ocsp.crt")
  ocsp.key: $(b64 "$LAB_OPCA_DIR/ocsp.key")
  index.txt: $(b64 "$LAB_OPCA_DIR/index.txt")
EOF
)
log debug "rendered $manifest and $secret (mode 600)"

step "publish the operator CA to namespace $LAB_FM_NAMESPACE"
dry_run || kubectl get --raw /readyz >/dev/null 2>&1 || die "no cluster at $KUBECONFIG; run: task k8s:up"
apply_manifest "$manifest" "operator CA, CRL and responder"
# Applied without a diff, so the signer key never reaches a log.
run kubectl apply --server-side --force-conflicts --field-manager="$LAB_FIELD_MANAGER" -f "$secret"
rollout "$LAB_FM_NAMESPACE" operator-ocsp
log info "operator CA SHA-256: $(openssl x509 -in "$LAB_OPCA_DIR/operator-ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
log info "responder: http://operator-ocsp.$LAB_FM_NAMESPACE.svc.cluster.local/ (in the cluster)"
