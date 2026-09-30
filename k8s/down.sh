#!/usr/bin/env bash
# task k8s:down: deletes the kind cluster and everything in it. The downloaded
# tools and artifacts in .tools/ stay cached for the next k8s:up.
set -euo pipefail
LAB_STEP=k8s:down
# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

step "delete kind cluster $LAB_K8S_CLUSTER"
if dry_run; then
  run kind delete cluster --name "$LAB_K8S_CLUSTER" --kubeconfig "$KUBECONFIG"
  exit 0
fi
if ! command -v kind >/dev/null; then
  log info "kind is not installed here, so there is no cluster to delete"
  exit 0
fi
if cluster_exists; then
  run kind delete cluster --name "$LAB_K8S_CLUSTER" --kubeconfig "$KUBECONFIG"
  rm -f "$LAB_K8S_STATE/issuer.env" "$LAB_K8S_STATE/served-serial"
  log info "deleted cluster $LAB_K8S_CLUSTER"
else
  log info "no kind cluster named $LAB_K8S_CLUSTER; nothing to do"
fi
