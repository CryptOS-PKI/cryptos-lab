#!/usr/bin/env bash
# task k8s:up: a single-node kind cluster on the lab box with Traefik as the
# ingress on ports 80/443, cert-manager, and traefik/whoami behind an Ingress.
# Everything is pinned in versions.env. Re-running it changes nothing.
set -euo pipefail
LAB_STEP=k8s:up
# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

step "preflight"
LAB_ARCH="$(detect_arch)"
log info "cluster $LAB_K8S_CLUSTER, node image $KIND_NODE_IMAGE, arch $LAB_ARCH"
log info "cert-manager $CERT_MANAGER_VERSION, Traefik chart $TRAEFIK_CHART_VERSION, whoami $WHOAMI_IMAGE"
log debug "state $LAB_K8S_STATE, tools $LAB_TOOLS_DIR, KUBECONFIG $KUBECONFIG"
if ! dry_run; then
  need curl
  need docker "kind runs the cluster in a container"
  docker info >/dev/null 2>&1 || die "docker is installed but not reachable (is the daemon running, and is this user in the docker group?)"
  log debug "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
fi

step "tools"
ensure_cluster_tools

step "cluster"
if ! dry_run && cluster_exists; then
  log info "kind cluster $LAB_K8S_CLUSTER already exists"
  running="$(docker inspect -f '{{.Config.Image}}' "$LAB_K8S_CLUSTER-control-plane" 2>/dev/null || echo unknown)"
  if [ "$running" != "$KIND_NODE_IMAGE" ]; then
    log warn "the cluster runs $running, not the pinned $KIND_NODE_IMAGE; run task k8s:down then task k8s:up to move to the pin"
  fi
  run kind export kubeconfig --name "$LAB_K8S_CLUSTER" --kubeconfig "$KUBECONFIG"
else
  log info "creating kind cluster $LAB_K8S_CLUSTER"
  run kind create cluster --name "$LAB_K8S_CLUSTER" --image "$KIND_NODE_IMAGE" \
    --config "$K8S_DIR/manifests/kind-config.yaml" --kubeconfig "$KUBECONFIG" --wait "${LAB_K8S_WAIT_SECONDS}s"
fi

step "cert-manager $CERT_MANAGER_VERSION"
cm="$LAB_TOOLS_DIR/cache/cert-manager-$CERT_MANAGER_VERSION.yaml"
fetch_verified "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" \
  "$CERT_MANAGER_SHA256" "$cm"
apply_manifest "$cm" "cert-manager"
rollout cert-manager cert-manager cert-manager-cainjector cert-manager-webhook
run cmctl check api --wait="${LAB_K8S_WAIT_SECONDS}s"

step "Traefik chart $TRAEFIK_CHART_VERSION"
chart="$LAB_TOOLS_DIR/cache/traefik-$TRAEFIK_CHART_VERSION.tgz"
fetch_verified "https://traefik.github.io/charts/traefik/traefik-${TRAEFIK_CHART_VERSION}.tgz" "$TRAEFIK_CHART_SHA256" "$chart"
traefik="$LAB_K8S_STATE/traefik.yaml"
printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: traefik\n---\n' >"$traefik.ns"
run_to "$traefik.chart" helm template traefik "$chart" --namespace traefik --include-crds \
  --kube-version "${KUBECTL_VERSION#v}" -f "$K8S_DIR/manifests/traefik-values.yaml"
dry_run || cat "$traefik.ns" "$traefik.chart" >"$traefik"
rm -f "$traefik.ns" "$traefik.chart"
apply_manifest "$traefik" "Traefik"
rollout traefik traefik

step "whoami"
whoami="$LAB_K8S_STATE/whoami.yaml"
render "$K8S_DIR/manifests/whoami.yaml" "$whoami"
log info "rendered $whoami"
apply_manifest "$whoami" "whoami"
rollout "$LAB_K8S_NAMESPACE" whoami

step "smoke test: http://127.0.0.1/ through Traefik"
if dry_run; then
  run curl -fsS --max-time 5 http://127.0.0.1/
else
  ok=""
  for i in $(seq 1 30); do
    if body="$(curl -fsS --max-time 5 http://127.0.0.1/ 2>&1)" && printf '%s' "$body" | grep -q '^Hostname:'; then
      ok=1
      log info "whoami answered through Traefik ($(printf '%s' "$body" | head -n 1))"
      break
    fi
    log debug "attempt $i: no whoami answer yet (${body:-empty}); retrying"
    sleep 2
  done
  [ -n "$ok" ] || die "whoami did not answer on http://127.0.0.1/ after 30 tries"
fi

step "done"
log info "cluster $LAB_K8S_CLUSTER is up. For kubectl: export KUBECONFIG=$KUBECONFIG PATH=$LAB_TOOLS_DIR/bin:\$PATH"
log info "next: task k8s:issuer ACME_URL=... CA_BUNDLE=... HOST=..."
