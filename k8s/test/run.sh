#!/usr/bin/env bash
# Offline checks for the k8s/ tooling: shellcheck, the pins file, every task in
# dry-run mode, the rendered manifests through kubeconform, and the served-chain
# checks against a throwaway openssl hierarchy. No cluster or docker is needed.
# ok and not_ok always succeed, so 'A && ok || not_ok' is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
k8s="$(cd "$here/.." && pwd)"
root="$(cd "$k8s/.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

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
export LOG_LEVEL=debug
unset ACME_URL CA_BUNDLE HOST EAB_KID EAB_HMAC LAB_ACME_URL LAB_CA_BUNDLE LAB_K8S_HOST \
  LAB_ACME_EAB_KID LAB_ACME_EAB_HMAC 2>/dev/null || true

dry() { DRY_RUN=1 "$@" 2>&1; }

# --- shellcheck -------------------------------------------------------------
if command -v shellcheck >/dev/null; then
  if out="$(shellcheck -x -P SCRIPTDIR "$k8s"/*.sh "$here"/*.sh 2>&1)"; then
    ok "shellcheck k8s/*.sh"
  else
    not_ok "shellcheck k8s/*.sh" "$out"
  fi
else
  not_ok "shellcheck k8s/*.sh" "shellcheck not installed"
fi

# --- versions.env -----------------------------------------------------------
# shellcheck source=../versions.env
source "$k8s/versions.env"
bad=""
for v in KIND_VERSION KIND_NODE_IMAGE KUBECTL_VERSION HELM_VERSION CMCTL_VERSION \
  CERT_MANAGER_VERSION TRAEFIK_CHART_VERSION WHOAMI_IMAGE; do
  [ -n "${!v:-}" ] || bad="$bad $v"
done
[ -z "$bad" ] && ok "versions.env sets every pin" || not_ok "versions.env sets every pin" "unset:$bad"
bad=""
for v in $(compgen -v | grep '_SHA256'); do
  [[ ${!v} =~ ^[0-9a-f]{64}$ ]] || bad="$bad $v"
done
[ -z "$bad" ] && ok "every *_SHA256 is a sha256" || not_ok "every *_SHA256 is a sha256" "bad:$bad"
[[ $KIND_NODE_IMAGE =~ ^kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}$ ]] \
  && ok "kind node image is pinned by digest" || not_ok "kind node image is pinned by digest" "$KIND_NODE_IMAGE"
[[ $WHOAMI_IMAGE =~ ^traefik/whoami:v[0-9.]+@sha256:[0-9a-f]{64}$ ]] \
  && ok "whoami image is pinned by digest" || not_ok "whoami image is pinned by digest" "$WHOAMI_IMAGE"

# --- k8s:up (dry run) -------------------------------------------------------
out="$(dry "$k8s/up.sh")" || not_ok "up.sh dry run exits 0" "$out"
contains "up creates the pinned kind cluster" "$out" \
  "kind create cluster --name cryptos-lab --image $KIND_NODE_IMAGE"
contains "up downloads the pinned kind binary" "$out" "kind/releases/download/$KIND_VERSION/kind-linux-"
contains "up checks every download's sha256" "$out" "sha256 check"
contains "up fetches the pinned cert-manager manifest" "$out" \
  "cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
contains "up fetches the pinned Traefik chart" "$out" "traefik-${TRAEFIK_CHART_VERSION}.tgz"
contains "up applies server-side" "$out" "kubectl apply --server-side"
contains "up renders whoami" "$out" "$LAB_K8S_STATE/whoami.yaml"
lacks "up never pipes a script into a shell" "$out" "| sh"
whoami_yaml="$LAB_K8S_STATE/whoami.yaml"
if [ -f "$whoami_yaml" ]; then
  grep -q "image: $WHOAMI_IMAGE" "$whoami_yaml" \
    && ok "whoami manifest uses the pinned digest" || not_ok "whoami manifest uses the pinned digest"
  grep -q "ingressClassName: traefik" "$whoami_yaml" \
    && ok "whoami Ingress uses the traefik class" || not_ok "whoami Ingress uses the traefik class"
else
  not_ok "whoami manifest rendered" "$whoami_yaml missing"
fi

# --- a throwaway CryptOS-shaped hierarchy for the issuer and chain checks ---
pki="$work/pki"
mkdir -p "$pki"
mkcert() { # name subject issuer-name ca? key-args...
  local name=$1 subj=$2 issuer=$3 ca=$4
  shift 4
  openssl req -new -newkey "$@" -nodes -keyout "$pki/$name.key" -subj "$subj" -out "$pki/$name.csr" 2>/dev/null
  if [ "$ca" = ca ]; then
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$pki/$name.ext"
  else
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:whoami.lab.example.org\n' >"$pki/$name.ext"
  fi
  if [ "$issuer" = self ]; then
    openssl x509 -req -in "$pki/$name.csr" -signkey "$pki/$name.key" -days 2 -extfile "$pki/$name.ext" -out "$pki/$name.pem" 2>/dev/null
  else
    openssl x509 -req -in "$pki/$name.csr" -CA "$pki/$issuer.pem" -CAkey "$pki/$issuer.key" -CAcreateserial \
      -days 1 -extfile "$pki/$name.ext" -out "$pki/$name.pem" 2>/dev/null
  fi
}
openssl ecparam -name secp384r1 -out "$pki/p384.param"
mkcert root "/CN=Lab Root" self ca "ec:$pki/p384.param"
mkcert int "/CN=Lab Intermediate" root ca "ec:$pki/p384.param"
mkcert leaf "/CN=whoami.lab.example.org" int leaf "ec:$pki/p384.param"
mkcert rsaleaf "/CN=whoami.lab.example.org" int leaf rsa:2048
mkcert other "/CN=Other Root" self ca "ec:$pki/p384.param"

# --- k8s:issuer (dry run) ---------------------------------------------------
acme="https://intermediate.lab.example.org/acme/directory"
host="whoami.lab.example.org"
out="$(ACME_URL=$acme CA_BUNDLE=$pki/root.pem HOST=$host dry "$k8s/issuer.sh")" \
  && ok "issuer.sh dry run exits 0" || not_ok "issuer.sh dry run exits 0" "$out"
issuer_yaml="$LAB_K8S_STATE/issuer.yaml"
if [ -f "$issuer_yaml" ]; then
  y="$(cat "$issuer_yaml")"
  contains "ClusterIssuer points at the ACME directory" "$y" "server: $acme"
  contains "ClusterIssuer trusts the CryptOS root" "$y" "caBundle: $(base64 <"$pki/root.pem" | tr -d '\n')"
  contains "http-01 goes through the traefik class" "$y" "ingressClassName: traefik"
  contains "Certificate asks for ECDSA" "$y" "algorithm: ECDSA"
  contains "Certificate asks for P-384" "$y" "size: 384"
  contains "Certificate names HOST" "$y" "- $host"
  contains "TLS Ingress serves HOST" "$y" "host: $host"
  lacks "no EAB block without a key" "$y" "externalAccountBinding"
else
  not_ok "issuer manifest rendered" "$issuer_yaml missing"
fi

hmac="c2VjcmV0LWhtYWMta2V5LWZvci10ZXN0cy1vbmx5LTEyMzQ1Ng"
out="$(ACME_URL=$acme CA_BUNDLE=$pki/root.pem HOST=$host EAB_KID=lab-kid EAB_HMAC=$hmac dry "$k8s/issuer.sh")" \
  && ok "issuer.sh with EAB dry run exits 0" || not_ok "issuer.sh with EAB dry run exits 0" "$out"
y="$(cat "$issuer_yaml")"
contains "EAB key id is set" "$y" "keyID: lab-kid"
contains "EAB secret is referenced" "$y" "name: cryptos-acme-eab"
lacks "EAB HMAC is not in the dry-run output" "$out" "$hmac"
lacks "EAB HMAC is not in the rendered issuer" "$y" "$hmac"

for bad in "ACME_URL=http://intermediate.lab.example.org/acme/directory CA_BUNDLE=$pki/root.pem HOST=$host" \
  "ACME_URL=$acme CA_BUNDLE=$work/missing.pem HOST=$host" \
  "ACME_URL=$acme CA_BUNDLE=$pki/root.key HOST=$host" \
  "ACME_URL=$acme CA_BUNDLE=$pki/root.pem HOST=not_a_host!" \
  "ACME_URL=$acme CA_BUNDLE=$pki/root.pem"; do
  # shellcheck disable=SC2086 # $bad is a list of NAME=value words
  if env $bad DRY_RUN=1 "$k8s/issuer.sh" >/dev/null 2>&1; then
    not_ok "issuer refuses: $bad"
  else
    ok "issuer refuses: ${bad//$work/<tmp>}"
  fi
done

# --- kubeconform ------------------------------------------------------------
if command -v kubeconform >/dev/null; then
  crds='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
  kc() { kubeconform -strict -summary -kubernetes-version "${KUBECTL_VERSION#v}" \
    -schema-location default -schema-location "$crds" "$@" 2>&1; }
  if out="$(kc "$whoami_yaml" "$issuer_yaml")"; then ok "kubeconform whoami + issuer"; else not_ok "kubeconform whoami + issuer" "$out"; fi
  if command -v helm >/dev/null; then
    chart="$work/traefik.tgz"
    if curl -fsSL -o "$chart" "https://traefik.github.io/charts/traefik/traefik-${TRAEFIK_CHART_VERSION}.tgz" \
      && [ "$( (sha256sum "$chart" 2>/dev/null || shasum -a 256 "$chart") | cut -d' ' -f1)" = "$TRAEFIK_CHART_SHA256" ]; then
      if rendered="$(helm template traefik "$chart" --namespace traefik --kube-version "${KUBECTL_VERSION#v}" \
        -f "$k8s/manifests/traefik-values.yaml" 2>&1)"; then
        printf '%s\n' "$rendered" >"$work/traefik.yaml"
        if out="$(kc -ignore-missing-schemas "$work/traefik.yaml")"; then ok "kubeconform traefik render"; else not_ok "kubeconform traefik render" "$out"; fi
        contains "traefik Service is a NodePort" "$rendered" "type: NodePort"
        contains "traefik web listens on the kind-mapped node port" "$rendered" "nodePort: 30080"
        contains "traefik websecure listens on the kind-mapped node port" "$rendered" "nodePort: 30443"
        contains "traefik IngressClass is named traefik" "$rendered" "name: traefik"
      else
        not_ok "helm template traefik" "$rendered"
      fi
    else
      not_ok "traefik chart download matches TRAEFIK_CHART_SHA256"
    fi
  fi
else
  not_ok "kubeconform" "kubeconform not installed"
fi

# --- served-chain checks ----------------------------------------------------
# shellcheck source=../lib.sh
source "$k8s/lib.sh"
{ echo "CONNECTED(00000003)"; echo "depth=1 CN = Lab Intermediate"; cat "$pki/leaf.pem"; echo "---"; cat "$pki/int.pem"; echo "Verify return code: 0 (ok)"; } >"$work/sclient.txt"
split_pem <"$work/sclient.txt" >"$work/served.pem"
[ "$(grep -c 'BEGIN CERTIFICATE' "$work/served.pem")" = 2 ] \
  && ok "split_pem keeps both certificates from s_client output" || not_ok "split_pem keeps both certificates from s_client output"
if out="$(check_chain "$work/served.pem" "$pki/root.pem" "$host" 2>&1)"; then ok "check_chain accepts leaf + intermediate to the root"; else not_ok "check_chain accepts leaf + intermediate to the root" "$out"; fi
cat "$pki/leaf.pem" >"$work/leafonly.pem"
check_chain "$work/leafonly.pem" "$pki/root.pem" "$host" >/dev/null 2>&1 \
  && not_ok "check_chain refuses a chain without the intermediate" || ok "check_chain refuses a chain without the intermediate"
check_chain "$work/served.pem" "$pki/other.pem" "$host" >/dev/null 2>&1 \
  && not_ok "check_chain refuses the wrong root" || ok "check_chain refuses the wrong root"
check_chain "$work/served.pem" "$pki/root.pem" "other.lab.example.org" >/dev/null 2>&1 \
  && not_ok "check_chain refuses a leaf without HOST" || ok "check_chain refuses a leaf without HOST"
cat "$pki/rsaleaf.pem" "$pki/int.pem" >"$work/rsa.pem"
check_chain "$work/rsa.pem" "$pki/root.pem" "$host" >/dev/null 2>&1 \
  && not_ok "check_chain refuses a non-P-384 leaf" || ok "check_chain refuses a non-P-384 leaf"
want="$(openssl x509 -noout -serial -in "$pki/leaf.pem" | cut -d= -f2)"
[ "$(leaf_serial "$work/served.pem")" = "$want" ] && ok "leaf_serial prints the leaf's serial" || not_ok "leaf_serial prints the leaf's serial"

# --- verify, renew, down (dry run) ------------------------------------------
out="$(HOST=$host CA_BUNDLE=$pki/root.pem dry "$k8s/verify.sh")" \
  && ok "verify.sh dry run exits 0" || not_ok "verify.sh dry run exits 0" "$out"
contains "verify waits for Ready" "$out" "kubectl -n lab-whoami wait certificate/whoami --for=condition=Ready"
contains "verify reads the served chain" "$out" "openssl s_client -connect 127.0.0.1:443 -servername $host -showcerts"
out="$(dry "$k8s/renew.sh")" && ok "renew.sh dry run exits 0" || not_ok "renew.sh dry run exits 0" "$out"
contains "renew uses cmctl" "$out" "cmctl renew -n lab-whoami whoami"
out="$(dry "$k8s/down.sh")" && ok "down.sh dry run exits 0" || not_ok "down.sh dry run exits 0" "$out"
contains "down deletes the kind cluster" "$out" "kind delete cluster --name cryptos-lab"

# --- Taskfile ---------------------------------------------------------------
if command -v task >/dev/null; then
  out="$(cd "$root" && task --list 2>&1)"
  for t in k8s:up k8s:issuer k8s:verify k8s:renew k8s:down k8s:check; do contains "Taskfile lists $t" "$out" "$t"; done
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
