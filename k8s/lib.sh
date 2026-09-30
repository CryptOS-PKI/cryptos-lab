# shellcheck shell=bash
# Shared helpers for the k8s/ tasks. Sourced, never run. Written for bash 3.2
# as well, so the dry run works with the bash macOS ships.
set -euo pipefail

K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$K8S_DIR/.." && pwd)"

LAB_ENV_FILE="${LAB_ENV_FILE:-$LAB_ROOT/.env}"
if [ -r "$LAB_ENV_FILE" ]; then
  # shellcheck source=/dev/null
  source "$LAB_ENV_FILE"
fi
# shellcheck source=versions.env
source "$K8S_DIR/versions.env"

: "${LAB_K8S_CLUSTER:=cryptos-lab}"
: "${LAB_K8S_NAMESPACE:=lab-whoami}"
: "${LAB_K8S_ADDR:=127.0.0.1}"
: "${LAB_K8S_WAIT_SECONDS:=300}"
: "${LAB_K8S_STATE:=$LAB_ROOT/.state/k8s}"
: "${LAB_TOOLS_DIR:=$LAB_ROOT/.tools}"
: "${LOG_LEVEL:=info}"
# shellcheck disable=SC2034 # read by the scripts and by render
LAB_ACME_ISSUER=cryptos-acme
LAB_FIELD_MANAGER=cryptos-lab

export KUBECONFIG="$LAB_K8S_STATE/kubeconfig"
export PATH="$LAB_TOOLS_DIR/bin:$PATH"
mkdir -p "$LAB_K8S_STATE"

# --- logging ----------------------------------------------------------------

level_num() {
  case "$1" in
    trace) echo 0 ;; debug) echo 1 ;; info) echo 2 ;; warn) echo 3 ;; error) echo 4 ;; *) echo 2 ;;
  esac
}
log() {
  local lvl=$1
  shift
  [ "$(level_num "$lvl")" -ge "$(level_num "$LOG_LEVEL")" ] || return 0
  printf '%s %-5s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$lvl" "${LAB_STEP:-k8s}" "$*" >&2
}
die() {
  log error "$*"
  exit 1
}
step() { log info "== $*"; }

dry_run() { [ "${DRY_RUN:-}" = 1 ]; }

# run prints the command instead of running it in dry-run mode. Arguments must
# never carry secrets: they are logged.
run() {
  if dry_run; then
    printf '+ %s\n' "$*"
    return 0
  fi
  log debug "run: $*"
  local start=$SECONDS rc=0
  "$@" || rc=$?
  log trace "exit $rc after $((SECONDS - start))s: $1"
  return "$rc"
}

# run_to FILE CMD... runs CMD with stdout into FILE.
run_to() {
  local out=$1
  shift
  if dry_run; then
    printf '+ %s > %s\n' "$*" "$out"
    return 0
  fi
  log debug "run: $* > $out"
  "$@" >"$out"
}

need() {
  command -v "$1" >/dev/null || die "$1 not found on PATH${2:+ ($2)}"
}

# --- platform and downloads -------------------------------------------------

detect_arch() {
  local os machine
  os="$(uname -s)"
  machine="$(uname -m)"
  if [ "$os" != Linux ]; then
    dry_run || die "the k8s tasks run on Linux (the lab box); this is $os. DRY_RUN=1 prints the commands anywhere."
    log info "dry run on $os: showing the linux-amd64 downloads"
    echo amd64
    return
  fi
  case "$machine" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "no pinned binaries for $machine" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# pinned NAME prints the arch-specific pin NAME_<arch> from versions.env.
pinned() {
  local var="$1_$LAB_ARCH"
  [ -n "${!var:-}" ] || die "versions.env has no $var"
  echo "${!var}"
}

# fetch_verified URL SHA256 DEST downloads URL to DEST unless DEST already
# holds the pinned bytes, and refuses anything whose sha256 differs.
fetch_verified() {
  local url=$1 want=$2 dest=$3
  mkdir -p "$(dirname "$dest")"
  if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$want" ]; then
    log debug "cached and verified: $dest"
    return 0
  fi
  log info "download $url"
  run curl -fsSL --retry 3 -o "$dest.part" "$url"
  log info "sha256 check $(basename "$dest"): want $want"
  dry_run && return 0
  local got
  got="$(sha256_of "$dest.part")"
  if [ "$got" != "$want" ]; then
    rm -f "$dest.part"
    die "checksum mismatch for $url: got $got, want $want"
  fi
  mv "$dest.part" "$dest"
  log debug "verified $dest"
}

# ensure_tool NAME URL SHA256 [MEMBER] installs a pinned binary into
# $LAB_TOOLS_DIR/bin. MEMBER is the binary's path inside a tarball.
ensure_tool() {
  local name=$1 url=$2 want=$3 member=${4:-}
  local bin="$LAB_TOOLS_DIR/bin/$name" stamp="$LAB_TOOLS_DIR/bin/.$name.sha256"
  if [ -x "$bin" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$want" ]; then
    log debug "$name already installed at the pinned version"
    return 0
  fi
  local cache
  cache="$LAB_TOOLS_DIR/cache/$(basename "$url")"
  fetch_verified "$url" "$want" "$cache"
  run mkdir -p "$LAB_TOOLS_DIR/bin"
  if [ -n "$member" ]; then
    local tmp="$LAB_TOOLS_DIR/cache/$name.extract"
    run mkdir -p "$tmp"
    run tar -xf "$cache" -C "$tmp" "$member"
    run install -m 0755 "$tmp/$member" "$bin"
    run rm -rf "$tmp"
  else
    run install -m 0755 "$cache" "$bin"
  fi
  dry_run || printf '%s\n' "$want" >"$stamp"
  log info "installed $name -> $bin"
}

ensure_cluster_tools() {
  ensure_tool kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-$LAB_ARCH" \
    "$(pinned KIND_SHA256)"
  ensure_tool kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$LAB_ARCH/kubectl" \
    "$(pinned KUBECTL_SHA256)"
  ensure_tool helm "https://get.helm.sh/helm-$HELM_VERSION-linux-$LAB_ARCH.tar.gz" \
    "$(pinned HELM_SHA256)" "linux-$LAB_ARCH/helm"
  ensure_tool cmctl "https://github.com/cert-manager/cmctl/releases/download/$CMCTL_VERSION/cmctl_linux_$LAB_ARCH" \
    "$(pinned CMCTL_SHA256)"
}

# --- manifests --------------------------------------------------------------

# render TEMPLATE DEST replaces each ${NAME} in TEMPLATE with the value of the
# shell variable NAME, and fails on any that is unset.
render() {
  local src=$1 dest=$2 content name tokens pat val out
  content="$(cat "$src")"
  # shellcheck disable=SC2016 # the pattern matches a literal ${NAME}
  tokens="$(grep -o '\${[A-Z0-9_]*}' "$src" | sort -u | sed 's/^\${//; s/}$//')" || true
  for name in $tokens; do
    [ -n "${!name+x}" ] || die "render $(basename "$src"): \${$name} is not set"
    # Prefix/suffix splitting rather than ${var//pat/rep}: the replacement's
    # quoting and '&' handling differ between bash 3.2 and 5.2.
    pat="\${$name}"
    val="${!name}"
    out=""
    while case "$content" in *"$pat"*) true ;; *) false ;; esac do
      out="$out${content%%"$pat"*}$val"
      content="${content#*"$pat"}"
    done
    content="$out$content"
  done
  printf '%s\n' "$content" >"$dest"
  log debug "rendered $(basename "$src") -> $dest"
}

# apply_manifest FILE WHAT applies FILE server-side, and only when the server
# reports a difference, so a re-run leaves the cluster as it was.
apply_manifest() {
  local file=$1 what=$2
  local apply=(kubectl apply --server-side --force-conflicts --field-manager="$LAB_FIELD_MANAGER" -f "$file")
  if dry_run; then
    run "${apply[@]}"
    return 0
  fi
  local rc=0 diffout="$LAB_K8S_STATE/last.diff"
  kubectl diff --server-side --force-conflicts --field-manager="$LAB_FIELD_MANAGER" -f "$file" >"$diffout" 2>&1 || rc=$?
  case "$rc" in
    0)
      log info "$what: up to date, nothing to apply"
      return 0
      ;;
    1)
      log info "$what: applying changes"
      log trace "$what diff: $(cat "$diffout")"
      ;;
    *)
      # A diff can't be computed before its namespace or CRD exists; apply
      # then reports any real error itself.
      log warn "$what: no diff available ($(tail -n 1 "$diffout")); applying"
      ;;
  esac
  run "${apply[@]}"
}

cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$LAB_K8S_CLUSTER"
}

rollout() { # NAMESPACE DEPLOYMENT...
  local ns=$1 d
  shift
  for d in "$@"; do
    run kubectl -n "$ns" rollout status "deployment/$d" --timeout="${LAB_K8S_WAIT_SECONDS}s"
  done
}

# --- issuer inputs ----------------------------------------------------------

# load_issuer_inputs fills ACME_URL, CA_BUNDLE and HOST from, in order: the
# task arguments, what the last k8s:issuer run saved, and .env.
load_issuer_inputs() {
  local saved="$LAB_K8S_STATE/issuer.env" SAVED_ACME_URL="" SAVED_CA_BUNDLE="" SAVED_HOST=""
  if [ -f "$saved" ]; then
    # shellcheck source=/dev/null
    source "$saved"
    log debug "loaded saved issuer inputs from $saved"
  fi
  ACME_URL="${ACME_URL:-${SAVED_ACME_URL:-${LAB_ACME_URL:-}}}"
  CA_BUNDLE="${CA_BUNDLE:-${SAVED_CA_BUNDLE:-${LAB_CA_BUNDLE:-}}}"
  HOST="${HOST:-${SAVED_HOST:-${LAB_K8S_HOST:-}}}"
}

save_issuer_inputs() {
  dry_run && return 0
  printf 'SAVED_ACME_URL=%q\nSAVED_CA_BUNDLE=%q\nSAVED_HOST=%q\n' "$ACME_URL" "$CA_BUNDLE" "$HOST" \
    >"$LAB_K8S_STATE/issuer.env"
  log debug "saved issuer inputs to $LAB_K8S_STATE/issuer.env"
}

valid_host() {
  [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

# --- certificate checks -----------------------------------------------------

# split_pem keeps only the PEM certificates from s_client output on stdin.
split_pem() {
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}'
}

leaf_serial() {
  openssl x509 -noout -serial -in "$1" | cut -d= -f2
}

# check_chain SERVED ROOT HOST checks that the first certificate in SERVED is a
# P-384 server certificate for HOST that verifies to ROOT through the rest of
# SERVED. It returns non-zero instead of exiting, so callers can retry.
check_chain() {
  local served=$1 root=$2 host=$3 tmp rc=0 n
  n="$(grep -c 'BEGIN CERTIFICATE' "$served" || true)"
  if [ "$n" -lt 1 ]; then
    log error "no certificate in $served"
    return 1
  fi
  tmp="$(mktemp -d)"
  awk -v dir="$tmp" '/-----BEGIN CERTIFICATE-----/{i++} {f = (i == 1) ? dir "/leaf.pem" : dir "/rest.pem"; print > f}' "$served"
  log info "served chain: $n certificate(s)"
  local verify=(openssl verify -purpose sslserver -CAfile "$root")
  [ -s "$tmp/rest.pem" ] && verify+=(-untrusted "$tmp/rest.pem")
  local out
  if out="$("${verify[@]}" "$tmp/leaf.pem" 2>&1)" && printf '%s' "$out" | grep -q ': OK'; then
    log info "chain verifies to $(openssl x509 -noout -subject -in "$root")"
  else
    log error "chain does not verify to $root: $(printf '%s' "$out" | tr '\n' ' ')"
    rc=1
  fi
  local text
  text="$(openssl x509 -noout -text -in "$tmp/leaf.pem")"
  if printf '%s\n' "$text" | awk '/Subject Alternative Name/{getline; print}' | tr ',' '\n' | sed 's/^ *//' | grep -qx "DNS:$host"; then
    log info "leaf names $host"
  else
    log error "leaf has no DNS SAN $host"
    rc=1
  fi
  if printf '%s\n' "$text" | grep -qE 'ASN1 OID: secp384r1|NIST CURVE: P-384'; then
    log info "leaf key is ECDSA P-384"
  else
    log error "leaf key is not ECDSA P-384"
    rc=1
  fi
  rm -rf "$tmp"
  return "$rc"
}

describe_leaf() {
  openssl x509 -noout -serial -subject -issuer -enddate -in "$1"
}
