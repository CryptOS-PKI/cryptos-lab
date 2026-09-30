# lab 🧪

> 🔬 Tooling for testing CryptOS on real and virtual hardware. Organized by target
> environment, so new environments (bare metal, other hypervisors) can be added
> alongside without disturbing the others.

## 🌍 Environments

- 🖥️ **`esxi/`** — boot CryptOS on VMware ESXi via `govc`: upload an ISO, create a
  UEFI VM (Secure Boot off, optional vTPM), boot it, and capture the serial
  console and screenshots.
- ☸️ **`k8s/`** — a single-node [kind](https://kind.sigs.k8s.io/) cluster on the lab
  box with Traefik, cert-manager and a test app, for getting a real certificate from
  a CryptOS Intermediate over ACME.
- 🔩 **bare metal** _(planned)_ — PXE/IPMI-driven install-and-boot on physical hosts.

## ⚙️ Setup

Copy `.env.example` to `.env`, fill in your host and target settings, then
`source .env`. ⚠️ `.env` is gitignored and must never be committed — this repo is
public.

## 🚀 ESXi quick start

```
source .env
esxi/upload-iso.sh build/out/cryptos-amd64-vmware.iso
esxi/create-vm.sh
esxi/boot.sh 80          # power on, capture serial + screenshot
esxi/serial.sh           # re-read the serial log
esxi/destroy-vm.sh       # tear down
```

## ☸️ Kubernetes (ACME) quick start

Runs on the Linux lab box and needs Docker (rootful, since kind publishes ports 80
and 443) and [Task](https://taskfile.dev). Every version, image digest and checksum
is pinned in [`k8s/versions.env`](k8s/versions.env); the binaries (kind, kubectl,
helm, cmctl) are downloaded into `.tools/` and checked against those checksums. The
cluster's kubeconfig is `.state/k8s/kubeconfig`, so your own `~/.kube/config` is left
alone. The tasks read `.env` themselves (see the k8s block in `.env.example`).

```
task k8s:up                     # kind cluster, Traefik on :80/:443, cert-manager, whoami
task k8s:issuer \
  ACME_URL=https://intermediate.lab.example.org/acme/directory \
  CA_BUNDLE=root.pem HOST=whoami.lab.example.org
task k8s:verify                 # Ready, served chain verifies to the root, prints the serial
task k8s:renew                  # force a renewal and check the new serial is served
task k8s:down                   # delete the cluster
```

- 🔁 **`k8s:up` is idempotent:** a re-run applies nothing when the cluster already
  matches the pins.
- 🔐 **`k8s:issuer`** creates an ACME `ClusterIssuer` that trusts the CryptOS root
  (`caBundle`) and solves `http-01` through Traefik (`ingressClassName: traefik`),
  and a `Certificate` for `HOST` with an ECDSA P-384 key (CryptOS refuses
  cert-manager's default RSA 2048). If the node requires an External Account Binding
  (the default), set `LAB_ACME_EAB_KID` and `LAB_ACME_EAB_HMAC` in `.env`, which keeps
  the key out of shell history.
- 🌐 **Reachability:** the Intermediate fetches the challenge from
  `http://HOST:80/.well-known/acme-challenge/...`, so `HOST` must resolve to the lab
  box on the resolver the node uses, and port 80 must be reachable from the node.
- 🧪 **Dry run:** `DRY_RUN=1 task k8s:up` (or any k8s task) prints the commands
  instead of running them, on any OS. `task k8s:check` runs the offline checks:
  shellcheck, the pins, every task in dry-run mode, the manifests through
  kubeconform, and the chain checks against a throwaway CA.

`task k8s:verify` and `task k8s:renew` reuse the last `k8s:issuer` inputs. Set
`LOG_LEVEL=trace` for step-by-step logs.

## 📄 License

[Apache License 2.0](LICENSE). Copyright The CryptOS Authors.
