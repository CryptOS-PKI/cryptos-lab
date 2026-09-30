# lab 🧪

> 🔬 Tooling for testing CryptOS on real and virtual hardware. Organized by target
> environment, so new environments (bare metal, other hypervisors) can be added
> alongside without disturbing the others.

> [!WARNING]
> 🚧 **Pre-1.0: any release can change fundamentally.** CryptOS is pre-1.0. Until v1.0.0, any release may change configuration, APIs, on-disk and state formats, trust setup, and upgrade paths, sometimes with no migration path. If you run it in production, you accept that risk. Read [each release's upgrade notes](https://github.com/CryptOS-PKI/cryptos/releases) before you upgrade.

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

🛑 **Lab only:** this tooling targets a lab ESXi host; never point it at production CryptOS nodes.

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

## 🔏 Fleet Manager operator CA

The lab Fleet Manager's operator CA is an external OpenSSL CA, never a CryptOS
node. `operator-ca/` builds it the way the manager docs describe: ECDSA P-384,
`pathlen:0`, KU `keyCertSign, cRLSign`, one `openssl ca` extension section per
level (`op_admin`, `op_operator`, `op_viewer`) with the level extension
`1.3.6.1.4.1.59999.1.1` marked **non-critical** (Go's verifier refuses a client
cert with an unhandled critical extension), an `authorityInfoAccess` OCSP URI, a
CRL valid for 7 days, and a delegated OCSP signer (EKU OCSPSigning, `noCheck`,
30 days) so the responder never needs the CA key.

The CA lives in `.state/operator-ca/` (mode 700, gitignored); set
`LAB_OPCA_DIR` to keep it elsewhere. `task k8s:down` doesn't touch it.

> [!CAUTION]
> `operator-ca.key` is the key every Fleet Manager admin credential hangs off.
> Keep it on the lab box only: never copy it into the cluster, a ticket or this
> repo. The publish step ships only the OCSP signer key.

```
task opca:init                                   # CA, OCSP signer, first CRL; prints the CA SHA-256
LAB_OPCA_P12_PASS_FILE=~/admin.pass \
  task opca:issue LEVEL=admin EMAIL=admin@example.org   # key, cert, checks, PKCS#12
task opca:publish                                # CA ConfigMap, CRL ConfigMap, OCSP responder in kind
task opca:revoke CERT=.state/operator-ca/issued/<email>/<email>.crt
task opca:publish                                # after every revoke, CRL or signer renewal
task opca:crl                                    # a new CRL before the 7 days run out
task opca:ocsp-signer                            # a new signer before its 30 days run out
task opca:check                                  # offline checks, no cluster needed
```

- 🔑 **PKCS#12 passphrase:** 18 bytes or more, from `LAB_OPCA_P12_PASS_FILE`
  (first line) or `LAB_OPCA_P12_PASS`. It never goes on the command line or into a
  log. `issue` lower-cases the email, and refuses a cert that fails the Fleet
  Manager's checks (level extension present, non-critical and exact, EKU exactly
  clientAuth, KU digitalSignature, CA:FALSE).
- 🛰️ **OCSP responder:** `openssl ocsp` in the `operator-ocsp` Deployment
  (namespace `LAB_FM_NAMESPACE`, default `fleet`), image pinned in
  `k8s/versions.env`, answering at `http://operator-ocsp.fleet.svc.cluster.local/`
  (the default `LAB_OPCA_OCSP_URL`, which `init` writes into every leaf's AIA).
  Its copy of `index.txt` comes from a Secret, so `opca:publish` updates the
  Secret and restarts the responder whenever the index, CRL or signer changes.
  Responses carry a 60-minute nextUpdate. The probes send a real OCSP request,
  because a bare TCP connect wedges `openssl ocsp`. From the lab box:

  ```
  kubectl -n fleet port-forward svc/operator-ocsp 8080:80 &
  openssl ocsp -issuer .state/operator-ca/operator-ca.crt -cert <cert> \
    -url http://127.0.0.1:8080 -CAfile .state/operator-ca/operator-ca.crt -resp_text
  ```

> [!WARNING]
> `openssl ocsp` is a lab-grade responder: single-threaded, no TLS, no caching
> and no high availability. Don't use it outside the lab.

- ⚙️ **Fleet Manager values** (`chart/fleet-manager`): trust the CA through the
  file source and drop `operatorCANode`:

  ```yaml
  operatorCA: {configMap: fm-operator-ca}   # written by task opca:publish
  # operatorCANode: removed; a CryptOS node is never the operator CA
  mcp: {enabled: false}                     # see below
  ```

  Until the manager can take a CRL (`operatorCRL`) and OCSP settings, it has no
  operator revocation source without `operatorCANode`: the CRL and responder are
  published for that, and MCP stays off, because the manager refuses MCP without
  a revocation source. The CRL is in the `fm-operator-crl` ConfigMap, key
  `operator.crl.pem`.

## 📄 License

[Apache License 2.0](LICENSE). Copyright The CryptOS Authors.
