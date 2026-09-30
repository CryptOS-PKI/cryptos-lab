# lab 🧪

> 🔬 Tooling for testing CryptOS on real and virtual hardware. Organized by target
> environment, so new environments (bare metal, other hypervisors) can be added
> alongside without disturbing the others.

## 🌍 Environments

- 🖥️ **`esxi/`** — boot CryptOS on VMware ESXi via `govc`: upload an ISO, create a
  UEFI VM (Secure Boot off, optional vTPM), boot it, and capture the serial
  console and screenshots.
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

## 📄 License

[Apache License 2.0](LICENSE). Copyright 2026 Shane.
