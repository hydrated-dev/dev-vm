CLI to manage VMs called `vzm`.

Written in Swift and uses Apple's Virtualization (`Virtualization`) framework.

## Current Scope

`vzm` currently supports:
- headless ARM Linux guests
- bundle-based VM creation with a manifest, kernel, initrd, and rootfs
- persistent root and data disks
- commands: `create`, `run`, and `secret`
- vsock-only host/guest transport
- host-side SSH forwarding into the guest
- host-side HTTPS proxying exposed to the guest over vsock
- outbound SSH proxying exposed to the guest over vsock
- menu bar approval for proxy requests
- Keychain-backed secret substitution for HTTPS requests

`vzm` does not currently include:
- `list`, `stop`, `delete`, or other lifecycle commands
- shared folders
- a virtual network interface attached to the VM
- disk format conversion or import from non-bundle formats
- configurable proxy policy or configurable outbound SSH destinations

## Platform Requirements

`vzm` requires macOS with Apple's Virtualization framework and ARM Linux guest support.

The guest is assumed to be a preinstalled, bootable ARM Linux image with guest-side services that connect to host vsock services for SSH and proxy access.

## VM Model

All VMs are headless.

Do not attach any network interface to the VM. Attach a virtio socket device and use vsock as the only host/guest transport.

Default VM hardware:
- memory: 4 GiB
- vCPU: 2
- architecture: ARM guest only

## Bundle Model

`vzm create` takes a guest bundle directory with `manifest.json`.

The bundle manifest declares:
- schema version
- architecture
- kernel path
- initrd path
- rootfs path
- root mode
- kernel command line
- required disk roles

Only persistent root mode and a required data disk are currently supported.

## Storage Layout

Store VM state under the user's Application Support directory:

`~/Library/Application Support/vzm/vms/<name>/`

Per-VM layout:
- `config.json`
- `machine-identifier`
- `disks/root.img`
- `disks/data.img`
- `runtime/lock`
- `runtime/pid`

`config.json` includes:
- schema version
- VM name
- bundle path
- configured host SSH port
- root disk path
- data disk path and size
- root mode
- created timestamp

VM names are restricted to lowercase letters, numbers, `-`, and `_`.

## Runtime Ownership

`run` ensures only one host process owns a VM at a time.

Use a per-VM lock file plus persisted PID:
- on `run`, acquire the lock atomically
- if a lock already exists, inspect the recorded PID
- if the PID is alive and belongs to `vzm`, fail because the VM is already running
- if the PID is stale, recover the runtime state and continue

## Host/Guest Services

`vzm run` starts a `GuestServiceStack` after the VM boots and a virtio socket device is available.

The stack starts:
- an SSH bridge listening on `127.0.0.1:<host SSH port>` and forwarding to the guest SSH vsock port
- an HTTPS proxy listener on host vsock port `3128`
- a CA certificate listener on host vsock port `3129`
- an outbound SSH proxy listener on host vsock port `2223`

The VM process remains foreground and interactive. It prints lifecycle and service events until guest shutdown, guest failure, or process interruption.

On `CTRL-C` or process termination:
- attempt graceful shutdown by sending an ACPI stop request to the guest
- wait up to 30 seconds for the guest to stop
- force stop the VM if graceful shutdown does not complete

## Proxy And Approval Model

Programs in the guest must use `HTTP_PROXY` and `HTTPS_PROXY` to access the network through the HTTPS proxy. Programs that do not use host-provided vsock services should have no network access.

The HTTPS proxy:
- accepts HTTP CONNECT from the guest over vsock
- serves a local proxy CA certificate over vsock
- generates per-host leaf certificates signed by the proxy CA
- terminates guest TLS locally
- parses the first HTTP/1.1 request
- optionally substitutes `vzm:<uuid>` placeholders with Keychain-backed secrets
- applies a hard-coded initial destination/request allowlist
- prompts the user through the menu bar approval UI when policy does not allow the request
- relays approved traffic to the upstream TLS server

The outbound SSH proxy currently connects only to the hard-coded initial destination `github.com:22` and requires menu bar approval.

The menu bar UI shows pending proxy requests, supports approve/deny actions, global hotkeys, and VM stop.

## Commands

### `vzm create <name> --bundle <path> --ssh-port <port> --data-disk-size <size>`

Creates a new named VM from a guest bundle.

Behavior:
- validate VM name
- validate the bundle manifest and referenced files
- validate that `--ssh-port` is a valid TCP port
- reject creation if another VM already uses the same configured SSH port
- create the VM directory under Application Support
- clone the bundle rootfs into `disks/root.img`
- create a sparse `disks/data.img`
- persist a Virtualization machine identifier
- write `config.json`
- do not run the VM

`create` stores configuration only. It does not reserve the SSH port at the OS level.

### `vzm run <name>`

Runs a named VM in the foreground.

Behavior:
- fail if the named VM does not exist
- fail if the VM is already running according to the runtime lock/PID check
- fail if the configured SSH host port is not currently bindable on the host
- load and validate the stored guest bundle
- start the VM
- start the guest service stack
- print state and block until VM exit or process interruption

### `vzm secret create --name <display-name> [--domain <host>]...`

Reads a secret value from stdin and stores it in Keychain.

The returned UUID can be used in HTTPS request bodies or headers as `vzm:<uuid>`. If domains are specified, substitution is allowed only for matching normalized hosts.

### `vzm secret delete <uuid>`

Deletes a Keychain-backed secret by UUID.
