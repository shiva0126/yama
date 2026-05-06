# Real AD Infrastructure Lab

This document captures the real VirtualBox-based AD lab substrate used for Yama development and defense testing.

## Current VM Set

- `LAB-DC01`
  - Windows Server 2022
  - Root forest / primary controller candidate
  - Internal network: `ad-lab-net`
  - NAT on adapter 2 for update access and host admin access
- `LAB-CHILDDC`
  - Clone of `LAB-DC01`
  - Intended child-domain controller / additional server
  - Internal network: `ad-lab-net`
  - Unique NAT forwards
- `LAB-SRV01`
  - Clone of `LAB-DC01`
  - Intended member server
  - Internal network: `ad-lab-net`
  - Unique NAT forwards
- `DC01-shivasecurity`
  - Windows Server 2022
  - Existing assessment-side DC/infra VM
  - Already attached to `ad-lab-net`
- `Win10-VictimClient`
  - Windows 10 victim workstation
  - Already attached to `ad-lab-net`
- `Kali-AttackClient`
  - Attack workstation
  - Already attached to `ad-lab-net`

## Network Topology

The lab uses one internal VirtualBox network:

- `ad-lab-net`

Every Windows host in the lab should have:

- adapter 1: `intnet` on `ad-lab-net`
- adapter 2: `nat` for internet access and admin port forwarding

Current host port forwards:

- `LAB-DC01`
  - RDP: `53389 -> 3389`
  - WinRM: `5985 -> 5985`
- `LAB-CHILDDC`
  - RDP: `53390 -> 3389`
  - WinRM: `5986 -> 5985`
- `LAB-SRV01`
  - RDP: `53391 -> 3389`
  - WinRM: `5987 -> 5985`

## Intended Forest Layout

Use the lab as a realistic AD environment with:

- root forest: `corp.yama.lab`
- child domain: `sec.corp.yama.lab`
- member server: `srv01.corp.yama.lab`
- workstation: `win10-01.corp.yama.lab`
- attacker host: `kali.yama.lab` or unmanaged Kali

This gives the platform a real multi-domain shape for:

- trust abuse
- child-to-root escalation
- GPO abuse
- AD CS abuse
- delegation abuse
- replication abuse
- domain controller defense logic

## Guest-Side Setup Required

VirtualBox cloning only creates the VM substrate. The actual forest promotion still has to happen inside the guests.

Recommended order:

1. Boot `LAB-DC01`
2. Set a static IP on `ad-lab-net`
3. Install AD DS and DNS
4. Create the root forest
5. Boot `LAB-CHILDDC`
6. Set a static IP and point DNS at the root DC
7. Promote it as a child domain controller
8. Boot `LAB-SRV01`
9. Join it to the root domain
10. Boot `Win10-VictimClient`
11. Join it to the root or child domain
12. Keep `Kali-AttackClient` off-domain

## Suggested IP Plan

- `LAB-DC01` - `10.10.10.10`
- `LAB-CHILDDC` - `10.10.10.11`
- `LAB-SRV01` - `10.10.10.20`
- `Win10-VictimClient` - `10.10.10.30`
- `Kali-AttackClient` - `10.10.10.40`

## What This Enables

Once the guests are promoted and joined, the lab can exercise:

- full assessment collection from a real forest
- child domain trust paths
- domain controller and member server inventory
- AD CS exposure
- replication and privilege abuse detection
- defense-plane incident simulation

## Notes

- The current root VM and clones are created at the host layer.
- Guest promotion and domain joins still need to be completed inside Windows.
- Keep the internal network name stable: `ad-lab-net`.
