# Yama Detector Implementation Guide

## Goal

This document bridges the attack-pattern catalog and the actual backend implementation.

It exists so detector development does not collapse into ad hoc rules.

## Detector Build Order

Implement detectors in this order:

### Tier 1

- DCSync
- DCShadow
- Kerberoasting
- AS-REP roasting
- NTLM relay
- Pass-the-Hash
- Shadow credentials
- RBCD
- AdminSDHolder abuse
- GPO abuse
- AD CS ESC1
- AD CS ESC4
- AD CS ESC8
- AD CS ESC14
- NoPac
- Certifried
- MachineAccountQuota abuse

### Tier 2

- Golden Ticket
- Silver Ticket
- Diamond Ticket
- Bronze Bit
- constrained delegation abuse
- unconstrained delegation abuse
- ForceChangePassword
- SPN-jacking
- SIDHistory injection
- LAPS / gMSA secret abuse
- coercion families

### Tier 3

- forest and trust abuse
- SCCM / WSUS / Exchange-adjacent abuse
- destructive campaigns
- anomaly-only detections

## Detector Shape

Each detector should implement:

- event matcher
- precondition evaluator
- evidence collector
- confidence scorer
- suggested response mapper

## Confidence Pattern

Use:

- source legitimacy
- target criticality
- rarity
- prerequisite exploitability
- attack chain completeness
- time correlation

Do not use only event count.

## Evidence Pattern

Each detector should store:

- source events
- touched objects
- before/after attributes where available
- actor and source host
- protocol path
- detector reasoning notes

## Response Pattern

Each detector should define:

- allowed response types
- required confidence
- approval requirement
- rollback expectations

Example:

- DCSync
  - alert: yes
  - disable account: yes
  - revert ACL: yes
  - auto mode: only if confidence is critical-confirmed and actor is not protected

## Demo Positioning

For demos, show the stack in this progression:

1. assessment knows the exposed path
2. signal ingestion sees the behavior
3. detector identifies the attack technique
4. correlation turns it into an incident
5. response orchestrator selects a safe action
6. evidence ledger preserves forensic material

This is the clean story for the product.
