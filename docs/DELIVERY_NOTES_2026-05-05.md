# Delivery Notes — 2026-05-05

## Scope of This Delivery

This delivery covered two major areas:

1. Frontend shell cleanup
2. Defense-engine backend architecture and detector planning documents

## Why This Was Built

The product direction was clarified during this session:

- Yama should not remain only an AD assessment platform
- Yama should become a full Active Directory defense stack
- the defense model should be attack-technique driven
- it should not behave like a noisy, old-school log-watching SIEM
- the backend architecture must be designed first for production use

The UI work was done to make the existing operator console look less like a demo and more like a security product.

The architecture work was done to define the future backend required to detect, correlate, and stop the full AD attack surface in production.

## What Was Built

### Frontend

The frontend shell was reworked to improve operator usability and visual consistency.

Main changes:

- icon-first collapsible sidebar
- cleaner top header/control bar
- reduced marketing/demo-style descriptive text
- tighter alignment between navigation and content
- Docker rebuild and redeploy of the frontend container after UI changes

Main frontend files changed:

- `frontend/src/components/layout/Layout.tsx`
- `frontend/src/components/layout/Sidebar.tsx`
- `frontend/src/components/layout/Header.tsx`
- `frontend/src/index.css`

Additional page-level simplification was also applied across:

- dashboard
- scanner
- findings
- inventory
- topology
- reports
- login

### Architecture Documents

The following planning documents were added:

- `docs/AGENT_BUILDING.md`
- `docs/DEFENSE_ENGINE_ARCHITECTURE.md`
- `docs/ATTACK_PATTERN_CATALOG.md`

These documents define:

- the intended product split between assessment and defense
- the defense-engine backend service model
- normalized attack coverage
- detector families
- signal requirements
- response model
- production safety controls
- backend-first implementation priorities

## Attack Coverage Direction

The defense-engine planning now assumes broad known Active Directory attack coverage across families including:

- credential dumping and extraction
- Kerberos abuse
- NTLM/authentication abuse
- replication/DC abuse
- AD CS abuse
- ACL/object control abuse
- persistence
- lateral movement
- trust/forest abuse
- GPO abuse
- coercion
- reconnaissance
- defense evasion
- destructive operations
- AD-adjacent control-plane abuse

## Errors / Issues Faced

### 1. Local git metadata missing

Problem:

- `/home/shetty/yama-main` was not a local git repository
- `/home/shetty/.git` existed but was empty and unusable

Resolution:

- verified GitHub repo `shiva0126/yama` exists
- cloned the remote repository to a temp path
- synced the local worktree into the clone
- prepared the clone for proper git review/commit/push flow

### 2. PowerShell quoting friction earlier during Windows-side repair work

Problem:

- some PowerShell invocations from WSL had quoting/parser issues

Resolution:

- reran commands with simplified PowerShell literals
- moved complex steps into dedicated script files where needed

### 3. Docker rebuild ordering

Problem:

- `frontend` restart command sometimes executed before the new image finished building

Resolution:

- waited for the image export to complete
- recreated `ad_frontend` after the image was built

### 4. UI inconsistency across pages

Problem:

- shell and pages mixed dark-theme assumptions with light panels
- excess explanatory text made the interface feel like a demo

Resolution:

- normalized shell spacing and panel behavior
- reduced marketing-style copy
- refactored sidebar/header structure

## What Still Remains

This delivery did not implement the defense backend itself yet.

Still to build:

- signal ingestion service
- normalization pipeline
- detector engine
- correlation engine
- response orchestrator
- evidence ledger
- policy engine
- operator defense APIs

The architecture is now documented and ready for backend implementation.

## Notes on Code Comments

This delivery mainly added and updated architecture documentation and UI code.

No attempt was made to add blanket comments across the entire existing codebase, because doing that mechanically across unrelated modules would add noise rather than clarity.

Future backend implementation should include focused comments only where:

- detector logic is non-obvious
- response safety logic needs explanation
- correlation rules are complex
- rollback semantics need to be explicit

## Recommended Next Step

The next engineering step should be:

1. define the normalized detector catalog as machine-readable data
2. define database schema for the defense plane
3. scaffold backend services for:
   - signal ingestion
   - normalization
   - detector execution
   - correlation
   - response
   - evidence

This is the correct path to productionizing the defense stack.
