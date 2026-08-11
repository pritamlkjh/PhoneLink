# PhoneLink

Personal authorized remote-access system: Android ↔ VPS relay ↔ Mac.

## Project status

**Planning / architecture phase.** No application implementation has been completed yet.

The authoritative planning artifacts are:

- `PhoneLink_Development_DAG.md` — 49-node development specification
- `project_graph.json` — machine-readable DAG and node state
- Linear — project/task tracking for the 49 DAG issues

## Components

- Android client
- VPS relay
- Mac client
- Shared protocol/schema
- Integration and security testing
- Release and documentation

## Development rule

PhoneLink is developed one DAG node at a time. A node is not considered complete until its dependencies, implementation, node tests, regression tests, and acceptance criteria have all been verified.

The VPS is designed as a low-trust relay; the project architecture requires end-to-end protection of private payloads and must respect Android/macOS security and privacy restrictions.

## Current state

- DAG: defined
- Linear project: connected
- GitHub repository: created
- Application code: not yet implemented
- Current root node: `REQ-1`
