# ADR 0001 — Controlled-beta production stack

- **Status:** Accepted for implementation foundation; deployment pending.
- **Date:** 25 November 2026.
- **Decision owner:** GomoGie project owner.

## Context
The current product is a static GitHub Pages prototype. Production requires persistent identity, social data, media storage and a server-side security boundary. The owner selected a RM0 operating target for a limited beta, while accepting transparent fair-use caps.

## Decision
Use a Node.js 22/Fastify modular monolith, PostgreSQL 17, Cloudflare R2 Standard for media objects, Docker Compose on an eligible Oracle Cloud Always Free Ampere A1 VM, and Cloudflare Tunnel for ingress. Keep GitHub Pages for the existing prototype until the client is deliberately integrated with the API.

## Alternatives considered
- **GitHub Pages only:** rejected for production because it cannot host a persistent API or relational database.
- **Supabase Free as primary database:** not selected for the first deployment because free project/database/storage and inactivity constraints do not match the always-on social backend target.
- **Cloudflare Workers as the full application backend:** not selected for the first implementation because request CPU/runtime constraints and database/media workflows need more control.
- **Cloudflare Stream:** not selected for RM0 phase because storage and delivery are usage-priced.
- **Microservices/Kubernetes:** rejected as premature operational overhead for a solo-maintained beta.

## Consequences
- A single VM is a single point of failure and has limited CPU.
- Free capacity is conditional and can change; no uptime or capacity guarantee is implied.
- R2 free storage/operation quotas require hard caps and monitoring.
- Video processing must be queued and constrained; live streaming is out of scope.
- Email verification, account recovery, media scanning, moderation, backup restore testing and frontend integration are mandatory before public launch.
- Provisioning and any paid resource use require explicit owner action.
