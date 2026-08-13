# AGENTS.md

## Project-Specific Orchestration

The primary agent is the project orchestrator. It owns task understanding,
architecture, decomposition, delegation, integration, review, and final
verification.

Use subagents aggressively for substantial implementation work. Subagents may
implement scoped tasks, investigate isolated problems, modify files, run tests,
and report findings. The primary agent must review subagent work before
continuing and must run final verification against the integrated tree.

## Project Context

This repository contains the Abyssal application and its supporting services.
Keep project-specific architecture and operational facts in `agent_docs/` as
they become verified.

## Core Design Principles

Follow SOLID principles. Keep responsibilities narrow, dependencies explicit,
interfaces cohesive, and implementations replaceable without unrelated changes.

Before committing or pushing any change, run the complete applicable unit-test
suite and every applicable security gate against the final integrated tree. Do
not commit or push while any required test or security check is failing,
skipped, stale, or unverified.

Frontend work is not exempt from these rules. Android and web changes must keep
the same modularity, unit-test coverage, and applicable security gates as
backend changes.

The project must strictly follow modular design.

Each module should have:

- A clear responsibility.
- A clear interface.
- Minimal unnecessary coupling.
- A structure that makes it easy to test, debug, replace, extend, and reuse.

Nested modules are allowed when they make responsibilities clearer. Avoid
placing unrelated responsibilities into the same file, class, service, or
large function.

- Define proportionate acceptance and verification requirements before implementation.
- Keep related tests cohesive enough to avoid fragmented micro-tests, but never reduce meaningful coverage, weaken assertions, or hide failures merely to save tokens or execution time.

## Tool Execution and Batching

For each bounded work stage, identify independent, already-known,
non-conflicting tool calls before invoking tools. When practical, execute them
through one outer `functions.exec` or Code Mode `exec` call.

Use `Promise.allSettled()` when successful results remain useful even if another
call fails. Inspect and attribute every returned result. Use `Promise.all()` only
when any individual failure invalidates the entire batch.

Prefer batching for:

- Read-only file inspection.
- Independent symbol, text, and call-site searches.
- Repository metadata and status collection.
- Independent log or artifact inspection.
- Validation commands that do not share mutable state.

Keep operations sequential when they involve:

- A result that determines the next operation.
- Adaptive investigation where the next target is not yet known.
- Approvals or permission boundaries.
- Agent spawn, wait, resume, or replacement operations.
- Overlapping or order-sensitive writes.
- Git staging, commits, resets, or other Git-state mutations.
- Builds or tests sharing a build directory, generated output, database, port, fixture, device, or other mutable resource.

Do not split an otherwise batchable inspection across repeated outer tool calls.
Do not create extra work, broaden scope, obscure failure attribution, or
increase worker count merely to fill a batch.

Tool-call concurrency is local to one agent thread. It does not change route
selection, worker ownership, verification requirements, or subagent-concurrency
limits. A stage requiring only one useful tool call should remain one call.

## Working State

At any given time, we will be in one of two working states:

- `deployment state`: beginning to plan a broad task or in the process of deploying a plan. A deployment plan can span multiple sessions.
- `leaf state`: tasks outside the plan being deployed by the `deployment state`, such as general queries, document editing, or small file/module/tool changes.

## Project Documentation Framework

The main project documents are stored under `agent_docs/`:

- `agent_docs/project_overview.md`: goals, architecture, workflow, and major decisions.
- `agent_docs/project_core_tech.md`: a brief summary of special technologies or architectures.
- `agent_docs/project_structure.md`: directory layout, modules, components, and ownership boundaries.
- `agent_docs/project_progress.md`: active implementation plan and cross-session execution status.
- `agent_docs/project_diary.md`: durable architecture decisions, discarded approaches, and lessons.
- `agent_docs/latest_session_work.md`: summary of previous sessions along with unfinished tasks.
- Module-specific documents, when present.

`agent_docs/project_progress.md` and `agent_docs/latest_session_work.md` are
designed for smooth handoff between sessions in deployment mode. They may only
be edited in `deployment state` or when the user explicitly requests it. The
primary agent is responsible for updating them; subagents must not edit them.

Update documentation only with verified facts. Keep temporary reasoning, raw
logs, and short-lived checkpoints out of durable project documents.

Never delete any main project document without warning the user and receiving a
second explicit confirmation.

## Route Selection

There are three routes.

### Light route

Use for light tasks in `leaf state`. Perform tasks by yourself and do not spawn
subagents for this route.

### Medium route

Use for deploying large tasks or plans in `deployment state`. Perform
implementation, verification, and documentation by yourself. The deployment
session's persistent `explorer` companion is the only exception and is not
counted as a subagent. Read and follow `agent_docs/workflow/medium_route.md`.

### Heavy route

Use for deploying large tasks or plans in `deployment state` while coordinating
subagents. Reuse the deployment session's persistent `explorer` companion for
bounded supplementary context and concise findings. It is not counted as a
worker subagent. Read and follow `agent_docs/workflow/heavy_route.md`.

The project-specific orchestration rules above remain authoritative: for
substantial implementation work, the primary agent should delegate scoped work
and review it before integration.

### Route selection rules and state interpolation

The route may be specified by the user, such as "use Light/medium/heavy route".
Apply that route throughout the session until the user switches it. If no route
is specified, use the light route for ordinary leaf work and use the project
orchestration rule above when the task is substantial enough to require
delegation. Do not silently change routes mid-session.

If the light route is selected, it means `leaf state`. If the medium or heavy
route is selected, proceed in `deployment state`.

## Context Loading

- In the Light route (`leaf state`), read only files relevant to the current task.
- On first entering `deployment state`, initialize exactly one session-long `explorer` companion. Reuse the same thread for later bounded context investigation, including across Medium/Heavy route changes within the session. Replace it only when the applicable lifecycle rules require it. The explorer is read-only and excluded from worker/subagent counts.
- An explorer assignment defines the investigation focus, not a hard reading boundary. The explorer may follow directly related files, symbols, call sites, documentation, and dependencies when needed while avoiding unrelated repository-wide exploration.
- Load foundational project context in one bounded read-only batch:
  1. `agent_docs/project_overview.md`
  2. `agent_docs/project_structure.md`
  3. `agent_docs/project_progress.md`
  4. `agent_docs/latest_session_work.md`
- Interpret overview and structure before reconciling progress and latest-session handoff. This interpretation order does not require separate outer tool calls.
- Use the resulting status and ownership map to inspect the smallest relevant interfaces, call sites, tests, and configuration surface.
- Read only relevant module documentation. Expand source inspection only when repository evidence requires it.
- Reconstruct active tasks, dependencies, verification state, and blockers. Resolve contradictions with targeted evidence.
- Under the Heavy route, review only critical hunks and integration boundaries after delegation unless risk, missing evidence, or conflicting results require broader inspection.
- In final agent-usage statistics for a deployment session, include the explorer's call count and label it as a `companion`, even though it is excluded from worker/subagent counts.

## Platform-Specific Paths

Paths in this workflow are written using `/` as a platform-neutral separator.
When running filesystem operations, adapt paths to the current environment.

- On Linux and macOS, use `/`.
- On Windows, use the equivalent Windows path format and `\\` where required.

Do not treat example separators as literal requirements. Resolve every path using
the conventions of the current environment.
