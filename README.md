# OpenSRE Security Advisory: Cross-Tenant Thread Access via Incomplete LangGraph Authorization

Published: 2026-04-22

This is an independent public disclosure and not an official vendor advisory.

## Advisory ID

Pending CVE  
Suggested placeholder: `CVE-YYYY-NNNNN`

## Severity

High

## Affected Product

- Vendor: Tracer Cloud
- Product: OpenSRE
- Repository: https://github.com/Tracer-Cloud/opensre

## Affected Versions

OpenSRE `at least v2026.4.5` through `v2026.4.22`

Latest audited affected commit:

- `831f1356012276be5de9712c01199ca95735feb0`
- Commit date: `2026-04-22 01:58:40 UTC`

Earliest audited affected tag:

- `v2026.4.5`
- Tag target commit: `aa8178a122963fddadc559b7582658e7cc50d652`
- Commit date: `2026-04-05 18:24:24 +0200`

## Summary

OpenSRE contains an incorrect access control vulnerability in its custom LangGraph authorization handlers for threads.

In affected versions, the application filters thread search results by `org_id`, but does not apply the same organization-scoping filter to direct thread operations such as read, update, delete, or create_run. As a result, an authenticated user who knows another tenant's `thread_id` can directly access or manipulate cross-tenant thread data.

## Vulnerability Type

- CWE-284: Improper Access Control
- CVE form category: Incorrect Access Control

## Attack Type

Remote

## Impact

An authenticated attacker may be able to:

- read another tenant's thread state
- update another tenant's thread
- delete another tenant's thread
- create runs on another tenant's thread

This can lead to cross-tenant information disclosure, unauthorized workflow execution, and unauthorized modification or deletion of investigation state.

## Technical Details

OpenSRE configures LangGraph custom authentication through `langgraph.json`, which points to `app/auth/auth.py`.

In the affected implementation:

- `on_thread_create` adds `org_id` metadata to newly created threads
- `on_thread_search` returns `{"org_id": _get_org_id(ctx)}` and therefore filters search results by organization
- `on_thread_read`, `on_thread_update`, `on_thread_delete`, and `on_thread_create_run` all return `None`

Relevant code:

```python
@auth.on.threads.read
async def on_thread_read(ctx, value) -> None:
    return None

@auth.on.threads.update
async def on_thread_update(ctx, value) -> None:
    return None

@auth.on.threads.delete
async def on_thread_delete(ctx, value) -> None:
    return None

@auth.on.threads.search
async def on_thread_search(ctx, value) -> dict[str, str]:
    return {"org_id": _get_org_id(ctx)}

@auth.on.threads.create_run
async def on_thread_create_run(ctx, value) -> None:
    return None
