# Scout UX Performance Proposal

Last updated: 2026-07-09

## Purpose

This proposal covers the small set of user-experience changes that could make Scout feel faster and clearer at enterprise scale without changing underlying business behavior.

None of the items below are implemented by default. Each should be treated as an explicit product decision, not a hidden side effect of performance work.

## What Has Already Improved Without UX Changes

The current performance work focused on system behavior behind the scenes:

- user-facing pages are now measured more consistently
- background jobs can be kept off interactive API nodes
- queue freshness and projection lag are tracked explicitly
- certification and release checks now catch regressions before rollout

That means Scout should become more stable and more predictable at scale even before any visible UI changes are approved.

## Why Consider UX Changes At All

Even when the system is faster, analysts can still experience delay if the product does not clearly communicate:

- whether data is still loading
- whether data is fresh
- whether a long-running action is queued, in progress, or finished
- whether a filter-heavy page is waiting on a large result set

The proposals below are aimed at reducing confusion and perceived slowness while preserving the current product model.

## Proposal 1: Clear Freshness Status On Heavy Pages

Pages:

- `/exposure`
- `/findings`
- `/inventory`
- `/vuln-repo`

Proposal:

- Show a small "Last updated" timestamp near the main page heading.
- Show a neutral "Refreshing" state only while visible data is being updated.
- Show a subtle "Data may be delayed" warning only when freshness SLOs are actually out of bounds.

Why it helps:

- reduces uncertainty when data refresh takes time
- makes background recompute lag understandable instead of looking like a broken page

Behavior constraint:

- no change to refresh timing, data rules, or page layout hierarchy

## Proposal 2: Better Feedback For Queued Or Long-Running Actions

Actions:

- sync triggers
- incident or ticket creation
- ingestion requests
- heavy recompute or maintenance actions exposed to operators

Proposal:

- Replace ambiguous success messaging with status language such as "Queued", "Running", or "Completed".
- Show the latest known state in the existing action area instead of requiring manual page refresh guesswork.
- Keep the action outcome wording consistent across integrations.

Why it helps:

- users understand that work was accepted even when the final effect is not immediate
- reduces duplicate clicks and accidental re-submission

Behavior constraint:

- no change to action semantics, permissions, or completion criteria

## Proposal 3: Safer Perceived Performance On Large Tables

Pages:

- findings
- inventory
- software identity
- vulnerability repository

Proposal:

- Keep current table behavior, but add a clearly visible loading state when filters or sorts are in progress.
- Preserve current results on screen while new results load, instead of flashing to an empty state.
- Show active filters more prominently so users understand why a large result set changed.

Why it helps:

- makes filtering feel more stable
- reduces the sense that the grid is resetting or losing context

Behavior constraint:

- no change to filter meaning, sort rules, pagination semantics, or row content

## Proposal 4: Return-To-Tab Awareness

Proposal:

- When a user comes back to a tab after it has been hidden, show a lightweight refresh pulse or "Updated just now" confirmation if new data arrived.

Why it helps:

- aligns the hidden-tab polling optimization with a visible confidence cue
- avoids the feeling that the page silently changed while the user was away

Behavior constraint:

- no change to active-tab freshness cadence

## Proposal 5: Operational Transparency For Platform Views

Pages:

- operational dashboard
- platform console

Proposal:

- Present system health with plain-language labels such as "Healthy", "Delayed", or "Needs attention".
- Group performance signals into a few understandable sections:
  - page responsiveness
  - data freshness
  - background processing
- Avoid exposing raw internal terminology first when a simpler label is enough.

Why it helps:

- makes the new scorecard usable by non-engineers
- helps demo and support scenarios without requiring metric interpretation

Behavior constraint:

- no change to underlying metrics or alert thresholds

## Proposal 6: Accessibility Review Before Any Table Virtualization

Proposal:

- Do not enable virtualization by default yet.
- If explored later, put it behind a feature flag and validate:
  - keyboard movement
  - row selection behavior
  - screen-reader announcements
  - browser find-in-page expectations
  - analyst scanability for long grids

Why it helps:

- virtualization may improve speed, but it can also hurt usability if introduced carelessly

Behavior constraint:

- no rollout until parity checks pass

## Recommended Decision Order

Highest-value, lowest-risk items:

1. Freshness status on heavy pages
2. Better feedback for queued and long-running actions
3. Safer loading behavior on large tables

Medium-value items:

4. Return-to-tab awareness
5. Operational transparency improvements

Deferred until explicitly approved:

6. Virtualization or any major rendering-model change

## Suggested Rollout Approach

- put each UX change behind a feature flag
- enable first for internal users or demo environments
- validate parity for results, accessibility, and analyst workflows
- promote only after product review confirms the experience is better

## Decision Needed

If approved, the best first implementation slice is:

- freshness status on `/findings` and `/exposure`
- queued-action feedback for ingestion and incident/ticket flows
- stable loading states for the findings grid

That slice is visible, low-risk, and directly connected to the performance architecture already completed.
