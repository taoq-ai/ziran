# Feature Specification: A configured data tag no chain reaches is reported as a warning

**Feature Branch**: `feat/tag-unreached-warning`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-TAG-UNREACHED-WARN (goal G-c)

## The promise in our own words

Operators tag tools and data sources under `blast_radius.tags` in `.ziran/detectors.yaml`
(spec 091). A tag shows only on a chain whose radius reaches the tagged node. A tag on a tool
outside every chain, or a mistyped id, shows nothing and says nothing. After the change,
`ResultBuilder` adds one warning to the existing `metadata["warnings"]` list (spec 086) naming
every configured tag key no chain's radius reached. The Markdown and HTML reports already show
that list, so the warning appears there with no renderer change.

A key counts as reached when some radius (demonstrated or reachable) tagged its node id, or
the id without `tool_`, matching how `blast_radius` looks tags up.

## Acceptance scenarios

1. Given a tag on a tool outside every chain, when a scan finishes, then the result's warnings
   name that tag.
2. Given a tag a chain's radius reaches (by node id or by tool name), then no warning names it.
3. Given no tags configured, then no warning is added and `warnings` stays absent.

## Requirements

- **FR-001**: At most one warning per scan, listing the unreached keys sorted.
- **FR-002**: Existing graph warnings keep their order; the new one follows them.
- **FR-003**: The input graph is not changed.

## Assumptions

- The warning is added to the result metadata, not to `graph.warnings`, so building twice does
  not repeat it. Overturned if a caller reads the warning from the graph.
- Tag ids are operator config, not target text, so the reports' existing warning rendering is
  enough. Overturned if tag keys come from a scanned agent.
