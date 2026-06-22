// Typed accessors over the canonical graph style/mapping spec.
//
// The spec itself (`graph_style.json`) is the single source of truth shared
// with the Python HTML report. This module mirrors the accessor logic in
// `ziran/interfaces/graph_style/spec.py`, so both surfaces render identically.
import rawSpec from "@graphstyle"

export interface NodeStyle {
  color: string
  border: string
  shape: string
  base_size: number
}

export interface EdgeStyle {
  color: string
  dashes: boolean | number[]
  width: number
  arrow: boolean
}

export interface DangerMarker {
  border_color: string
  border_width: number
  shadow_color: string
  shadow_size: number
}

export interface GraphStyleSpec {
  version: string
  node_types: Record<string, NodeStyle>
  edge_types: Record<string, EdgeStyle>
  severity_ramp: Record<string, string>
  danger_marker: DangerMarker
  phase_order: string[]
  size_encoding: { min_size: number; max_size: number }
  attack_edge_types: string[]
  thresholds: { large_graph_node_threshold: number; auto_cluster: boolean }
}

export const graphStyle = rawSpec as GraphStyleSpec

const FALLBACK_NODE_TYPE = "agent_state"
const FALLBACK_EDGE_COLOR = "#94a3b8"

/** Styling for a node type, falling back to the neutral agent_state style. */
export function nodeStyle(nodeType: string): NodeStyle {
  return graphStyle.node_types[nodeType] ?? graphStyle.node_types[FALLBACK_NODE_TYPE]
}

/** Styling for an edge type, synthesizing a neutral default when unknown. */
export function edgeStyle(edgeType: string): EdgeStyle {
  return (
    graphStyle.edge_types[edgeType] ?? {
      color: FALLBACK_EDGE_COLOR,
      dashes: false,
      width: 1.5,
      arrow: true,
    }
  )
}

/** Ramp color for a severity band (case-insensitive), or undefined. */
export function severityColor(severity?: string | null): string | undefined {
  if (!severity) return undefined
  return graphStyle.severity_ramp[severity.toLowerCase()]
}

/** Map a normalized centrality (0..1) onto a size within the encoding bounds. */
export function sizeForCentrality(centrality?: number | null): number {
  const c = centrality == null ? 0 : Math.max(0, Math.min(1, centrality))
  const { min_size, max_size } = graphStyle.size_encoding
  return min_size + (max_size - min_size) * c
}

/** Effective node size: the type's base size, grown by centrality. */
export function nodeSize(nodeType: string, centrality?: number | null): number {
  return Math.max(nodeStyle(nodeType).base_size, sizeForCentrality(centrality))
}

/** Hierarchical-layout column for a phase (0 = unassigned, else 1..N). */
export function phaseLevel(phase?: string | null): number {
  if (!phase) return 0
  const i = graphStyle.phase_order.indexOf(phase)
  return i < 0 ? 0 : i + 1
}

/** Whether an edge type is attack-relevant (emphasized in the viz). */
export function isAttackEdge(edgeType: string): boolean {
  return graphStyle.attack_edge_types.includes(edgeType)
}

export const largeGraphNodeThreshold = graphStyle.thresholds.large_graph_node_threshold
