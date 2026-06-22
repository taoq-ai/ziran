// Pure mapping from graph state to vis-network nodes/edges.
//
// This mirrors `graph_state_to_vis` in `ziran/interfaces/cli/html_report.py`;
// both read the same shared spec via the accessors in `graphStyle.ts`, so the
// web UI and the HTML report render the graph identically.
import type { GraphEdge, GraphNode, GraphState } from "../../types"
import {
  edgeStyle,
  graphStyle,
  isAttackEdge,
  nodeSize,
  nodeStyle,
  phaseLevel,
  severityColor,
} from "./graphStyle"

const FALLBACK_NODE_TYPE = "agent_state"

export interface VisNodeColor {
  background: string
  border: string
  highlight: { background: string; border: string }
}

export interface VisNode {
  id: string
  label: string
  shape: string
  size: number
  color: VisNodeColor
  font: { color: string; size: number }
  nodeType: string
  severity?: string
  phase?: string
  level: number
  borderWidth?: number
  shadow?: { enabled: boolean; color: string; size: number }
  _raw: GraphNode
}

export interface VisEdge {
  id: string
  from: string
  to: string
  label: string
  arrows: string
  color: { color: string; opacity: number }
  width: number
  dashes: boolean | number[]
  edgeType: string
  _raw: GraphEdge
}

function truncate(label: string): string {
  return label.length > 30 ? `${label.slice(0, 27)}…` : label
}

export function mapNode(node: GraphNode): VisNode {
  const nodeType = node.node_type ?? FALLBACK_NODE_TYPE
  const style = nodeStyle(nodeType)
  const label = truncate(((node.name as string) ?? node.id) as string)

  const severity = node.severity
  const border = severityColor(severity) ?? style.border

  const vis: VisNode = {
    id: node.id,
    label,
    shape: style.shape,
    size: nodeSize(nodeType, node.centrality),
    color: {
      background: style.color,
      border,
      highlight: { background: style.color, border },
    },
    font: { color: "#f8fafc", size: 12 },
    nodeType,
    severity,
    phase: node.phase,
    level: phaseLevel(node.phase),
    _raw: node,
  }

  if (node.dangerous) {
    const marker = graphStyle.danger_marker
    vis.borderWidth = marker.border_width
    vis.color.border = marker.border_color
    vis.shadow = { enabled: true, color: marker.shadow_color, size: marker.shadow_size }
  } else if (severity) {
    vis.borderWidth = 3
  }

  return vis
}

export function mapEdge(edge: GraphEdge, idx: number): VisEdge {
  const edgeType = edge.edge_type ?? ""
  const style = edgeStyle(edgeType)
  const attack = isAttackEdge(edgeType)
  return {
    id: `e${idx}`,
    from: edge.source,
    to: edge.target,
    label: edgeType.replace(/_/g, " "),
    arrows: style.arrow ? "to" : "",
    color: { color: style.color, opacity: attack ? 1.0 : 0.85 },
    width: attack ? Math.max(style.width, 2.5) : style.width,
    dashes: style.dashes,
    edgeType,
    _raw: edge,
  }
}

export function graphStateToVis(state: GraphState): { nodes: VisNode[]; edges: VisEdge[] } {
  return {
    nodes: state.nodes.map(mapNode),
    edges: state.edges.map((e, i) => mapEdge(e, i)),
  }
}

/** Distinct node types present in the graph, for legend/filter building. */
export function presentNodeTypes(state: GraphState): string[] {
  return [...new Set(state.nodes.map((n) => n.node_type ?? FALLBACK_NODE_TYPE))]
}

/** Distinct edge types present in the graph, for filter building. */
export function presentEdgeTypes(state: GraphState): string[] {
  return [...new Set(state.edges.map((e) => e.edge_type).filter(Boolean))]
}

/** Severity bands present among nodes, for filter building. */
export function presentSeverities(state: GraphState): string[] {
  return [...new Set(state.nodes.map((n) => n.severity).filter((s): s is string => Boolean(s)))]
}
