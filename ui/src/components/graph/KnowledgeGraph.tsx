import { useCallback, useEffect, useRef, useState } from "react"
import {
  Maximize2,
  Pause,
  Play,
  Search,
  X,
} from "lucide-react"

// vis-network types
import type { Network as VisNetwork } from "vis-network"

// ── Node/edge styling constants (ported from html_report.py) ─────────

const NODE_COLORS: Record<string, { background: string; border: string; highlight: { background: string; border: string } }> = {
  capability: { background: "#3b82f6", border: "#1d4ed8", highlight: { background: "#60a5fa", border: "#2563eb" } },
  tool: { background: "#10b981", border: "#047857", highlight: { background: "#34d399", border: "#059669" } },
  vulnerability: { background: "#ef4444", border: "#b91c1c", highlight: { background: "#f87171", border: "#dc2626" } },
  data_source: { background: "#f59e0b", border: "#b45309", highlight: { background: "#fbbf24", border: "#d97706" } },
  phase: { background: "#8b5cf6", border: "#6d28d9", highlight: { background: "#a78bfa", border: "#7c3aed" } },
  agent_state: { background: "#6b7280", border: "#374151", highlight: { background: "#9ca3af", border: "#4b5563" } },
}

const NODE_SHAPES: Record<string, string> = {
  capability: "dot",
  tool: "diamond",
  vulnerability: "triangle",
  data_source: "square",
  phase: "hexagon",
  agent_state: "ellipse",
}

const NODE_SIZES: Record<string, number> = {
  capability: 18,
  tool: 20,
  vulnerability: 25,
  data_source: 18,
  phase: 22,
  agent_state: 16,
}

const EDGE_COLORS: Record<string, string> = {
  uses_tool: "#3b82f6",
  accesses_data: "#f59e0b",
  trusts: "#10b981",
  enables: "#ef4444",
  can_chain_to: "#f97316",
  discovered_in: "#8b5cf6",
  exploits: "#dc2626",
  leads_to: "#ec4899",
}

const EDGE_DASHES = new Set(["enables", "can_chain_to", "exploits"])

// ── Types ────────────────────────────────────────────────────────────

interface GraphNode {
  id: string
  node_type: string
  [key: string]: unknown
}

interface GraphEdge {
  source: string
  target: string
  edge_type: string
  [key: string]: unknown
}

interface GraphState {
  nodes: GraphNode[]
  edges: GraphEdge[]
  stats?: {
    total_nodes: number
    total_edges: number
    node_types: Record<string, number>
  }
}

interface NodeDetail {
  id: string
  type: string
  attrs: Record<string, unknown>
}

interface Props {
  graphState: GraphState | null
  highlightPath?: string[]
  onClearHighlight?: () => void
}

export function KnowledgeGraph({ graphState, highlightPath, onClearHighlight }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef = useRef<VisNetwork | null>(null)
  const [physicsEnabled, setPhysicsEnabled] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null)

  const isLargeGraph = (graphState?.nodes.length ?? 0) > 200

  // Build and render the graph
  useEffect(() => {
    if (!containerRef.current || !graphState || graphState.nodes.length === 0) return

    let cancelled = false

    const loadNetwork = async () => {
      const vis = await import("vis-network/standalone")
      if (cancelled) return

      const nodes = graphState.nodes.map((n) => {
        const nodeType = n.node_type?.toLowerCase() ?? "agent_state"
        return {
          id: n.id,
          label: (n.label as string) ?? n.id,
          shape: NODE_SHAPES[nodeType] ?? "ellipse",
          size: NODE_SIZES[nodeType] ?? 16,
          color: NODE_COLORS[nodeType] ?? NODE_COLORS.agent_state,
          font: { color: "#fafafa", size: 11 },
          _raw: n,
        }
      })

      const edges = graphState.edges.map((e, i) => {
        const edgeType = e.edge_type?.toLowerCase() ?? "default"
        return {
          id: `e${i}`,
          from: e.source,
          to: e.target,
          color: { color: EDGE_COLORS[edgeType] ?? "#555", opacity: 0.8 },
          dashes: EDGE_DASHES.has(edgeType),
          arrows: "to",
          width: 1.5,
          _raw: e,
        }
      })

      const nodesDS = new vis.DataSet(nodes)
      const edgesDS = new vis.DataSet(edges)

      const network = new vis.Network(
        containerRef.current!,
        { nodes: nodesDS, edges: edgesDS },
        {
          physics: {
            enabled: !isLargeGraph,
            solver: "forceAtlas2Based",
            stabilization: { iterations: isLargeGraph ? 200 : 100 },
          },
          interaction: {
            hover: true,
            tooltipDelay: 200,
          },
          edges: {
            smooth: { enabled: true, type: "continuous", roundness: 0.2 },
          },
        }
      )

      network.on("click", (params: { nodes: string[] }) => {
        if (params.nodes.length > 0) {
          const nodeId = params.nodes[0]
          const node = graphState.nodes.find((n) => n.id === nodeId)
          if (node) {
            const { id, node_type, ...rest } = node
            setSelectedNode({ id, type: node_type, attrs: rest })
          }
        } else {
          setSelectedNode(null)
        }
      })

      networkRef.current = network

      if (isLargeGraph) {
        network.stabilize(200)
        setPhysicsEnabled(false)
      }
    }

    loadNetwork()
    return () => { cancelled = true }
  }, [graphState, isLargeGraph])

  // Handle path highlighting
  useEffect(() => {
    if (!networkRef.current || !highlightPath || highlightPath.length === 0) return

    const pathSet = new Set(highlightPath)
    const allNodeIds = graphState?.nodes.map((n) => n.id) ?? []

    // Dim nodes not in path
    const nodeUpdates: Array<{ id: string; opacity: number }> = allNodeIds.map((nid) => ({
      id: nid,
      opacity: pathSet.has(nid) ? 1.0 : 0.15,
    }))

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(networkRef.current as any).body.data.nodes.update(nodeUpdates)
  }, [highlightPath, graphState])

  // Physics toggle
  const togglePhysics = useCallback(() => {
    if (!networkRef.current) return
    const next = !physicsEnabled
    networkRef.current.setOptions({ physics: { enabled: next } })
    setPhysicsEnabled(next)
  }, [physicsEnabled])

  // Fit view
  const fitView = useCallback(() => {
    networkRef.current?.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } })
  }, [])

  // Search
  const handleSearch = useCallback(() => {
    if (!networkRef.current || !searchQuery.trim() || !graphState) return
    const q = searchQuery.toLowerCase()
    const match = graphState.nodes.find(
      (n) => n.id.toLowerCase().includes(q) || ((n.label as string) ?? "").toLowerCase().includes(q)
    )
    if (match) {
      networkRef.current.focus(match.id, { scale: 1.5, animation: { duration: 500, easingFunction: "easeInOutQuad" } })
      networkRef.current.selectNodes([match.id])
    }
  }, [searchQuery, graphState])

  if (!graphState || graphState.nodes.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-8 text-center">
        <p className="text-fg-secondary">No graph data available for this scan.</p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-border bg-bg-secondary overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-bg-tertiary">
        <button onClick={fitView} className="p-1.5 rounded hover:bg-bg-secondary transition-colors" title="Fit view">
          <Maximize2 className="h-4 w-4 text-fg-secondary" />
        </button>
        <button onClick={togglePhysics} className="p-1.5 rounded hover:bg-bg-secondary transition-colors" title={physicsEnabled ? "Pause physics" : "Resume physics"}>
          {physicsEnabled ? <Pause className="h-4 w-4 text-fg-secondary" /> : <Play className="h-4 w-4 text-fg-secondary" />}
        </button>
        {highlightPath && onClearHighlight && (
          <button onClick={onClearHighlight} className="p-1.5 rounded hover:bg-bg-secondary transition-colors text-severity-danger" title="Clear highlight">
            <X className="h-4 w-4" />
          </button>
        )}
        <div className="flex-1" />
        <div className="flex items-center gap-1">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="Search nodes..."
            className="bg-bg-secondary border border-border rounded px-2 py-1 text-xs text-fg-primary w-40"
          />
          <button onClick={handleSearch} className="p-1.5 rounded hover:bg-bg-secondary transition-colors">
            <Search className="h-3.5 w-3.5 text-fg-secondary" />
          </button>
        </div>

        {/* Legend */}
        <div className="hidden md:flex items-center gap-3 ml-3 text-[10px] text-fg-secondary">
          {Object.entries(NODE_COLORS).map(([type, colors]) => (
            <span key={type} className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ backgroundColor: colors.background }} />
              {type.replace("_", " ")}
            </span>
          ))}
        </div>
      </div>

      {/* Graph container */}
      <div ref={containerRef} className="w-full" style={{ height: 500 }} />

      {/* Node detail overlay */}
      {selectedNode && (
        <div className="absolute bottom-4 right-4 w-72 rounded-lg border border-border bg-bg-secondary/95 backdrop-blur p-3 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-accent capitalize">{selectedNode.type.replace("_", " ")}</span>
            <button onClick={() => setSelectedNode(null)} className="p-0.5">
              <X className="h-3.5 w-3.5 text-fg-secondary" />
            </button>
          </div>
          <p className="text-sm font-medium text-fg-primary truncate">{selectedNode.id}</p>
          <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
            {Object.entries(selectedNode.attrs)
              .filter(([k]) => k !== "label")
              .map(([key, val]) => (
                <div key={key} className="flex gap-2 text-xs">
                  <span className="text-fg-secondary shrink-0">{key}:</span>
                  <span className="text-fg-primary truncate">{String(val)}</span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}
