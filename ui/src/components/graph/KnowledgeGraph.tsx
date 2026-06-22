import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Search, X } from "lucide-react"
import type { Network as VisNetwork, Options as VisOptions } from "vis-network"

import type { GraphState } from "../../types"
import { GraphControls } from "./GraphControls"
import { GraphLegend } from "./GraphLegend"
import { AttackChainWalker } from "./AttackChainWalker"
import {
  graphStateToVis,
  presentEdgeTypes,
  presentNodeTypes,
  presentSeverities,
  type VisNode,
} from "./graphMapping"
import { largeGraphNodeThreshold } from "./graphStyle"
import { layoutOptions, physicsDefaultFor, type LayoutMode } from "./layouts"
import {
  applyClusterMode,
  resetClusters,
  shouldAutoCluster,
  type ClusterableNetwork,
  type ClusterMode,
} from "./clustering"

interface VisDataSet {
  update: (items: unknown) => void
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
  /** Discovered attack paths (node-id sequences) for the chain walker. */
  attackPaths?: string[][]
  /** Externally-focused node (e.g. from clicking a finding/attack-log row). */
  selectedNodeId?: string | null
  /** Notifies the parent which node was clicked (for cross-linking). */
  onNodeSelect?: (nodeId: string | null) => void
}

export function KnowledgeGraph({
  graphState,
  highlightPath,
  onClearHighlight,
  attackPaths = [],
  selectedNodeId,
  onNodeSelect,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef = useRef<VisNetwork | null>(null)
  const nodesRef = useRef<VisDataSet | null>(null)
  const edgesRef = useRef<VisDataSet | null>(null)
  const visNodesRef = useRef<VisNode[]>([])
  const clusterIdsRef = useRef<string[]>([])

  const [layoutMode, setLayoutMode] = useState<LayoutMode>("force")
  const [clusterMode, setClusterMode] = useState<ClusterMode>("none")
  const [physicsEnabled, setPhysicsEnabled] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null)
  const [hiddenNodeTypes, setHiddenNodeTypes] = useState<Set<string>>(new Set())
  const [hiddenEdgeTypes, setHiddenEdgeTypes] = useState<Set<string>>(new Set())
  const [hiddenSeverities, setHiddenSeverities] = useState<Set<string>>(new Set())
  const [walk, setWalk] = useState<{ path: string[]; step: number } | null>(null)

  const isLargeGraph = (graphState?.nodes.length ?? 0) > largeGraphNodeThreshold

  const nodeTypes = useMemo(() => (graphState ? presentNodeTypes(graphState) : []), [graphState])
  const edgeTypes = useMemo(() => (graphState ? presentEdgeTypes(graphState) : []), [graphState])
  const severities = useMemo(() => (graphState ? presentSeverities(graphState) : []), [graphState])
  const hasAgents = nodeTypes.includes("agent")

  // Build / rebuild the network when the graph data changes.
  useEffect(() => {
    if (!containerRef.current || !graphState || graphState.nodes.length === 0) return
    let cancelled = false

    const loadNetwork = async () => {
      const vis = await import("vis-network/standalone")
      if (cancelled || !containerRef.current) return

      const { nodes, edges } = graphStateToVis(graphState)
      visNodesRef.current = nodes
      const nodesDS = new vis.DataSet(nodes)
      const edgesDS = new vis.DataSet(edges)
      nodesRef.current = nodesDS as unknown as VisDataSet
      edgesRef.current = edgesDS as unknown as VisDataSet

      const base = layoutOptions(layoutMode, isLargeGraph)
      const options = {
        ...base,
        interaction: { hover: true, tooltipDelay: 200 },
        edges: { smooth: { enabled: true, type: "continuous", roundness: 0.2 } },
      } as unknown as VisOptions

      const network = new vis.Network(
        containerRef.current,
        { nodes: nodesDS, edges: edgesDS },
        options,
      )

      network.on("click", (params: { nodes: string[] }) => {
        if (params.nodes.length > 0) {
          const node = graphState.nodes.find((n) => n.id === params.nodes[0])
          if (node) {
            const { id, node_type, ...rest } = node
            setSelectedNode({ id, type: node_type, attrs: rest })
            onNodeSelect?.(id)
            return
          }
        }
        setSelectedNode(null)
        onNodeSelect?.(null)
      })

      networkRef.current = network
      setPhysicsEnabled(physicsDefaultFor(layoutMode, isLargeGraph))

      // Auto-cluster large graphs by phase for a navigable overview.
      if (shouldAutoCluster(graphState.nodes.length)) {
        setClusterMode("phase")
      }
    }

    loadNetwork()
    return () => {
      cancelled = true
    }
    // layoutMode/clusterMode handled by dedicated effects (no rebuild).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphState, isLargeGraph])

  // Apply layout changes without rebuilding (preserves filters + selection).
  useEffect(() => {
    if (!networkRef.current) return
    networkRef.current.setOptions(layoutOptions(layoutMode, isLargeGraph) as unknown as VisOptions)
    setPhysicsEnabled(physicsDefaultFor(layoutMode, isLargeGraph))
  }, [layoutMode, isLargeGraph])

  // Apply clustering (collapse/expand into super-nodes).
  useEffect(() => {
    const network = networkRef.current as ClusterableNetwork | null
    if (!network) return
    resetClusters(network, clusterIdsRef.current)
    clusterIdsRef.current = applyClusterMode(network, visNodesRef.current, clusterMode)
  }, [clusterMode, graphState])

  // Apply type/severity/edge filters by toggling node/edge visibility.
  useEffect(() => {
    if (!nodesRef.current || !edgesRef.current || !graphState) return
    nodesRef.current.update(
      graphState.nodes.map((n) => ({
        id: n.id,
        hidden:
          hiddenNodeTypes.has(n.node_type) ||
          (n.severity ? hiddenSeverities.has(n.severity) : false),
      })),
    )
    edgesRef.current.update(
      graphState.edges.map((e, i) => ({ id: `e${i}`, hidden: hiddenEdgeTypes.has(e.edge_type) })),
    )
  }, [graphState, hiddenNodeTypes, hiddenEdgeTypes, hiddenSeverities])

  // Static path highlighting — dim nodes not on the highlighted path.
  useEffect(() => {
    if (!nodesRef.current || !highlightPath || highlightPath.length === 0 || !graphState) return
    const pathSet = new Set(highlightPath)
    nodesRef.current.update(
      graphState.nodes.map((n) => ({ id: n.id, opacity: pathSet.has(n.id) ? 1.0 : 0.15 })),
    )
  }, [highlightPath, graphState])

  // Attack-chain walker — focus the current step with surrounding context.
  useEffect(() => {
    if (!nodesRef.current || !graphState) return
    if (!walk) {
      nodesRef.current.update(graphState.nodes.map((n) => ({ id: n.id, opacity: 1.0 })))
      return
    }
    const pathSet = new Set(walk.path)
    const current = walk.path[walk.step]
    nodesRef.current.update(
      graphState.nodes.map((n) => ({
        id: n.id,
        opacity: n.id === current ? 1.0 : pathSet.has(n.id) ? 0.6 : 0.12,
      })),
    )
    if (current && networkRef.current) {
      try {
        networkRef.current.focus(current, {
          scale: 1.3,
          animation: { duration: 400, easingFunction: "easeInOutQuad" },
        })
        networkRef.current.selectNodes([current])
      } catch {
        // Node may be inside a cluster — ignore focus failure.
      }
    }
  }, [walk, graphState])

  // External focus (cross-linking from a finding / attack-log row).
  useEffect(() => {
    if (!networkRef.current || !selectedNodeId) return
    try {
      networkRef.current.focus(selectedNodeId, {
        scale: 1.5,
        animation: { duration: 500, easingFunction: "easeInOutQuad" },
      })
      networkRef.current.selectNodes([selectedNodeId])
    } catch {
      // Unknown / clustered node — ignore.
    }
  }, [selectedNodeId])

  const togglePhysics = useCallback(() => {
    if (!networkRef.current) return
    const next = !physicsEnabled
    networkRef.current.setOptions({ physics: { enabled: next } })
    setPhysicsEnabled(next)
  }, [physicsEnabled])

  const fitView = useCallback(() => {
    networkRef.current?.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } })
  }, [])

  const handleSearch = useCallback(() => {
    if (!networkRef.current || !searchQuery.trim() || !graphState) return
    const q = searchQuery.toLowerCase()
    const match = graphState.nodes.find(
      (n) => n.id.toLowerCase().includes(q) || ((n.name as string) ?? "").toLowerCase().includes(q),
    )
    if (match) {
      networkRef.current.focus(match.id, {
        scale: 1.5,
        animation: { duration: 500, easingFunction: "easeInOutQuad" },
      })
      networkRef.current.selectNodes([match.id])
    }
  }, [searchQuery, graphState])

  const toggleSetMember = (setter: typeof setHiddenNodeTypes, value: string) => {
    setter((prev) => {
      const next = new Set(prev)
      if (next.has(value)) next.delete(value)
      else next.add(value)
      return next
    })
  }

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
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-border bg-bg-tertiary">
        <GraphControls
          layoutMode={layoutMode}
          onLayoutChange={setLayoutMode}
          clusterMode={clusterMode}
          onClusterChange={setClusterMode}
          hasAgents={hasAgents}
          physicsEnabled={physicsEnabled}
          onTogglePhysics={togglePhysics}
          onFit={fitView}
          showClear={Boolean(highlightPath && onClearHighlight)}
          onClear={() => onClearHighlight?.()}
        />
        <AttackChainWalker
          paths={attackPaths}
          onStep={(path, step) => setWalk({ path, step })}
          onExit={() => setWalk(null)}
        />
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
      </div>

      {/* Graph container */}
      <div ref={containerRef} className="w-full" style={{ height: 500 }} />

      {/* Legend doubles as a filter */}
      <GraphLegend
        nodeTypes={nodeTypes}
        hiddenNodeTypes={hiddenNodeTypes}
        onToggleNodeType={(t) => toggleSetMember(setHiddenNodeTypes, t)}
        edgeTypes={edgeTypes}
        hiddenEdgeTypes={hiddenEdgeTypes}
        onToggleEdgeType={(t) => toggleSetMember(setHiddenEdgeTypes, t)}
        severities={severities}
        hiddenSeverities={hiddenSeverities}
        onToggleSeverity={(s) => toggleSetMember(setHiddenSeverities, s)}
      />

      {/* Node detail overlay */}
      {selectedNode && (
        <div className="absolute bottom-4 right-4 w-72 rounded-lg border border-border bg-bg-secondary/95 backdrop-blur p-3 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-accent capitalize">
              {selectedNode.type.replace("_", " ")}
            </span>
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
