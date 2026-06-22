// Collapse/expand the graph into labeled super-nodes (spec 026 US2).
//
// Clustering by phase or type uses node attributes that `mapNode` already
// emits (`phase`, `nodeType`); clustering by agent groups each agent node
// with the nodes it directly connects to. Above the spec's node threshold a
// graph auto-clusters by phase so large graphs open as a navigable overview.
import { graphStyle, largeGraphNodeThreshold } from "./graphStyle"
import type { VisNode } from "./graphMapping"

export type ClusterMode = "none" | "phase" | "type" | "agent"

// Minimal structural view of the vis-network methods we use, so this module
// stays decoupled from the heavy vis types.
export interface ClusterableNetwork {
  cluster(options: Record<string, unknown>): void
  openCluster(clusterId: string): void
  clusterByConnection(nodeId: string, options?: Record<string, unknown>): void
}

const CLUSTER_COLOR = "#475569"

function clusterId(mode: ClusterMode, key: string): string {
  return `cluster:${mode}:${key}`
}

/** Open (expand) any clusters we previously created. */
export function resetClusters(network: ClusterableNetwork, ids: Iterable<string>): void {
  for (const id of ids) {
    try {
      network.openCluster(id)
    } catch {
      // Cluster already opened or never created — safe to ignore.
    }
  }
}

function groupCounts(nodes: VisNode[], keyOf: (n: VisNode) => string | undefined): Map<string, number> {
  const counts = new Map<string, number>()
  for (const n of nodes) {
    const key = keyOf(n)
    if (key) counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return counts
}

function clusterByAttribute(
  network: ClusterableNetwork,
  nodes: VisNode[],
  mode: "phase" | "type",
): string[] {
  const attr = mode === "phase" ? "phase" : "nodeType"
  const keyOf = (n: VisNode) => (mode === "phase" ? n.phase : n.nodeType)
  const counts = groupCounts(nodes, keyOf)
  const created: string[] = []

  for (const [key, count] of counts) {
    // A cluster of one adds noise, not clarity.
    if (count < 2) continue
    const id = clusterId(mode, key)
    network.cluster({
      joinCondition: (opts: Record<string, unknown>) => opts[attr] === key,
      clusterNodeProperties: {
        id,
        label: `${key.replace(/_/g, " ")} (${count})`,
        shape: "database",
        color: CLUSTER_COLOR,
        font: { color: "#f8fafc", size: 13 },
        borderWidth: 2,
      },
    })
    created.push(id)
  }
  return created
}

function clusterByAgent(network: ClusterableNetwork, nodes: VisNode[]): string[] {
  const agents = nodes.filter((n) => n.nodeType === "agent")
  const created: string[] = []
  for (const agent of agents) {
    const id = clusterId("agent", agent.id)
    network.clusterByConnection(agent.id, {
      clusterNodeProperties: {
        id,
        label: `${agent.label} ⚙`,
        shape: "database",
        color: graphStyle.node_types.agent?.color ?? CLUSTER_COLOR,
        font: { color: "#f8fafc", size: 13 },
        borderWidth: 2,
      },
    })
    created.push(id)
  }
  return created
}

/**
 * Apply a cluster mode, returning the ids of the clusters created (so the
 * caller can expand them before applying a different mode).
 */
export function applyClusterMode(
  network: ClusterableNetwork,
  nodes: VisNode[],
  mode: ClusterMode,
): string[] {
  if (mode === "none") return []
  if (mode === "agent") return clusterByAgent(network, nodes)
  return clusterByAttribute(network, nodes, mode)
}

/** Whether a graph of this size should auto-cluster on first render. */
export function shouldAutoCluster(nodeCount: number): boolean {
  return graphStyle.thresholds.auto_cluster && nodeCount > largeGraphNodeThreshold
}
