// vis-network layout/physics option builders for the supported layout modes.
//
// `force`         — physics-based ForceAtlas2 cloud (the original behavior).
// `hierarchical`  — left-to-right bands by campaign phase (uses node.level,
//                   which `mapNode` derives from the discovery phase).
// `centrality`    — physics tuned to pull pivotal nodes toward the center.
export type LayoutMode = "force" | "hierarchical" | "centrality"

export interface LayoutOptions {
  layout: { hierarchical: Record<string, unknown> }
  physics: Record<string, unknown>
}

export function layoutOptions(mode: LayoutMode, largeGraph: boolean): LayoutOptions {
  if (mode === "hierarchical") {
    return {
      layout: {
        hierarchical: {
          enabled: true,
          direction: "LR",
          sortMethod: "directed",
          levelSeparation: 220,
          nodeSpacing: 110,
          treeSpacing: 160,
        },
      },
      physics: { enabled: false },
    }
  }

  if (mode === "centrality") {
    return {
      layout: { hierarchical: { enabled: false } },
      physics: {
        enabled: !largeGraph,
        solver: "forceAtlas2Based",
        forceAtlas2Based: {
          gravitationalConstant: -30,
          centralGravity: 0.05,
          springLength: 100,
          springConstant: 0.08,
          damping: 0.4,
        },
        stabilization: { iterations: largeGraph ? 200 : 120 },
      },
    }
  }

  // force (default)
  return {
    layout: { hierarchical: { enabled: false } },
    physics: {
      enabled: !largeGraph,
      solver: "forceAtlas2Based",
      stabilization: { iterations: largeGraph ? 200 : 100 },
    },
  }
}

/** Whether physics should run for a given layout mode + graph size. */
export function physicsDefaultFor(mode: LayoutMode, largeGraph: boolean): boolean {
  return mode !== "hierarchical" && !largeGraph
}
