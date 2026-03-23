import { useEffect, useRef, useState, useCallback } from "react"
import type { ProgressMessage } from "../types"

export function useRunProgress(runId: string | undefined) {
  const [events, setEvents] = useState<ProgressMessage[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (!runId) return

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
    const host = window.location.host
    const ws = new WebSocket(`${protocol}//${host}/ws/runs/${runId}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data) as ProgressMessage
      setEvents((prev) => [...prev, data])
    }

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [runId])

  useEffect(() => {
    const cleanup = connect()
    return cleanup
  }, [connect])

  return { events, connected, latest: events[events.length - 1] ?? null }
}
