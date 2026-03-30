"""WebSocket endpoint for real-time scan progress."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from ziran.interfaces.web.dependencies import get_db, get_run_manager
from ziran.interfaces.web.services.run_manager import RunManager

router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def run_progress(
    websocket: WebSocket,
    run_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    manager: Annotated[RunManager, Depends(get_run_manager)],
) -> None:
    """Stream scan progress events to the client."""
    await websocket.accept()

    # Validate run exists
    from ziran.interfaces.web.models import Run

    run = await db.get(Run, uuid.UUID(run_id))
    if not run:
        await websocket.send_json({"error": "Run not found"})
        await websocket.close(code=4004)
        return

    # If run is already finished, send final status and close
    if run.status in ("completed", "failed", "cancelled"):
        await websocket.send_json(
            {
                "event": "campaign_complete",
                "message": f"Run already {run.status}",
            }
        )
        await websocket.close()
        return

    # Subscribe to progress events
    manager.subscribe(run_id, websocket)
    try:
        # Keep connection open until client disconnects or scan finishes
        while True:
            # Wait for client messages (ping/pong or disconnect)
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.unsubscribe(run_id, websocket)
