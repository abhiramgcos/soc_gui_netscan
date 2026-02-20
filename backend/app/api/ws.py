"""WebSocket endpoint for real-time scan progress updates."""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.utils.logging import get_logger

router = APIRouter(tags=["websocket"])
log = get_logger("ws")


class ConnectionManager:
    """Manage active WebSocket connections per scan and firmware analysis."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}
        self._firmware_connections: dict[str, list[WebSocket]] = {}
        self._global: list[WebSocket] = []

    async def connect(self, websocket: WebSocket, scan_id: str | None = None):
        await websocket.accept()
        if scan_id:
            self._connections.setdefault(scan_id, []).append(websocket)
        else:
            self._global.append(websocket)
        log.info("ws_connected", scan_id=scan_id)

    async def connect_firmware(self, websocket: WebSocket, analysis_id: str):
        await websocket.accept()
        self._firmware_connections.setdefault(analysis_id, []).append(websocket)
        log.info("ws_firmware_connected", analysis_id=analysis_id)

    def disconnect(self, websocket: WebSocket, scan_id: str | None = None):
        if scan_id and scan_id in self._connections:
            self._connections[scan_id] = [c for c in self._connections[scan_id] if c != websocket]
            if not self._connections[scan_id]:
                del self._connections[scan_id]
        elif websocket in self._global:
            self._global.remove(websocket)

    def disconnect_firmware(self, websocket: WebSocket, analysis_id: str):
        if analysis_id in self._firmware_connections:
            self._firmware_connections[analysis_id] = [
                c for c in self._firmware_connections[analysis_id] if c != websocket
            ]
            if not self._firmware_connections[analysis_id]:
                del self._firmware_connections[analysis_id]

    async def broadcast_scan(self, scan_id: str, data: dict):
        """Send update to all connections watching a specific scan + global watchers."""
        message = json.dumps(data)
        targets = self._connections.get(scan_id, []) + self._global
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                pass

    async def broadcast_firmware(self, analysis_id: str, data: dict):
        """Send update to connections watching a firmware analysis + global."""
        message = json.dumps(data)
        targets = self._firmware_connections.get(analysis_id, []) + self._global
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                pass

    async def broadcast_global(self, data: dict):
        """Send update to all global connections."""
        message = json.dumps(data)
        for ws in self._global:
            try:
                await ws.send_text(message)
            except Exception:
                pass


manager = ConnectionManager()


@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: uuid.UUID):
    """Subscribe to real-time updates for a specific scan."""
    sid = str(scan_id)
    await manager.connect(websocket, sid)
    try:
        while True:
            # Keep alive — client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket, sid)
        log.info("ws_disconnected", scan_id=sid)


@router.websocket("/ws/live")
async def live_websocket(websocket: WebSocket):
    """Subscribe to all scan updates globally."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        log.info("ws_global_disconnected")


@router.websocket("/ws/firmware/{analysis_id}")
async def firmware_websocket(websocket: WebSocket, analysis_id: uuid.UUID):
    """Subscribe to real-time updates for a firmware analysis."""
    aid = str(analysis_id)
    await manager.connect_firmware(websocket, aid)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect_firmware(websocket, aid)
        log.info("ws_firmware_disconnected", analysis_id=aid)
