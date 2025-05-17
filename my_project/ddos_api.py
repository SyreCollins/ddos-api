import os
import logging
import multiprocessing
import statistics
import asyncio
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Dict, Any
import uvicorn
from .ddos import execute_attack

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = multiprocessing.Manager()
attack_processes: Dict[str, multiprocessing.Process] = {}
attack_stats = manager.dict()
attack_logs = manager.dict()
rate_limits: Dict[str, list] = {}

RATE_LIMIT = 10
RATE_WINDOW = timedelta(minutes=1)

class AttackConfig(BaseModel):
    target_url: str
    duration: int
    intensity: int
    concurrent_connections: int
    attack_type: str

    @validator('intensity')
    def intensity_range(cls, v):
        if not 1 <= v <= 5:
            raise ValueError('intensity must be between 1 and 5')
        return v

    @validator('duration')
    def duration_positive(cls, v):
        if v <= 0:
            raise ValueError('duration must be positive')
        return v

class AttackStats(BaseModel):
    requests_sent: int = 0
    connections_open: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: datetime = None
    complete: bool = False
    latency_samples: list = []
    http_status_codes: dict = {}
    timeout_count: int = 0
    bandwidth: dict = {}
    connection_metrics: dict = {}
    request_performance: dict = {}

    # enhanced fields
    min_latency: float = None
    max_latency: float = None
    avg_latency: float = None
    median_latency: float = None
    p50: float = None
    p90: float = None
    p95: float = None

    def to_dict(self) -> Dict[str, Any]:
        base = self.dict()
        latencies = base.get('latency_samples') or []
        if latencies:
            base['min_latency'] = min(latencies)
            base['max_latency'] = max(latencies)
            base['avg_latency'] = statistics.mean(latencies)
            base['median_latency'] = statistics.median(latencies)
            qs = statistics.quantiles(latencies, n=100)
            base['p50'] = qs[49]
            base['p90'] = qs[89]
            base['p95'] = qs[94]
        if self.start_time:
            base['start_time'] = self.start_time.isoformat()
        return base

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Service is running"}

@app.post("/api/attack/start")
async def start_attack(config: AttackConfig, request: Request):
    ip = request.client.host
    now = datetime.utcnow()
    times = rate_limits.setdefault(ip, [])
    times = [t for t in times if now - t < RATE_WINDOW]
    if len(times) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    times.append(now)
    rate_limits[ip] = times

    attack_id = str(len(attack_processes) + 1)
    # initialize stats
    attack_stats[attack_id] = manager.dict({
        'requests_sent': 0,
        'connections_open': 0,
        'bytes_sent': 0,
        'errors': 0,
        'start_time': now,
        'complete': False,
        'latency_samples': manager.list(),
        'http_status_codes': manager.dict(),
        'timeout_count': 0,
        'bandwidth': manager.dict({
            'total_data_transferred': 0,
            'peak_download': 0,
            'download_history': manager.list()
        }),
        'connection_metrics': manager.dict({
            'attempts': 0,
            'successes': 0,
            'active_connections': 0,
            'lifetimes': manager.list()
        }),
        'request_performance': manager.dict()
    })
    attack_logs[attack_id] = manager.list()

    proc = multiprocessing.Process(
        target=execute_attack,
        args=(config, attack_stats[attack_id], attack_logs[attack_id]),
    )
    proc.start()
    attack_processes[attack_id] = proc
    logger.info(f"Started attack {attack_id} from {ip}")
    return {"attack_id": attack_id}

@app.get("/api/attack/{attack_id}/stop")
async def stop_attack(attack_id: str):
    if attack_id in attack_processes:
        proc = attack_processes.pop(attack_id)
        proc.terminate()
        proc.join(timeout=5)
        if attack_id in attack_stats:
            attack_stats[attack_id]['complete'] = True
        logger.info(f"Stopped attack {attack_id}")
        return {"status": "stopped"}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/logs")
async def get_logs(attack_id: str):
    if attack_id in attack_logs:
        return {"logs": list(attack_logs[attack_id])}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats")
async def get_stats(attack_id: str):
    if attack_id in attack_stats:
        raw = attack_stats[attack_id]
        stats = AttackStats(**{**raw, 'start_time': raw['start_time']})
        return {"stats": stats.to_dict()}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.websocket("/ws/attack/{attack_id}")
async def attack_ws(ws: WebSocket, attack_id: str):
    await ws.accept()
    try:
        while True:
            if attack_id not in attack_stats:
                await ws.close(code=1008)
                return
            raw = attack_stats[attack_id]
            stats = AttackStats(**{**raw, 'start_time': raw['start_time']})
            await ws.send_json(stats.to_dict())
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass

@app.on_event("shutdown")
def shutdown_cleanup():
    for pid, proc in attack_processes.items():
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
    attack_processes.clear()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv('PORT', 8000)))
