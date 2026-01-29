from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import json
import os
from datetime import datetime, timedelta, timezone
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
from elasticsearch import Elasticsearch
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import jwt
from passlib.context import CryptContext

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_USER = os.getenv('POSTGRES_USER', 'cloudhawk')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'cloudhawk_secure_2024')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'cloudhawk')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
ELASTICSEARCH_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
JWT_SECRET = os.getenv('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')

# Initialize FastAPI
app = FastAPI(
    title="CloudHawk Security API",
    description="Real-time cloud threat detection and response system",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connections
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
redis_binary = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=False)


def get_pg_connection():
    """Get PostgreSQL connection"""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        dbname=POSTGRES_DB
    )


es_client = Elasticsearch([f'http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}'])

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"🔌 WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"🔌 WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            self.active_connections.remove(conn)


manager = ConnectionManager()


# Pydantic models
class EventFilter(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    severity: Optional[List[str]] = None
    event_name: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    limit: int = 100


class ThreatFilter(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    severity: Optional[List[str]] = None
    threat_type: Optional[str] = None
    limit: int = 100


# API Routes

@app.get("/")
async def root():
    """API health check"""
    return {
        "service": "CloudHawk Security API",
        "status": "operational",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/stats")
async def get_stats():
    """Get real-time statistics"""
    try:
        # Get metrics from Redis
        metrics = redis_client.hgetall('metrics')
        
        # Get recent events count
        recent_events = redis_client.llen('recent_events')
        
        # Get threat count
        threat_count = redis_client.get('threat_count') or 0
        
        # Get active alerts
        active_alerts = redis_client.llen('active_alerts')
        
        # Get severity distribution
        severity_dist = {
            'LOW': int(metrics.get('severity_LOW', 0)),
            'MEDIUM': int(metrics.get('severity_MEDIUM', 0)),
            'HIGH': int(metrics.get('severity_HIGH', 0)),
            'CRITICAL': int(metrics.get('severity_CRITICAL', 0))
        }
        
        # Get database stats
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Total events
            cur.execute("SELECT COUNT(*) as total FROM security_events;")
            total_events = cur.fetchone()['total']
            
            # Events last hour
            cur.execute("""
                SELECT COUNT(*) as count FROM security_events
                WHERE time > NOW() - INTERVAL '1 hour';
            """)
            events_last_hour = cur.fetchone()['count']
            
            # Threats last hour
            cur.execute("""
                SELECT COUNT(*) as count FROM detected_threats
                WHERE time > NOW() - INTERVAL '1 hour';
            """)
            threats_last_hour = cur.fetchone()['count']
            
            # Top threat types
            cur.execute("""
                SELECT threat_type, COUNT(*) as count
                FROM detected_threats
                WHERE time > NOW() - INTERVAL '24 hours'
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 5;
            """)
            top_threats = cur.fetchall()
        
        conn.close()
        
        return {
            "realtime": {
                "events_processed": int(metrics.get('events_processed', 0)),
                "threats_detected": int(threat_count),
                "active_alerts": active_alerts,
                "recent_events": recent_events
            },
            "severity_distribution": severity_dist,
            "database": {
                "total_events": total_events,
                "events_last_hour": events_last_hour,
                "threats_last_hour": threats_last_hour
            },
            "top_threats": top_threats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/events/recent")
async def get_recent_events(limit: int = 50):
    """Get recent security events"""
    try:
        # Get from Redis cache
        events_json = redis_client.lrange('recent_events', 0, limit - 1)
        events = [json.loads(e) for e in events_json]
        
        return {
            "events": events,
            "count": len(events),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/events/query")
async def query_events(filters: EventFilter):
    """Query security events with filters"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Build query
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            
            if filters.start_time:
                query += " AND time >= %s"
                params.append(filters.start_time)
            
            if filters.end_time:
                query += " AND time <= %s"
                params.append(filters.end_time)
            
            if filters.severity:
                query += " AND severity = ANY(%s)"
                params.append(filters.severity)
            
            if filters.event_name:
                query += " AND event_name ILIKE %s"
                params.append(f"%{filters.event_name}%")
            
            if filters.user_name:
                query += " AND user_name ILIKE %s"
                params.append(f"%{filters.user_name}%")
            
            if filters.source_ip:
                query += " AND source_ip = %s"
                params.append(filters.source_ip)
            
            query += " ORDER BY time DESC LIMIT %s"
            params.append(filters.limit)
            
            cur.execute(query, params)
            events = cur.fetchall()
        
        conn.close()
        
        # Convert datetime to string
        for event in events:
            if event['time']:
                event['time'] = event['time'].isoformat()
        
        return {
            "events": events,
            "count": len(events),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threats/recent")
async def get_recent_threats(limit: int = 50):
    """Get recent detected threats"""
    try:
        # Get from Redis cache
        threats_json = redis_client.lrange('recent_threats', 0, limit - 1)
        threats = [json.loads(t) for t in threats_json]
        
        return {
            "threats": threats,
            "count": len(threats),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threats/query")
async def query_threats(filters: ThreatFilter):
    """Query detected threats with filters"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Build query
            query = "SELECT * FROM detected_threats WHERE 1=1"
            params = []
            
            if filters.start_time:
                query += " AND time >= %s"
                params.append(filters.start_time)
            
            if filters.end_time:
                query += " AND time <= %s"
                params.append(filters.end_time)
            
            if filters.severity:
                query += " AND severity = ANY(%s)"
                params.append(filters.severity)
            
            if filters.threat_type:
                query += " AND threat_type = %s"
                params.append(filters.threat_type)
            
            query += " ORDER BY time DESC LIMIT %s"
            params.append(filters.limit)
            
            cur.execute(query, params)
            threats = cur.fetchall()
        
        conn.close()
        
        # Convert datetime to string
        for threat in threats:
            if threat['time']:
                threat['time'] = threat['time'].isoformat()
        
        return {
            "threats": threats,
            "count": len(threats),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/alerts/active")
async def get_active_alerts():
    """Get active security alerts"""
    try:
        alerts_json = redis_client.lrange('active_alerts', 0, 19)
        alerts = [json.loads(a) for a in alerts_json]
        
        return {
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/timeline")
async def get_event_timeline(hours: int = 24):
    """Get event timeline analytics"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    DATE_TRUNC('hour', time) as hour,
                    severity,
                    COUNT(*) as count
                FROM security_events
                WHERE time > NOW() - INTERVAL '%s hours'
                GROUP BY hour, severity
                ORDER BY hour;
            """, (hours,))
            
            results = cur.fetchall()
        
        conn.close()
        
        # Format results
        timeline = {}
        for row in results:
            hour_str = row['hour'].isoformat()
            if hour_str not in timeline:
                timeline[hour_str] = {
                    'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0
                }
            timeline[hour_str][row['severity']] = row['count']
        
        return {
            "timeline": timeline,
            "period_hours": hours,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/top-users")
async def get_top_users(limit: int = 10):
    """Get top users by activity"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    user_name,
                    COUNT(*) as event_count,
                    COUNT(CASE WHEN is_suspicious THEN 1 END) as suspicious_count,
                    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
                FROM security_events
                WHERE time > NOW() - INTERVAL '24 hours'
                AND user_name IS NOT NULL
                GROUP BY user_name
                ORDER BY event_count DESC
                LIMIT %s;
            """, (limit,))
            
            users = cur.fetchall()
        
        conn.close()
        
        return {
            "users": users,
            "count": len(users),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/top-ips")
async def get_top_ips(limit: int = 10):
    """Get top source IPs by activity"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    source_ip,
                    COUNT(*) as event_count,
                    COUNT(CASE WHEN is_suspicious THEN 1 END) as suspicious_count,
                    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
                FROM security_events
                WHERE time > NOW() - INTERVAL '24 hours'
                AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY suspicious_count DESC, event_count DESC
                LIMIT %s;
            """, (limit,))
            
            ips = cur.fetchall()
        
        conn.close()
        
        return {
            "ips": ips,
            "count": len(ips),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mitre-attack/coverage")
async def get_mitre_coverage():
    """Get MITRE ATT&CK technique coverage"""
    try:
        conn = get_pg_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    mitre_attack,
                    threat_type,
                    COUNT(*) as count
                FROM detected_threats
                WHERE time > NOW() - INTERVAL '24 hours'
                AND mitre_attack IS NOT NULL
                GROUP BY mitre_attack, threat_type
                ORDER BY count DESC;
            """)
            
            techniques = cur.fetchall()
        
        conn.close()
        
        return {
            "techniques": techniques,
            "count": len(techniques),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket endpoint for real-time updates
@app.websocket("/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time event streaming"""
    await manager.connect(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to CloudHawk real-time stream",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Subscribe to Redis pub/sub for alerts
        pubsub = redis_client.pubsub()
        pubsub.subscribe('security_alerts')
        
        # Keep connection alive and send updates
        while True:
            # Check for new messages
            message = pubsub.get_message()
            if message and message['type'] == 'message':
                alert_data = json.loads(message['data'])
                await websocket.send_json({
                    "type": "alert",
                    "data": alert_data
                })
            
            # Send periodic stats update
            try:
                stats = await get_stats()
                await websocket.send_json({
                    "type": "stats",
                    "data": stats
                })
            except:
                pass
            
            # Sleep to prevent overwhelming the client
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
