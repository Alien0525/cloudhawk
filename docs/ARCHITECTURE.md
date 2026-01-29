# 🏗️ CloudHawk Architecture

## System Overview

CloudHawk is a distributed, real-time cloud security monitoring system built on modern stream processing and machine learning technologies.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     CloudHawk Architecture                       │
└─────────────────────────────────────────────────────────────────┘

                        ┌──────────────┐
                        │   AWS        │
                        │  CloudTrail  │
                        │   Events     │
                        └──────┬───────┘
                               │
                        ┌──────▼───────┐
                        │    Event     │
                        │  Simulator   │
                        └──────┬───────┘
                               │
                    ┌──────────▼──────────┐
                    │   Apache Kafka      │
                    │  (Message Broker)   │
                    └──────────┬──────────┘
                               │
                ┌──────────────▼─────────────┐
                │    Stream Processor        │
                │  - Rule-based detection    │
                │  - Correlation engine      │
                │  - MITRE ATT&CK mapping    │
                └──┬────────┬────────┬───┬───┘
                   │        │        │   │
        ┌──────────▼──┐  ┌─▼────┐  │   │
        │  ML Engine  │  │Redis │  │   │
        │  - Anomaly  │  │Cache │  │   │
        │  Detection  │  └──────┘  │   │
        └──────┬──────┘            │   │
               │              ┌────▼───▼────┐
               │              │ TimescaleDB │
               │              │ (Time-Series│
               │              │  Database)  │
               └──────────────►└─────┬───────┘
                              │      │
                         ┌────▼──────▼─────┐
                         │  Elasticsearch  │
                         │  (Log Storage)  │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │  FastAPI Server │
                         │  - REST API     │
                         │  - WebSockets   │
                         └────┬─────┬──────┘
                              │     │
                    ┌─────────▼─┐   └──────────┐
                    │   React   │              │
                    │ Dashboard │      ┌───────▼────────┐
                    └───────────┘      │   Grafana +    │
                                       │  Prometheus    │
                                       └────────────────┘
```

## Components

### 1. Event Simulator
**Purpose**: Generates realistic CloudTrail events for demonstration

**Technology**: Python, Kafka Producer

**Features**:
- Simulates 100+ events/second
- Generates normal and suspicious activities
- Creates attack sequences (5% of traffic)
- Realistic CloudTrail JSON format

**Attack Patterns**:
- Credential access
- Privilege escalation
- Data exfiltration
- Persistence
- Impact (deletions)

### 2. Apache Kafka
**Purpose**: Distributed message streaming

**Technology**: Apache Kafka 7.5

**Configuration**:
- Single broker (scalable to cluster)
- Topic: `cloudtrail-events`
- Replication factor: 1 (demo)
- Retention: 7 days

**Benefits**:
- Decouples producers/consumers
- Handles high throughput
- Provides fault tolerance
- Enables replay capability

### 3. Stream Processor
**Purpose**: Real-time event analysis and threat detection

**Technology**: Python, Kafka Consumer

**Detection Methods**:
1. **IP Reputation Check**
   - Maintains list of known malicious IPs
   - Checks against threat intelligence

2. **High-Risk Event Detection**
   - Monitors destructive operations
   - Flags privilege changes

3. **Behavioral Analysis**
   - Tracks user activity history
   - Detects rapid suspicious actions

4. **Attack Chain Detection**
   - Correlates related events
   - Identifies multi-step attacks

5. **Impossible Travel**
   - Tracks IP changes per user
   - Flags geographic anomalies

6. **Off-Hours Activity**
   - Monitors business hours
   - Flags unusual timing

**Outputs**:
- PostgreSQL (long-term storage)
- Redis (real-time cache)
- Elasticsearch (searchable logs)
- Redis Pub/Sub (alerts)

### 4. ML Anomaly Detection Engine
**Purpose**: Machine learning-based threat detection

**Technology**: Python, scikit-learn (Isolation Forest)

**Models**:

1. **User Behavior Model**
   - Features: Event types, timing, severity
   - Detects: Unusual user patterns

2. **IP Behavior Model**
   - Features: IP characteristics, timing
   - Detects: Suspicious sources

3. **Temporal Pattern Model**
   - Features: Time-based patterns
   - Detects: Off-hours anomalies

**Training**:
- Retrains every hour (configurable)
- Uses last 24 hours of data
- Requires minimum 100 events
- Contamination rate: 10%

**Anomaly Scoring**:
- Score < -0.3: CRITICAL
- Score < -0.2: HIGH
- Score < -0.1: MEDIUM
- Otherwise: LOW

### 5. TimescaleDB
**Purpose**: Time-series event storage

**Technology**: PostgreSQL + TimescaleDB extension

**Schema**:

**security_events**:
- time (timestamptz, indexed)
- event_id (primary key)
- event_name, event_source
- aws_region, source_ip
- user_name, user_agent
- severity, is_suspicious
- event_data (jsonb)

**detected_threats**:
- id (serial)
- time (timestamptz)
- event_id (foreign key)
- threat_type, severity
- description, mitre_attack
- user_name, source_ip
- additional_data (jsonb)

**Optimization**:
- Hypertable with 1-day chunks
- Automatic partitioning
- Efficient time-range queries
- Compression (optional)

### 6. Redis
**Purpose**: Real-time caching and pub/sub

**Technology**: Redis 7

**Data Structures**:
- `recent_events` (list): Last 100 events
- `recent_threats` (list): Last 50 threats
- `active_alerts` (list): Last 20 alerts
- `metrics` (hash): Real-time counters
- `threats:ip:{ip}` (set): Threats by IP
- `ml_model:{type}` (string): Serialized models

**Pub/Sub**:
- Channel: `security_alerts`
- Broadcasts high-severity threats
- Consumed by API for WebSocket

### 7. Elasticsearch
**Purpose**: Full-text log search

**Technology**: Elasticsearch 8.11

**Index**: `security-events`

**Use Cases**:
- Full-text event search
- Complex queries
- Aggregations
- Log exploration

### 8. FastAPI Backend
**Purpose**: REST API and WebSocket server

**Technology**: FastAPI, Uvicorn, WebSockets

**Endpoints**:

**Statistics**:
- `GET /api/stats`: Real-time metrics

**Events**:
- `GET /api/events/recent`
- `POST /api/events/query`

**Threats**:
- `GET /api/threats/recent`
- `POST /api/threats/query`

**Alerts**:
- `GET /api/alerts/active`

**Analytics**:
- `GET /api/analytics/timeline`
- `GET /api/analytics/top-users`
- `GET /api/analytics/top-ips`
- `GET /api/mitre-attack/coverage`

**WebSocket**:
- `WS /ws/realtime`: Live updates

**Features**:
- CORS enabled for dashboard
- JSON responses
- Error handling
- Connection management

### 9. React Dashboard
**Purpose**: Real-time visualization

**Technology**: React, Recharts, WebSockets, Axios

**Components**:

1. **StatsCards**: Key metrics
2. **EventTimeline**: 24-hour chart
3. **ThreatMap**: Pie chart
4. **ActiveAlerts**: Priority alerts
5. **RecentEvents**: Event table
6. **TopUsers**: Bar charts
7. **MitreCoverage**: Technique list

**Features**:
- WebSocket real-time updates
- Auto-refresh (30s)
- Browser notifications
- Responsive design
- Dark theme

### 10. Prometheus & Grafana
**Purpose**: Infrastructure monitoring

**Technology**: Prometheus (metrics), Grafana (visualization)

**Metrics Collected**:
- Service health
- API performance
- Database queries
- Redis operations
- Custom business metrics

## Data Flow

### Event Processing Flow
```
1. CloudTrail Event Generated
   ↓
2. Sent to Kafka (event-simulator)
   ↓
3. Consumed by Stream Processor
   ↓
4. Rule-based analysis
   ↓
5. Stored in TimescaleDB, Elasticsearch, Redis
   ↓
6. ML Engine analyzes periodically
   ↓
7. Anomalies stored as threats
   ↓
8. High-severity alerts published to Redis Pub/Sub
   ↓
9. API receives via subscription
   ↓
10. WebSocket broadcasts to dashboard
   ↓
11. User sees real-time alert
```

### Query Flow
```
1. User opens dashboard
   ↓
2. Dashboard calls API endpoints
   ↓
3. API queries:
   - Redis (real-time cache)
   - PostgreSQL (historical data)
   - Elasticsearch (full-text search)
   ↓
4. Results returned as JSON
   ↓
5. Dashboard renders visualizations
   ↓
6. WebSocket maintains connection
   ↓
7. Real-time updates pushed automatically
```

## Scaling Considerations

### Horizontal Scaling
- **Kafka**: Add brokers, increase partitions
- **Stream Processor**: Scale with `docker-compose up -d --scale`
- **PostgreSQL**: Read replicas, connection pooling
- **Redis**: Redis Cluster, Redis Sentinel
- **Elasticsearch**: Add nodes, sharding

### Vertical Scaling
- Increase container resources
- Optimize database queries
- Tune JVM settings (Kafka, ES)

### Performance Tuning
- Kafka batch size and linger
- PostgreSQL connection pooling
- Redis pipeline commands
- Elasticsearch bulk indexing
- React virtualization for large lists

## Security Architecture

### Network Security
- Internal Docker network
- Service isolation
- No exposed credentials

### Data Security
- PostgreSQL encryption at rest (optional)
- Redis password protection (optional)
- JWT authentication for API (implemented but not enforced in demo)

### Application Security
- Input validation
- SQL injection prevention (parameterized queries)
- XSS prevention (React escaping)
- Rate limiting (optional)

## High Availability

### For Production
1. **Kafka**: 3+ broker cluster with replication
2. **PostgreSQL**: Primary-replica setup with failover
3. **Redis**: Sentinel or Cluster mode
4. **Elasticsearch**: 3+ node cluster
5. **Load Balancer**: For API and dashboard

### Monitoring
- Prometheus for metrics
- Grafana for dashboards
- Alert manager for notifications
- Log aggregation (ELK stack)

## Technology Choices

### Why Kafka?
- Industry standard for stream processing
- High throughput (millions/sec)
- Durability and replay
- Easy to scale

### Why TimescaleDB?
- Optimized for time-series
- SQL compatibility
- Automatic partitioning
- Compression

### Why Isolation Forest?
- Unsupervised learning (no labeled data needed)
- Handles high-dimensional data
- Efficient training and inference
- Good for anomaly detection

### Why FastAPI?
- Modern Python framework
- Native WebSocket support
- Automatic API docs
- High performance

### Why React?
- Component-based architecture
- Rich ecosystem (Recharts, etc.)
- Easy WebSocket integration
- Fast rendering

## Deployment Options

### Docker Compose (Demo)
- Single machine
- Easy setup
- Great for learning

### Kubernetes (Production)
- High availability
- Auto-scaling
- Rolling updates
- Service mesh

### Cloud Managed Services
- AWS MSK (Kafka)
- AWS RDS (PostgreSQL)
- AWS ElastiCache (Redis)
- AWS OpenSearch (Elasticsearch)
- ECS/EKS for containers

---

This architecture provides a scalable, maintainable foundation for real-time security monitoring and threat detection.
