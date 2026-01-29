import json
import os
import time
from datetime import datetime, timezone
from kafka import KafkaConsumer
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
from elasticsearch import Elasticsearch
import hashlib
from collections import defaultdict, deque

# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9094')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'cloudtrail-events')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_USER = os.getenv('POSTGRES_USER', 'cloudhawk')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'cloudhawk_secure_2024')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'cloudhawk')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
ELASTICSEARCH_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))


class ThreatDetector:
    """Advanced threat detection logic"""
    
    def __init__(self):
        # Track user behavior for anomaly detection
        self.user_activity = defaultdict(lambda: deque(maxlen=100))
        self.ip_activity = defaultdict(lambda: deque(maxlen=100))
        
        # Threat intelligence
        self.suspicious_ips = set([
            '185.220.101.1', '45.142.120.50', '89.248.165.123', '103.253.145.28'
        ])
        
        self.high_risk_events = {
            'DeleteBucket', 'DeleteDBInstance', 'TerminateInstances',
            'AttachUserPolicy', 'CreateAccessKey', 'DeleteUser',
            'PutBucketPolicy', 'ModifyDBInstance'
        }
        
        # Attack patterns (MITRE ATT&CK)
        self.attack_chains = {
            'credential_theft': [
                'GetAccountPasswordPolicy', 'ListAccessKeys', 'CreateAccessKey'
            ],
            'privilege_escalation': [
                'AttachUserPolicy', 'PutUserPolicy', 'CreatePolicyVersion'
            ],
            'data_exfiltration': [
                'ListBuckets', 'GetBucketLocation', 'GetObject', 'CreateSnapshot'
            ]
        }

    def analyze_event(self, event):
        """Comprehensive threat analysis"""
        threats = []
        
        # 1. Check source IP reputation
        source_ip = event.get('sourceIPAddress')
        if source_ip in self.suspicious_ips:
            threats.append({
                'type': 'malicious_ip',
                'severity': 'HIGH',
                'description': f'Request from known malicious IP: {source_ip}',
                'mitre': 'T1078 - Valid Accounts'
            })
        
        # 2. Check for high-risk events
        event_name = event.get('eventName')
        if event_name in self.high_risk_events:
            threats.append({
                'type': 'high_risk_event',
                'severity': 'HIGH',
                'description': f'High-risk event detected: {event_name}',
                'mitre': self._get_mitre_for_event(event_name)
            })
        
        # 3. Check for unusual access patterns
        user = event.get('userIdentity', {}).get('userName')
        if user:
            user_history = self.user_activity[user]
            user_history.append(event_name)
            
            # Detect rapid successive high-risk actions
            if len(user_history) >= 5:
                recent = list(user_history)[-5:]
                high_risk_count = sum(1 for e in recent if e in self.high_risk_events)
                if high_risk_count >= 3:
                    threats.append({
                        'type': 'suspicious_behavior',
                        'severity': 'CRITICAL',
                        'description': f'User {user} performing multiple high-risk actions',
                        'mitre': 'T1059 - Command and Scripting'
                    })
        
        # 4. Check for attack chains
        for chain_name, chain_events in self.attack_chains.items():
            if user:
                recent_events = list(self.user_activity[user])[-10:]
                matches = [e for e in chain_events if e in recent_events]
                if len(matches) >= 2:
                    threats.append({
                        'type': 'attack_chain',
                        'severity': 'CRITICAL',
                        'description': f'Potential {chain_name} attack chain detected',
                        'mitre': self._get_mitre_for_chain(chain_name),
                        'chain': chain_name
                    })
        
        # 5. Check for impossible travel (IP geolocation changes)
        if user and source_ip:
            ip_history = self.ip_activity[user]
            if ip_history and len(ip_history) > 0:
                last_ip = ip_history[-1]
                # Simplified check: different IP class
                if last_ip.split('.')[0] != source_ip.split('.')[0]:
                    threats.append({
                        'type': 'impossible_travel',
                        'severity': 'MEDIUM',
                        'description': f'User {user} accessing from different network',
                        'mitre': 'T1078 - Valid Accounts'
                    })
            ip_history.append(source_ip)
        
        # 6. Check for suspicious user agents
        user_agent = event.get('userAgent', '')
        if 'MSIE' in user_agent or 'compatible' in user_agent.lower():
            threats.append({
                'type': 'suspicious_user_agent',
                'severity': 'MEDIUM',
                'description': f'Suspicious user agent: {user_agent}',
                'mitre': 'T1071 - Application Layer Protocol'
            })
        
        # 7. Check for non-business hours activity
        event_time = datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
        if event_time.hour < 6 or event_time.hour > 20:
            if event_name in self.high_risk_events:
                threats.append({
                    'type': 'off_hours_activity',
                    'severity': 'MEDIUM',
                    'description': f'High-risk activity outside business hours',
                    'mitre': 'T1078 - Valid Accounts'
                })
        
        return threats

    def _get_mitre_for_event(self, event_name):
        """Map event to MITRE ATT&CK technique"""
        mitre_map = {
            'DeleteBucket': 'T1485 - Data Destruction',
            'DeleteDBInstance': 'T1485 - Data Destruction',
            'TerminateInstances': 'T1529 - System Shutdown/Reboot',
            'AttachUserPolicy': 'T1098 - Account Manipulation',
            'CreateAccessKey': 'T1098 - Account Manipulation',
            'PutBucketPolicy': 'T1098 - Account Manipulation'
        }
        return mitre_map.get(event_name, 'T1059 - Command and Scripting')

    def _get_mitre_for_chain(self, chain_name):
        """Map attack chain to MITRE ATT&CK"""
        chain_map = {
            'credential_theft': 'T1078 - Valid Accounts',
            'privilege_escalation': 'T1548 - Abuse Elevation Control',
            'data_exfiltration': 'T1537 - Transfer Data to Cloud Account'
        }
        return chain_map.get(chain_name, 'T1059 - Command and Scripting')


class StreamProcessor:
    """Main stream processing engine"""
    
    def __init__(self):
        print("🔧 Initializing Stream Processor...")
        
        # Wait for services
        time.sleep(15)
        
        # Initialize Kafka consumer
        self.consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            auto_offset_reset='latest',
            enable_auto_commit=True,
            group_id='cloudhawk-processor'
        )
        
        # Initialize Redis
        self.redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True
        )
        
        # Initialize PostgreSQL
        self.pg_conn = psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            dbname=POSTGRES_DB
        )
        self._setup_database()
        
        # Initialize Elasticsearch
        self.es_client = Elasticsearch([f'http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}'])
        self._setup_elasticsearch()
        
        # Initialize threat detector
        self.threat_detector = ThreatDetector()
        
        # Metrics
        self.events_processed = 0
        self.threats_detected = 0
        
        print("✅ Stream Processor initialized successfully")

    def _setup_database(self):
        """Setup TimescaleDB schema"""
        with self.pg_conn.cursor() as cur:
            # Enable TimescaleDB extension
            cur.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
            
            # Create events table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    time TIMESTAMPTZ NOT NULL,
                    event_id TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    event_source TEXT,
                    aws_region TEXT,
                    source_ip TEXT,
                    user_name TEXT,
                    user_agent TEXT,
                    severity TEXT,
                    is_suspicious BOOLEAN,
                    event_data JSONB,
                    PRIMARY KEY (event_id, time)
                );
            """)
            
            # Create hypertable for time-series optimization
            cur.execute("""
                SELECT create_hypertable('security_events', 'time', 
                    if_not_exists => TRUE,
                    chunk_time_interval => INTERVAL '1 day'
                );
            """)
            
            # Create threats table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS detected_threats (
                    id SERIAL PRIMARY KEY,
                    time TIMESTAMPTZ NOT NULL,
                    event_id TEXT,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    mitre_attack TEXT,
                    user_name TEXT,
                    source_ip TEXT,
                    additional_data JSONB
                );
            """)
            
            # Create indexes
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_severity 
                ON security_events (severity, time DESC);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_user 
                ON security_events (user_name, time DESC);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_severity 
                ON detected_threats (severity, time DESC);
            """)
            
            self.pg_conn.commit()
        
        print("✅ Database schema created")

    def _setup_elasticsearch(self):
        """Setup Elasticsearch indices"""
        index_body = {
            'mappings': {
                'properties': {
                    'timestamp': {'type': 'date'},
                    'event_id': {'type': 'keyword'},
                    'event_name': {'type': 'keyword'},
                    'user_name': {'type': 'keyword'},
                    'source_ip': {'type': 'ip'},
                    'severity': {'type': 'keyword'},
                    'is_suspicious': {'type': 'boolean'},
                    'threats': {'type': 'nested'},
                    'event_data': {'type': 'object', 'enabled': False}
                }
            }
        }
        
        if not self.es_client.indices.exists(index='security-events'):
            self.es_client.indices.create(index='security-events', body=index_body)
        
        print("✅ Elasticsearch indices created")

    def process_event(self, event):
        """Process a single event"""
        try:
            # Extract key fields
            event_id = event.get('eventID')
            event_time = event.get('eventTime')
            event_name = event.get('eventName')
            source_ip = event.get('sourceIPAddress')
            user_identity = event.get('userIdentity', {})
            user_name = user_identity.get('userName', 'unknown')
            user_agent = event.get('userAgent', '')
            
            # Run threat detection
            threats = self.threat_detector.analyze_event(event)
            
            # Calculate severity
            severity = 'LOW'
            if threats:
                max_severity = max(t['severity'] for t in threats)
                severity = max_severity
                self.threats_detected += len(threats)
            
            # Store in PostgreSQL
            self._store_in_postgres(event, event_time, event_id, event_name, 
                                   source_ip, user_name, user_agent, severity, threats)
            
            # Store in Elasticsearch
            self._store_in_elasticsearch(event, event_time, event_id, event_name,
                                        source_ip, user_name, severity, threats)
            
            # Update Redis (real-time cache)
            self._update_redis_cache(event, threats, severity)
            
            # Publish alerts for high-severity threats
            if severity in ['HIGH', 'CRITICAL']:
                self._publish_alert(event, threats, severity)
            
            self.events_processed += 1
            
            if self.events_processed % 100 == 0:
                print(f"📊 Processed: {self.events_processed} events, "
                      f"Detected: {self.threats_detected} threats")
            
        except Exception as e:
            print(f"❌ Error processing event: {e}")

    def _store_in_postgres(self, event, event_time, event_id, event_name, 
                          source_ip, user_name, user_agent, severity, threats):
        """Store event in PostgreSQL"""
        with self.pg_conn.cursor() as cur:
            # Insert event
            cur.execute("""
                INSERT INTO security_events 
                (time, event_id, event_name, event_source, aws_region, 
                 source_ip, user_name, user_agent, severity, is_suspicious, event_data)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id, time) DO NOTHING;
            """, (
                event_time,
                event_id,
                event_name,
                event.get('eventSource'),
                event.get('awsRegion'),
                source_ip,
                user_name,
                user_agent,
                severity,
                len(threats) > 0,
                json.dumps(event)
            ))
            
            # Insert threats
            for threat in threats:
                cur.execute("""
                    INSERT INTO detected_threats 
                    (time, event_id, threat_type, severity, description, 
                     mitre_attack, user_name, source_ip, additional_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    event_time,
                    event_id,
                    threat['type'],
                    threat['severity'],
                    threat['description'],
                    threat.get('mitre'),
                    user_name,
                    source_ip,
                    json.dumps(threat)
                ))
            
            self.pg_conn.commit()

    def _store_in_elasticsearch(self, event, event_time, event_id, event_name,
                               source_ip, user_name, severity, threats):
        """Store event in Elasticsearch"""
        doc = {
            'timestamp': event_time,
            'event_id': event_id,
            'event_name': event_name,
            'user_name': user_name,
            'source_ip': source_ip,
            'severity': severity,
            'is_suspicious': len(threats) > 0,
            'threats': threats,
            'event_data': event
        }
        
        self.es_client.index(index='security-events', id=event_id, document=doc)

    def _update_redis_cache(self, event, threats, severity):
        """Update Redis with real-time data"""
        # Store latest events
        event_data = {
            'event_id': event.get('eventID'),
            'event_name': event.get('eventName'),
            'user': event.get('userIdentity', {}).get('userName'),
            'source_ip': event.get('sourceIPAddress'),
            'severity': severity,
            'threat_count': len(threats),
            'timestamp': event.get('eventTime')
        }
        
        # Push to recent events list (keep last 100)
        self.redis_client.lpush('recent_events', json.dumps(event_data))
        self.redis_client.ltrim('recent_events', 0, 99)
        
        # Update threat count
        if threats:
            self.redis_client.incr('threat_count')
            self.redis_client.lpush('recent_threats', json.dumps(threats))
            self.redis_client.ltrim('recent_threats', 0, 49)
        
        # Update metrics
        self.redis_client.hincrby('metrics', 'events_processed', 1)
        self.redis_client.hincrby('metrics', f'severity_{severity}', 1)
        
        # Store active threats by IP
        if threats and severity in ['HIGH', 'CRITICAL']:
            source_ip = event.get('sourceIPAddress')
            self.redis_client.sadd(f'threats:ip:{source_ip}', event.get('eventID'))
            self.redis_client.expire(f'threats:ip:{source_ip}', 3600)

    def _publish_alert(self, event, threats, severity):
        """Publish high-priority alerts"""
        alert = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': severity,
            'event_id': event.get('eventID'),
            'event_name': event.get('eventName'),
            'user': event.get('userIdentity', {}).get('userName'),
            'source_ip': event.get('sourceIPAddress'),
            'threats': threats
        }
        
        # Publish to Redis pub/sub
        self.redis_client.publish('security_alerts', json.dumps(alert))
        
        # Store in active alerts
        self.redis_client.lpush('active_alerts', json.dumps(alert))
        self.redis_client.ltrim('active_alerts', 0, 19)

    def run(self):
        """Main processing loop"""
        print("🚀 Stream Processor started")
        print(f"📡 Listening to Kafka topic: {KAFKA_TOPIC}")
        print("-" * 60)
        
        try:
            for message in self.consumer:
                self.process_event(message.value)
        except KeyboardInterrupt:
            print("\n⏹️  Stream Processor stopped")
        finally:
            self.consumer.close()
            self.pg_conn.close()
            self.redis_client.close()


if __name__ == '__main__':
    processor = StreamProcessor()
    processor.run()
