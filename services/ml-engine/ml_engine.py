import os
import time
import json
import numpy as np
from datetime import datetime, timedelta, timezone
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import hashlib

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
POSTGRES_USER = os.getenv('POSTGRES_USER', 'cloudhawk')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'cloudhawk_secure_2024')
POSTGRES_DB = os.getenv("POSTGRES_DB", "cloudhawk")
MODEL_RETRAIN_INTERVAL = int(os.getenv('MODEL_RETRAIN_INTERVAL', 3600))


class AnomalyDetectionEngine:
    """ML-powered anomaly detection using Isolation Forest"""
    
    def __init__(self):
        print("🧠 Initializing ML Anomaly Detection Engine...")
        
        # Wait for services
        time.sleep(20)
        
        # Initialize Redis
        self.redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=False  # We'll store binary model
        )
        
        # Initialize PostgreSQL
        self.pg_conn = psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            dbname=POSTGRES_DB
        )
        
        # ML models for different detection scenarios
        self.models = {
            'user_behavior': None,
            'ip_behavior': None,
            'temporal_patterns': None
        }
        
        self.scalers = {
            'user_behavior': StandardScaler(),
            'ip_behavior': StandardScaler(),
            'temporal_patterns': StandardScaler()
        }
        
        # Feature engineering
        self.event_types_map = {}
        self.user_map = {}
        self.ip_map = {}
        
        # Metrics
        self.anomalies_detected = 0
        self.models_trained = 0
        
        print("✅ ML Engine initialized successfully")

    def extract_features(self, events, feature_type='user_behavior'):
        """Extract features from events for ML training"""
        features = []
        
        for event in events:
            if feature_type == 'user_behavior':
                feature_vector = self._extract_user_features(event)
            elif feature_type == 'ip_behavior':
                feature_vector = self._extract_ip_features(event)
            elif feature_type == 'temporal_patterns':
                feature_vector = self._extract_temporal_features(event)
            else:
                continue
            
            if feature_vector:
                features.append(feature_vector)
        
        return np.array(features)

    def _extract_user_features(self, event):
        """Extract user behavior features"""
        try:
            event_data = event['event_data']
            
            # Get or create event type ID
            event_name = event_data.get('eventName', 'unknown')
            if event_name not in self.event_types_map:
                self.event_types_map[event_name] = len(self.event_types_map)
            
            # Get or create user ID
            user_name = event.get('user_name', 'unknown')
            if user_name not in self.user_map:
                self.user_map[user_name] = len(self.user_map)
            
            # Parse timestamp
            timestamp = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
            
            # Feature vector
            features = [
                self.event_types_map[event_name],  # Event type (encoded)
                self.user_map[user_name],  # User (encoded)
                timestamp.hour,  # Hour of day
                timestamp.weekday(),  # Day of week
                int(event.get('is_suspicious', False)),  # Suspicious flag
                len(event_data.get('userAgent', '')),  # User agent length
                1 if event.get('severity') == 'HIGH' else 0,  # High severity flag
                1 if event.get('severity') == 'CRITICAL' else 0,  # Critical severity flag
            ]
            
            return features
        except Exception as e:
            print(f"Error extracting user features: {e}")
            return None

    def _extract_ip_features(self, event):
        """Extract IP behavior features"""
        try:
            source_ip = event.get('source_ip', '0.0.0.0')
            
            # Get or create IP ID
            if source_ip not in self.ip_map:
                self.ip_map[source_ip] = len(self.ip_map)
            
            # Parse IP octets
            octets = [int(x) for x in source_ip.split('.')]
            
            # Parse timestamp
            timestamp = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
            
            # Feature vector
            features = [
                self.ip_map[source_ip],  # IP (encoded)
                octets[0],  # First octet
                octets[1],  # Second octet
                timestamp.hour,  # Hour of day
                int(event.get('is_suspicious', False)),  # Suspicious flag
                1 if event.get('severity') in ['HIGH', 'CRITICAL'] else 0,  # High severity
            ]
            
            return features
        except Exception as e:
            print(f"Error extracting IP features: {e}")
            return None

    def _extract_temporal_features(self, event):
        """Extract temporal pattern features"""
        try:
            event_data = event['event_data']
            raw_ts = event.get("time") or event.get("eventTime") or event.get("timestamp")

            if isinstance(raw_ts, (int, float)):
                timestamp = datetime.fromtimestamp(raw_ts, tz=timezone.utc)

            elif isinstance(raw_ts, str):
                try:
                    timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except Exception:
                    timestamp = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)

            else:
                timestamp = datetime.now(timezone.utc)
            
            # Time-based features
            features = [
                timestamp.hour,  # Hour
                timestamp.minute,  # Minute
                timestamp.weekday(),  # Day of week
                1 if 6 <= timestamp.hour <= 20 else 0,  # Business hours flag
                1 if timestamp.weekday() < 5 else 0,  # Weekday flag
                int(event.get('is_suspicious', False)),  # Suspicious flag
                1 if event.get('severity') in ['HIGH', 'CRITICAL'] else 0,  # High severity
            ]
            
            return features
        except Exception as e:
            print(f"Error extracting temporal features: {e}")
            return None

    def train_models(self):
        """Train anomaly detection models"""
        print("🎓 Training ML models...")
        
        try:
            # Fetch recent events for training
            with self.pg_conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get events from last 24 hours
                cur.execute("""
                    SELECT * FROM security_events
                    WHERE time > NOW() - INTERVAL '24 hours'
                    ORDER BY time DESC
                    LIMIT 10000;
                """)
                events = cur.fetchall()
            
            if len(events) < 100:
                print("⚠️  Not enough data for training (need at least 100 events)")
                return
            
            print(f"📊 Training on {len(events)} events")
            
            # Train each model
            for model_type in ['user_behavior', 'ip_behavior', 'temporal_patterns']:
                print(f"   Training {model_type} model...")
                
                # Extract features
                X = self.extract_features(events, feature_type=model_type)
                
                if len(X) < 50:
                    print(f"   ⚠️  Not enough features for {model_type}")
                    continue
                
                # Scale features
                X_scaled = self.scalers[model_type].fit_transform(X)
                
                # Train Isolation Forest
                model = IsolationForest(
                    contamination=0.1,  # Expect 10% anomalies
                    random_state=42,
                    n_estimators=100
                )
                model.fit(X_scaled)
                
                # Store model
                self.models[model_type] = model
                
                # Save to Redis
                self._save_model_to_redis(model_type, model, self.scalers[model_type])
                
                print(f"   ✅ {model_type} model trained")
            
            self.models_trained += 1
            print(f"✅ All models trained successfully (total: {self.models_trained})")
            
        except Exception as e:
            print(f"❌ Error training models: {e}")

    def _save_model_to_redis(self, model_type, model, scaler):
        """Save model to Redis"""
        try:
            # Serialize model
            model_bytes = pickle.dumps({
                'model': model,
                'scaler': scaler,
                'event_types_map': self.event_types_map,
                'user_map': self.user_map,
                'ip_map': self.ip_map,
                'trained_at': datetime.now(timezone.utc).isoformat()
            })
            
            # Store in Redis
            self.redis_client.set(f'ml_model:{model_type}', model_bytes)
            
            # Store metadata
            metadata = {
                'model_type': model_type,
                'trained_at': datetime.now(timezone.utc).isoformat(),
                'size_bytes': len(model_bytes)
            }
            self.redis_client.set(
                f'ml_model_meta:{model_type}',
                json.dumps(metadata)
            )
            
        except Exception as e:
            print(f"Error saving model to Redis: {e}")

    def load_models_from_redis(self):
        """Load models from Redis"""
        try:
            for model_type in ['user_behavior', 'ip_behavior', 'temporal_patterns']:
                model_bytes = self.redis_client.get(f'ml_model:{model_type}')
                
                if model_bytes:
                    data = pickle.loads(model_bytes)
                    self.models[model_type] = data['model']
                    self.scalers[model_type] = data['scaler']
                    self.event_types_map = data.get('event_types_map', {})
                    self.user_map = data.get('user_map', {})
                    self.ip_map = data.get('ip_map', {})
                    
                    print(f"✅ Loaded {model_type} model from Redis")
        except Exception as e:
            print(f"⚠️  Could not load models from Redis: {e}")

    def detect_anomalies(self):
        """Detect anomalies in recent events"""
        try:
            # Check if models are trained
            if not any(self.models.values()):
                print("⚠️  Models not trained yet")
                return
            
            # Get recent unanalyzed events
            with self.pg_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM security_events
                    WHERE time > NOW() - INTERVAL '5 minutes'
                    AND event_id NOT IN (
                        SELECT DISTINCT event_id FROM detected_threats
                        WHERE threat_type = 'ml_anomaly'
                    )
                    ORDER BY time DESC
                    LIMIT 1000;
                """)
                events = cur.fetchall()
            
            if not events:
                return
            
            print(f"🔍 Analyzing {len(events)} events for anomalies...")
            
            anomalies_found = 0
            
            # Check each model
            for model_type, model in self.models.items():
                if model is None:
                    continue
                
                # Extract features
                X = self.extract_features(events, feature_type=model_type)
                
                if len(X) == 0:
                    continue
                
                # Scale features
                X_scaled = self.scalers[model_type].transform(X)
                
                # Predict anomalies (-1 for anomaly, 1 for normal)
                predictions = model.predict(X_scaled)
                anomaly_scores = model.score_samples(X_scaled)
                
                # Find anomalies
                for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
                    if pred == -1 and i < len(events):  # Anomaly detected
                        event = events[i]
                        severity = self._calculate_anomaly_severity(score)
                        
                        # Store anomaly
                        self._store_anomaly(event, model_type, score, severity)
                        anomalies_found += 1
            
            if anomalies_found > 0:
                self.anomalies_detected += anomalies_found
                print(f"🚨 Detected {anomalies_found} anomalies "
                      f"(total: {self.anomalies_detected})")
            
        except Exception as e:
            print(f"❌ Error detecting anomalies: {e}")

    def _calculate_anomaly_severity(self, score):
        """Calculate severity based on anomaly score"""
        # Isolation Forest scores are typically between -0.5 and 0.5
        # More negative = more anomalous
        if score < -0.3:
            return 'CRITICAL'
        elif score < -0.2:
            return 'HIGH'
        elif score < -0.1:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _store_anomaly(self, event, model_type, score, severity):
        """Store detected anomaly"""
        try:
            with self.pg_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO detected_threats 
                    (time, event_id, threat_type, severity, description, 
                     mitre_attack, user_name, source_ip, additional_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    event['time'],
                    event['event_id'],
                    'ml_anomaly',
                    severity,
                    f'ML-detected anomaly in {model_type} (score: {score:.3f})',
                    'T1087 - Account Discovery',
                    event.get('user_name'),
                    event.get('source_ip'),
                    json.dumps({
                        'model_type': model_type,
                        'anomaly_score': float(score),
                        'detection_method': 'isolation_forest'
                    })
                ))
                self.pg_conn.commit()
            
            # Publish alert if high severity
            if severity in ['HIGH', 'CRITICAL']:
                alert = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'type': 'ml_anomaly',
                    'severity': severity,
                    'event_id': event['event_id'],
                    'model_type': model_type,
                    'score': float(score),
                    'event_name': event['event_name'],
                    'user': event.get('user_name'),
                    'source_ip': event.get('source_ip')
                }
                
                redis_client = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    decode_responses=True
                )
                redis_client.publish('security_alerts', json.dumps(alert))
                redis_client.close()
                
        except Exception as e:
            print(f"Error storing anomaly: {e}")

    def run(self):
        """Main ML engine loop"""
        print("🚀 ML Anomaly Detection Engine started")
        print(f"🔄 Model retrain interval: {MODEL_RETRAIN_INTERVAL} seconds")
        print("-" * 60)
        
        # Try to load existing models
        self.load_models_from_redis()
        
        last_training = time.time()
        
        try:
            while True:
                # Check if it's time to retrain
                if time.time() - last_training >= MODEL_RETRAIN_INTERVAL:
                    self.train_models()
                    last_training = time.time()
                
                # Detect anomalies
                self.detect_anomalies()
                
                # Sleep before next iteration
                time.sleep(30)
                
        except KeyboardInterrupt:
            print("\n⏹️  ML Engine stopped")
        finally:
            self.pg_conn.close()


if __name__ == '__main__':
    engine = AnomalyDetectionEngine()
    engine.run()
