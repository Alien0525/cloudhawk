import json
import random
import time
from datetime import datetime, timezone
from kafka import KafkaProducer
import os
import uuid

# Kafka configuration
KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9094')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'cloudtrail-events')
EVENT_RATE = int(os.getenv('EVENT_RATE', 100))

# AWS Service simulation data
AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'eu-central-1']
AWS_SERVICES = ['ec2', 's3', 'iam', 'lambda', 'rds', 'cloudformation', 'cloudwatch']

# Normal event types
NORMAL_EVENTS = [
    'DescribeInstances', 'ListBuckets', 'GetObject', 'PutObject',
    'InvokeFunction', 'DescribeDBInstances', 'GetMetricStatistics',
    'DescribeSecurityGroups', 'DescribeVolumes', 'GetBucketPolicy'
]

# Suspicious event types (lower probability)
SUSPICIOUS_EVENTS = [
    'DeleteBucket', 'DeleteDBInstance', 'CreateAccessKey',
    'AttachUserPolicy', 'PutBucketPolicy', 'ModifyDBInstance',
    'AuthorizeSecurityGroupIngress', 'CreateUser', 'DeleteUser',
    'StopInstances', 'TerminateInstances'
]

# Attack patterns
ATTACK_PATTERNS = {
    'credential_access': [
        'GetAccountPasswordPolicy', 'CreateAccessKey', 'CreateLoginProfile',
        'UpdateAccessKey', 'ListAccessKeys'
    ],
    'data_exfiltration': [
        'GetObject', 'ListBuckets', 'GetBucketLocation',
        'CreateSnapshot', 'CopySnapshot'
    ],
    'privilege_escalation': [
        'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy',
        'CreatePolicyVersion', 'SetDefaultPolicyVersion'
    ],
    'persistence': [
        'CreateUser', 'CreateAccessKey', 'CreateRole',
        'AttachRolePolicy', 'CreateFunction'
    ],
    'impact': [
        'DeleteBucket', 'DeleteDBInstance', 'TerminateInstances',
        'DeleteVolume', 'DeleteSnapshot'
    ]
}

# User agents (mix normal and suspicious)
USER_AGENTS = [
    'aws-cli/2.13.25 Python/3.11.5',
    'aws-sdk-go/1.45.11',
    'Boto3/1.28.57 Python/3.9.7',
    'aws-cli/1.29.57 Python/3.9.7',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',  # Suspicious
    'python-requests/2.31.0',
]

# Source IPs (include some malicious IPs)
NORMAL_IPS = [
    '10.0.1.' + str(i) for i in range(1, 50)
] + [
    '172.16.0.' + str(i) for i in range(1, 30)
]

SUSPICIOUS_IPS = [
    '185.220.101.1',  # Tor exit node
    '45.142.120.50',  # Known malicious
    '89.248.165.123',  # Suspicious geo
    '103.253.145.28',  # High-risk country
]

# User accounts
NORMAL_USERS = [f'user-{i:03d}' for i in range(1, 21)]
ADMIN_USERS = ['admin', 'root', 'cloudadmin', 'security-admin']
SUSPICIOUS_USERS = ['temp-user', 'contractor-temp', 'backup-script']


class CloudTrailSimulator:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all',
            retries=3
        )
        self.event_count = 0
        self.attack_sequence_active = False
        self.attack_type = None

    def generate_event(self):
        """Generate a CloudTrail event"""
        
        # 5% chance to start an attack sequence
        if not self.attack_sequence_active and random.random() < 0.05:
            self.attack_sequence_active = True
            self.attack_type = random.choice(list(ATTACK_PATTERNS.keys()))
            print(f"🚨 Starting attack sequence: {self.attack_type}")

        # Generate event based on state
        if self.attack_sequence_active:
            event = self._generate_attack_event()
            # 20% chance to end attack sequence
            if random.random() < 0.2:
                self.attack_sequence_active = False
                print(f"✅ Attack sequence ended: {self.attack_type}")
        else:
            event = self._generate_normal_event()

        return event

    def _generate_normal_event(self):
        """Generate a normal CloudTrail event"""
        event_name = random.choice(NORMAL_EVENTS)
        source_ip = random.choice(NORMAL_IPS)
        user = random.choice(NORMAL_USERS)
        user_agent = random.choice(USER_AGENTS[:4])  # Normal user agents

        return self._create_cloudtrail_event(
            event_name=event_name,
            source_ip=source_ip,
            user=user,
            user_agent=user_agent,
            is_suspicious=False
        )

    def _generate_attack_event(self):
        """Generate a suspicious/attack event"""
        event_name = random.choice(ATTACK_PATTERNS[self.attack_type])
        
        # Mix of suspicious IPs
        source_ip = random.choice(SUSPICIOUS_IPS + NORMAL_IPS[:5])
        
        # Suspicious users or compromised accounts
        user = random.choice(SUSPICIOUS_USERS + ADMIN_USERS)
        
        # Mix of user agents, including suspicious ones
        user_agent = random.choice(USER_AGENTS)

        return self._create_cloudtrail_event(
            event_name=event_name,
            source_ip=source_ip,
            user=user,
            user_agent=user_agent,
            is_suspicious=True,
            attack_type=self.attack_type
        )

    def _create_cloudtrail_event(self, event_name, source_ip, user, user_agent, 
                                  is_suspicious=False, attack_type=None):
        """Create a CloudTrail-like event structure"""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        region = random.choice(AWS_REGIONS)
        
        # Determine service from event name
        service = self._get_service_from_event(event_name)

        event = {
            'eventVersion': '1.08',
            'eventID': event_id,
            'eventTime': timestamp,
            'eventName': event_name,
            'eventSource': f'{service}.amazonaws.com',
            'awsRegion': region,
            'sourceIPAddress': source_ip,
            'userAgent': user_agent,
            'userIdentity': {
                'type': 'IAMUser',
                'principalId': f'AIDA{random.randint(100000000000, 999999999999)}',
                'arn': f'arn:aws:iam::123456789012:user/{user}',
                'accountId': '123456789012',
                'userName': user
            },
            'requestParameters': self._generate_request_params(event_name, service),
            'responseElements': self._generate_response_elements(event_name),
            'requestID': str(uuid.uuid4()),
            'eventType': 'AwsApiCall',
            'recipientAccountId': '123456789012',
            'readOnly': event_name.startswith(('Describe', 'List', 'Get')),
            'resources': self._generate_resources(service, region),
            
            # CloudHawk custom fields
            'cloudhawk': {
                'is_suspicious': is_suspicious,
                'attack_type': attack_type,
                'severity': self._calculate_severity(event_name, is_suspicious),
                'mitre_attack': self._map_to_mitre(event_name, attack_type)
            }
        }

        return event

    def _get_service_from_event(self, event_name):
        """Map event name to AWS service"""
        service_map = {
            'Instance': 'ec2',
            'Bucket': 's3',
            'Object': 's3',
            'User': 'iam',
            'Policy': 'iam',
            'AccessKey': 'iam',
            'Role': 'iam',
            'Function': 'lambda',
            'DB': 'rds',
            'Volume': 'ec2',
            'SecurityGroup': 'ec2',
            'Snapshot': 'ec2'
        }
        
        for key, service in service_map.items():
            if key in event_name:
                return service
        
        return random.choice(AWS_SERVICES)

    def _generate_request_params(self, event_name, service):
        """Generate realistic request parameters"""
        params = {}
        
        if 'Bucket' in event_name:
            params['bucketName'] = f'production-data-{random.randint(1, 10)}'
        elif 'Instance' in event_name:
            params['instancesSet'] = {
                'items': [{
                    'instanceId': f'i-{random.randint(10000000, 99999999):08x}'
                }]
            }
        elif 'User' in event_name or 'AccessKey' in event_name:
            params['userName'] = f'user-{random.randint(1, 100)}'
        elif 'Policy' in event_name:
            params['policyArn'] = f'arn:aws:iam::aws:policy/AdministratorAccess'
        
        return params

    def _generate_response_elements(self, event_name):
        """Generate response elements"""
        if event_name.startswith(('Describe', 'List', 'Get')):
            return None
        
        return {
            'requestId': str(uuid.uuid4()),
            '_return': True
        }

    def _generate_resources(self, service, region):
        """Generate resource information"""
        resource_id = f'{service}-{random.randint(100000, 999999)}'
        
        return [{
            'ARN': f'arn:aws:{service}:{region}:123456789012:{service}/{resource_id}',
            'accountId': '123456789012',
            'type': f'AWS::{service.upper()}::{service.capitalize()}'
        }]

    def _calculate_severity(self, event_name, is_suspicious):
        """Calculate event severity"""
        if is_suspicious:
            if any(x in event_name for x in ['Delete', 'Terminate', 'Modify']):
                return 'CRITICAL'
            elif any(x in event_name for x in ['Create', 'Attach', 'Put']):
                return 'HIGH'
            else:
                return 'MEDIUM'
        else:
            return 'LOW'

    def _map_to_mitre(self, event_name, attack_type):
        """Map to MITRE ATT&CK framework"""
        mitre_map = {
            'credential_access': 'T1078 - Valid Accounts',
            'data_exfiltration': 'T1537 - Transfer Data to Cloud Account',
            'privilege_escalation': 'T1548 - Abuse Elevation Control',
            'persistence': 'T1098 - Account Manipulation',
            'impact': 'T1485 - Data Destruction'
        }
        
        return mitre_map.get(attack_type, 'T1059 - Command and Scripting')

    def send_event(self, event):
        """Send event to Kafka"""
        try:
            future = self.producer.send(KAFKA_TOPIC, value=event)
            future.get(timeout=10)
            self.event_count += 1
            
            if self.event_count % 100 == 0:
                print(f"📊 Sent {self.event_count} events. "
                      f"Last event: {event['eventName']} from {event['sourceIPAddress']}")
            
            return True
        except Exception as e:
            print(f"❌ Error sending event: {e}")
            return False

    def run(self):
        """Main simulation loop"""
        print(f"🚀 CloudHawk Event Simulator started")
        print(f"📡 Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
        print(f"📨 Topic: {KAFKA_TOPIC}")
        print(f"⚡ Event rate: {EVENT_RATE} events/second")
        print("-" * 60)

        # Wait for Kafka to be ready
        time.sleep(10)

        interval = 1.0 / EVENT_RATE

        try:
            while True:
                event = self.generate_event()
                self.send_event(event)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n⏹️  Simulator stopped")
        finally:
            self.producer.close()


if __name__ == '__main__':
    simulator = CloudTrailSimulator()
    simulator.run()
