import boto3
import json
import random
from datetime import datetime

def lambda_handler(event, context):
    """
    Generates realistic web server logs with attack simulation
    """
    s3 = boto3.client('s3')
    
    # Define attack patterns based on real-world observations
    attack_scenarios = {
        'ddos_sources': [
            '45.32.15.123',    # Known botnet IP
            '198.51.100.42',   # Scanning service
            '185.220.101.45'   # TOR exit node
        ],
        'legitimate_sources': [
            '192.168.1.100',   # Office network
            '10.0.0.50',       # VPN users
            '172.16.0.25'      # Partner network
        ],
        'malicious_agents': [
            'sqlmap/1.0',
            'Nikto/2.1.6', 
            'python-requests/2.25.1',
            'curl/7.68.0'
        ],
        'target_endpoints': [
            '/wp-admin/login.php',
            '/admin/',
            '/.env',
            '/config.php',
            '/backup/',
            '/phpmyadmin/'
        ],
        'normal_endpoints': [
            '/',
            '/about/',
            '/services/',
            '/contact/',
            '/blog/',
            '/products/'
        ]
    }
    
    logs = []
    
    for _ in range(100):  # Generate 100 log entries per run
        # 15% chance of malicious traffic (realistic ratio)
        is_malicious = random.random() < 0.15
        
        if is_malicious:
            # Simulate attack traffic
            source_ip = random.choice(attack_scenarios['ddos_sources'])
            endpoint = random.choice(attack_scenarios['target_endpoints'])
            user_agent = random.choice(attack_scenarios['malicious_agents'])
            
            # Attackers often get blocked or cause errors
            status_code = random.choices(
                [404, 403, 401, 500, 200], 
                weights=[40, 25, 20, 10, 5]
            )[0]
            
            # Smaller response sizes for failed requests
            response_size = random.randint(200, 1000)
            method = random.choice(['GET', 'POST', 'PUT'])
            
        else:
            # Simulate legitimate traffic
            source_ip = random.choice(attack_scenarios['legitimate_sources'])
            endpoint = random.choice(attack_scenarios['normal_endpoints'])
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            # Legitimate traffic mostly succeeds
            status_code = random.choices(
                [200, 301, 302, 404], 
                weights=[85, 5, 5, 5]
            )[0]
            
            # Larger response sizes for successful pages
            response_size = random.randint(2000, 10000)
            method = 'GET'
        
        # Generate log entry in standard Apache/Nginx format
        timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
        referrer = '-' if is_malicious else 'https://www.google.com/search'
        
        log_entry = (
            f'{source_ip} - - [{timestamp}] '
            f'"{method} {endpoint} HTTP/1.1" {status_code} {response_size} '
            f'"{referrer}" "{user_agent}"'
        )
        
        logs.append(log_entry)
    
    # Save to S3 with timestamp
    log_content = '\n'.join(logs)
    timestamp_key = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    s3.put_object(
        Bucket='your-security-logs-bucket',
        Key=f'raw-logs/access_log_{timestamp_key}.log',
        Body=log_content
    )
    
    print(f"Generated {len(logs)} log entries")
    return {
        'statusCode': 200,
        'body': json.dumps(f'Generated {len(logs)} log entries')
    }