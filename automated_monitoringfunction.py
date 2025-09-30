import boto3
import json
import time
from datetime import datetime

def lambda_handler(event, context):
    """
    Main Lambda handler - runs security analysis queries and publishes metrics to CloudWatch
    """
    athena = boto3.client('athena')
    cloudwatch = boto3.client('cloudwatch')
    s3 = boto3.client('s3')
    
    # Configuration
    database = 'web_security'
    s3_output = 's3://your-security-logs-bucket/athena-results/'
    
    def execute_athena_query(query, description="Query"):
        """Execute Athena query and wait for completion"""
        print(f"Executing {description}...")
        
        try:
            # Start query execution
            response = athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': database},
                ResultConfiguration={'OutputLocation': s3_output}
            )
            
            query_id = response['QueryExecutionId']
            print(f"Query ID: {query_id}")
            
            # Wait for query completion
            max_attempts = 30  # 5 minutes max
            attempt = 0
            
            while attempt < max_attempts:
                result = athena.get_query_execution(QueryExecutionId=query_id)
                status = result['QueryExecution']['Status']['State']
                
                if status == 'SUCCEEDED':
                    print(f"{description} completed successfully")
                    # Get results
                    results = athena.get_query_results(QueryExecutionId=query_id)
                    return results['ResultSet']['Rows']
                
                elif status == 'FAILED':
                    error_reason = result['QueryExecution']['Status']['StateChangeReason']
                    print(f"{description} failed: {error_reason}")
                    return []
                
                elif status == 'CANCELLED':
                    print(f"{description} was cancelled")
                    return []
                
                # Still running, wait and check again
                time.sleep(10)
                attempt += 1
            
            print(f"{description} timed out after {max_attempts * 10} seconds")
            return []
            
        except Exception as e:
            print(f"Error executing {description}: {str(e)}")
            return []
    
    def extract_count_from_results(results):
        """Extract count value from Athena results"""
        if len(results) > 1 and len(results[1]['Data']) > 0:
            try:
                return int(results[1]['Data'][0]['VarCharValue'])
            except (ValueError, KeyError, IndexError):
                return 0
        return 0
    
    # Query 1: Count suspicious IPs (potential DDoS sources)
    ddos_query = """
    SELECT COUNT(*) as suspicious_ips
    FROM (
        SELECT 
            regexp_extract(log_line, '^([0-9.]+)', 1) as ip_address,
            COUNT(*) as request_count
        FROM access_logs
        WHERE log_line IS NOT NULL
        GROUP BY regexp_extract(log_line, '^([0-9.]+)', 1)
        HAVING COUNT(*) > 20
    ) suspicious_activity
    """
    
    ddos_results = execute_athena_query(ddos_query, "DDoS Detection Query")
    suspicious_ip_count = extract_count_from_results(ddos_results)
    print(f"Suspicious IPs detected: {suspicious_ip_count}")
    
    # Query 2: Count intrusion attempts
    intrusion_query = """
    SELECT COUNT(*) as intrusion_attempts
    FROM access_logs
    WHERE log_line IS NOT NULL
      AND (
          regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%'
          OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%.env%'
          OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%config%'
          OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%backup%'
      )
    """
    
    intrusion_results = execute_athena_query(intrusion_query, "Intrusion Detection Query")
    intrusion_count = extract_count_from_results(intrusion_results)
    print(f"Intrusion attempts detected: {intrusion_count}")
    
    # Query 3: Count total requests and errors
    traffic_query = """
    SELECT 
        COUNT(*) as total_requests,
        COUNT(CASE WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 THEN 1 END) as error_requests
    FROM access_logs
    WHERE log_line IS NOT NULL
    """
    
    traffic_results = execute_athena_query(traffic_query, "Traffic Analysis Query")
    
    total_requests = 0
    error_requests = 0
    
    if len(traffic_results) > 1 and len(traffic_results[1]['Data']) >= 2:
        try:
            total_requests = int(traffic_results[1]['Data'][0]['VarCharValue'])
            error_requests = int(traffic_results[1]['Data'][1]['VarCharValue'])
        except (ValueError, KeyError, IndexError):
            pass
    
    # Calculate metrics
    error_rate = (error_requests / max(total_requests, 1)) * 100
    availability = max(0, 100 - error_rate)
    estimated_cost = suspicious_ip_count * 50 + intrusion_count * 10
    
    print(f"Total requests: {total_requests}")
    print(f"Error requests: {error_requests}")
    print(f"Error rate: {error_rate:.2f}%")
    print(f"Estimated cost impact: ${estimated_cost}")
    
    # Publish metrics to CloudWatch
    try:
        metrics = [
            {
                'MetricName': 'SuspiciousIPs',
                'Value': suspicious_ip_count,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'ThreatType', 'Value': 'DDoS'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            },
            {
                'MetricName': 'IntrusionAttempts',
                'Value': intrusion_count,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'ThreatType', 'Value': 'Intrusion'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            },
            {
                'MetricName': 'TotalRequests',
                'Value': total_requests,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'TrafficType', 'Value': 'All'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            },
            {
                'MetricName': 'ErrorRate',
                'Value': error_rate,
                'Unit': 'Percent',
                'Dimensions': [
                    {'Name': 'MetricType', 'Value': 'Availability'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            },
            {
                'MetricName': 'SystemAvailability',
                'Value': availability,
                'Unit': 'Percent',
                'Dimensions': [
                    {'Name': 'MetricType', 'Value': 'Uptime'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            },
            {
                'MetricName': 'SecurityCostImpact',
                'Value': estimated_cost,
                'Unit': 'None',
                'Dimensions': [
                    {'Name': 'ImpactType', 'Value': 'Financial'},
                    {'Name': 'Currency', 'Value': 'USD'}
                ]
            }
        ]
        
        # Publish metrics in batches (CloudWatch limit is 20 metrics per call)
        cloudwatch.put_metric_data(
            Namespace='Security/WebAnalytics',
            MetricData=metrics
        )
        
        print("Metrics published to CloudWatch successfully")
        
    except Exception as e:
        print(f"Error publishing metrics to CloudWatch: {str(e)}")
    
    # Send alerts if thresholds exceeded
    alerts_sent = []
    
    try:
        if suspicious_ip_count > 5:
            alert_message = f"🚨 HIGH ALERT: {suspicious_ip_count} suspicious IPs detected with high request volume!"
            send_alert(alert_message, "High Priority Security Alert")
            alerts_sent.append("DDoS Alert")
        
        if intrusion_count > 10:
            alert_message = f"🔓 INTRUSION ALERT: {intrusion_count} attempts to access sensitive endpoints detected!"
            send_alert(alert_message, "Intrusion Detection Alert") 
            alerts_sent.append("Intrusion Alert")
        
        if availability < 95:
            alert_message = f"📉 AVAILABILITY ALERT: System availability dropped to {availability:.1f}%"
            send_alert(alert_message, "System Availability Alert")
            alerts_sent.append("Availability Alert")
            
    except Exception as e:
        print(f"Error sending alerts: {str(e)}")
    
    # Return comprehensive results
    return {
        'statusCode': 200,
        'body': json.dumps({
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'suspicious_ips': suspicious_ip_count,
                'intrusion_attempts': intrusion_count, 
                'total_requests': total_requests,
                'error_requests': error_requests,
                'error_rate_percent': round(error_rate, 2),
                'availability_percent': round(availability, 2),
                'estimated_cost_impact_usd': estimated_cost
            },
            'alerts_sent': alerts_sent,
            'status': 'completed_successfully'
        })
    }

def send_alert(message, subject="Security Alert"):
    """Send alert via SNS (you'll need to create an SNS topic)"""
    try:
        sns = boto3.client('sns')
        
        # Replace with your actual SNS topic ARN
        topic_arn = 'arn:aws:sns:us-east-1:YOUR-ACCOUNT:security-alerts'
        
        response = sns.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject
        )
        
        print(f"Alert sent successfully: {subject}")
        return response
        
    except Exception as e:
        print(f"Failed to send alert: {str(e)}")
        # Fallback: at least log the alert
        print(f"ALERT: {subject} - {message}")
        return None