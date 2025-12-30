import boto3
import json
import time
import os
from datetime import datetime, timedelta
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def lambda_handler(event, context):
    """
    Lambda de monitoring automatisé - Analyse les logs et publie des métriques CloudWatch
    Compatible avec la structure créée par le générateur de logs
    """
    
    # Clients AWS
    athena = boto3.client('athena')
    cloudwatch = boto3.client('cloudwatch')
    sns = boto3.client('sns')
    
    # Configuration depuis les variables d'environnement
    DATABASE = os.environ.get('DATABASE', 'web_security_logs')
    TABLE = os.environ.get('TABLE', 'access_logs')
    S3_OUTPUT = os.environ.get('S3_OUTPUT_LOCATION', 's3://athena-results/monitoring/')
    NAMESPACE = os.environ.get('CLOUDWATCH_NAMESPACE', 'WebSecurity/Monitoring')
    SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
    
    logger.info(f"Starting monitoring analysis - Database: {DATABASE}, Table: {TABLE}")
    
    # Fonction pour exécuter une requête Athena
    def execute_athena_query(query, query_name):
        """Exécute une requête Athena et retourne les résultats"""
        try:
            logger.info(f"Executing query: {query_name}")
            
            # Démarrer l'exécution
            response = athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': DATABASE},
                ResultConfiguration={'OutputLocation': S3_OUTPUT}
            )
            
            query_id = response['QueryExecutionId']
            logger.info(f"Query ID: {query_id}")
            
            # Attendre la fin de l'exécution
            max_attempts = 30
            for attempt in range(max_attempts):
                status_response = athena.get_query_execution(QueryExecutionId=query_id)
                status = status_response['QueryExecution']['Status']['State']
                
                if status == 'SUCCEEDED':
                    logger.info(f"{query_name} completed successfully")
                    results = athena.get_query_results(QueryExecutionId=query_id)
                    return results
                    
                elif status in ['FAILED', 'CANCELLED']:
                    reason = status_response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                    logger.error(f"{query_name} failed: {reason}")
                    return None
                
                time.sleep(2)
            
            logger.error(f"{query_name} timed out")
            return None
            
        except Exception as e:
            logger.error(f"Error executing {query_name}: {str(e)}")
            return None
    
    # Fonction pour parser les résultats Athena
    def parse_athena_results(results):
        """Parse les résultats Athena en format dict"""
        if not results or 'ResultSet' not in results:
            return []
        
        rows = results['ResultSet']['Rows']
        if len(rows) <= 1:
            return []
        
        # Extraire les headers
        headers = [col['VarCharValue'] for col in rows[0]['Data']]
        
        # Extraire les données
        data = []
        for row in rows[1:]:
            row_data = {}
            for i, cell in enumerate(row['Data']):
                value = cell.get('VarCharValue', '0')
                # Convertir en nombre si possible
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except:
                    pass
                row_data[headers[i]] = value
            data.append(row_data)
        
        return data
    
    # Dictionnaire pour stocker les métriques
    metrics_to_publish = []
    alerts_to_send = []
    
    # ============================================
    # REQUÊTE 1: Détection DDoS (IPs suspectes)
    # ============================================
    logger.info("Analyzing DDoS patterns...")
    
    ddos_query = f"""
    SELECT 
        ip,
        country,
        COUNT(*) as request_count
    FROM {DATABASE}.{TABLE}
    WHERE from_iso8601_timestamp(timestamp) >= current_timestamp - interval '1' hour
    GROUP BY ip, country
    HAVING COUNT(*) > 100
    ORDER BY request_count DESC
    LIMIT 20
    """
    
    ddos_results = execute_athena_query(ddos_query, "DDoS Detection")
    ddos_data = parse_athena_results(ddos_results) if ddos_results else []
    
    ddos_ip_count = len(ddos_data)
    max_requests = max([row['request_count'] for row in ddos_data], default=0)
    
    logger.info(f"DDoS Analysis: {ddos_ip_count} suspicious IPs detected, max requests: {max_requests}")
    
    metrics_to_publish.append({
        'MetricName': 'DDosIPsDetected',
        'Value': ddos_ip_count,
        'Unit': 'Count',
        'Timestamp': datetime.utcnow()
    })
    
    metrics_to_publish.append({
        'MetricName': 'MaxRequestsPerHour',
        'Value': max_requests,
        'Unit': 'Count',
        'Timestamp': datetime.utcnow()
    })
    
    # Alert DDoS
    if ddos_ip_count >= 3:
        alert_msg = f"🚨 DDoS ALERT: {ddos_ip_count} IPs with >100 requests/hour detected!\n"
        alert_msg += f"Max requests from single IP: {max_requests}\n"
        if ddos_data:
            alert_msg += f"Top offender: {ddos_data[0]['ip']} ({ddos_data[0]['country']}) - {ddos_data[0]['request_count']} requests"
        alerts_to_send.append(('DDoS Detection Alert', alert_msg))
    
    # ============================================
    # REQUÊTE 2: Analyse des Attaques par Type
    # ============================================
    logger.info("Analyzing attack patterns...")
    
    attacks_query = f"""
    SELECT 
        attack_type,
        COUNT(*) as attack_count,
        COUNT(DISTINCT ip) as unique_attackers
    FROM {DATABASE}.{TABLE}
    WHERE attack_type != 'normal'
        AND from_iso8601_timestamp(timestamp) >= current_timestamp - interval '1' hour
    GROUP BY attack_type
    ORDER BY attack_count DESC
    """
    
    attacks_results = execute_athena_query(attacks_query, "Attack Analysis")
    attacks_data = parse_athena_results(attacks_results) if attacks_results else []
    
    total_attacks = sum([row['attack_count'] for row in attacks_data])
    total_attackers = sum([row['unique_attackers'] for row in attacks_data])
    
    logger.info(f"Attack Analysis: {total_attacks} attacks from {total_attackers} unique IPs")
    
    metrics_to_publish.append({
        'MetricName': 'TotalAttacks',
        'Value': total_attacks,
        'Unit': 'Count',
        'Timestamp': datetime.utcnow()
    })
    
    metrics_to_publish.append({
        'MetricName': 'UniqueAttackers',
        'Value': total_attackers,
        'Unit': 'Count',
        'Timestamp': datetime.utcnow()
    })
    
    # Métriques par type d'attaque
    for attack in attacks_data:
        metrics_to_publish.append({
            'MetricName': 'AttacksByType',
            'Value': attack['attack_count'],
            'Unit': 'Count',
            'Timestamp': datetime.utcnow(),
            'Dimensions': [
                {'Name': 'AttackType', 'Value': str(attack['attack_type'])}
            ]
        })
    
    # Alert Attaques
    if total_attacks > 100:
        alert_msg = f"🔴 HIGH ATTACK VOLUME: {total_attacks} attacks detected in the last hour!\n"
        alert_msg += f"Unique attackers: {total_attackers}\n"
        alert_msg += "Attack breakdown:\n"
        for attack in attacks_data[:5]:
            alert_msg += f"  - {attack['attack_type']}: {attack['attack_count']} attempts\n"
        alerts_to_send.append(('High Attack Volume Alert', alert_msg))
    
    # ============================================
    # REQUÊTE 3: Taux d'Erreur et Disponibilité
    # ============================================
    logger.info("Analyzing error rates...")
    
    error_query = f"""
    SELECT 
        COUNT(*) as total_requests,
        COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_requests,
        COUNT(CASE WHEN status_code >= 500 THEN 1 END) as server_errors,
        COUNT(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 END) as client_errors
    FROM {DATABASE}.{TABLE}
    WHERE from_iso8601_timestamp(timestamp) >= current_timestamp - interval '1' hour
    """
    
    error_results = execute_athena_query(error_query, "Error Rate Analysis")
    error_data = parse_athena_results(error_results) if error_results else []
    
    if error_data:
        total_requests = error_data[0].get('total_requests', 0)
        error_requests = error_data[0].get('error_requests', 0)
        server_errors = error_data[0].get('server_errors', 0)
        client_errors = error_data[0].get('client_errors', 0)
        
        error_rate = (error_requests / max(total_requests, 1)) * 100
        availability = max(0, 100 - error_rate)
        
        logger.info(f"Traffic: {total_requests} requests, {error_requests} errors ({error_rate:.2f}%)")
        
        metrics_to_publish.extend([
            {
                'MetricName': 'TotalRequests',
                'Value': total_requests,
                'Unit': 'Count',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'ErrorRequests',
                'Value': error_requests,
                'Unit': 'Count',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'ServerErrors',
                'Value': server_errors,
                'Unit': 'Count',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'ClientErrors',
                'Value': client_errors,
                'Unit': 'Count',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'ErrorRate',
                'Value': error_rate,
                'Unit': 'Percent',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'SystemAvailability',
                'Value': availability,
                'Unit': 'Percent',
                'Timestamp': datetime.utcnow()
            }
        ])
        
        # Alert Disponibilité
        if availability < 95:
            alert_msg = f"⚠️ LOW AVAILABILITY: System availability at {availability:.1f}%\n"
            alert_msg += f"Total requests: {total_requests}\n"
            alert_msg += f"Error requests: {error_requests}\n"
            alert_msg += f"Server errors (5xx): {server_errors}\n"
            alert_msg += f"Client errors (4xx): {client_errors}"
            alerts_to_send.append(('Low Availability Alert', alert_msg))
    
    # ============================================
    # REQUÊTE 4: Performance (Temps de Réponse)
    # ============================================
    logger.info("Analyzing performance metrics...")
    
    perf_query = f"""
    SELECT 
        ROUND(AVG(response_time), 2) as avg_response_time,
        ROUND(percentile_approx(response_time, 0.50), 2) as p50_response_time,
        ROUND(percentile_approx(response_time, 0.95), 2) as p95_response_time,
        ROUND(percentile_approx(response_time, 0.99), 2) as p99_response_time,
        MAX(response_time) as max_response_time
    FROM {DATABASE}.{TABLE}
    WHERE attack_type = 'normal'
        AND status_code = 200
        AND from_iso8601_timestamp(timestamp) >= current_timestamp - interval '1' hour
    """
    
    perf_results = execute_athena_query(perf_query, "Performance Analysis")
    perf_data = parse_athena_results(perf_results) if perf_results else []
    
    if perf_data:
        avg_time = perf_data[0].get('avg_response_time', 0)
        p95_time = perf_data[0].get('p95_response_time', 0)
        p99_time = perf_data[0].get('p99_response_time', 0)
        max_time = perf_data[0].get('max_response_time', 0)
        
        logger.info(f"Performance: Avg={avg_time}ms, P95={p95_time}ms, P99={p99_time}ms")
        
        metrics_to_publish.extend([
            {
                'MetricName': 'AverageResponseTime',
                'Value': avg_time,
                'Unit': 'Milliseconds',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'P95ResponseTime',
                'Value': p95_time,
                'Unit': 'Milliseconds',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'P99ResponseTime',
                'Value': p99_time,
                'Unit': 'Milliseconds',
                'Timestamp': datetime.utcnow()
            },
            {
                'MetricName': 'MaxResponseTime',
                'Value': max_time,
                'Unit': 'Milliseconds',
                'Timestamp': datetime.utcnow()
            }
        ])
        
        # Alert Performance
        if p95_time > 2000:
            alert_msg = f"🐢 SLOW PERFORMANCE: P95 response time at {p95_time}ms\n"
            alert_msg += f"Average: {avg_time}ms\n"
            alert_msg += f"P99: {p99_time}ms\n"
            alert_msg += f"Max: {max_time}ms"
            alerts_to_send.append(('Performance Degradation Alert', alert_msg))
    
    # ============================================
    # REQUÊTE 5: Analyse Géographique
    # ============================================
    logger.info("Analyzing geographic distribution...")
    
    geo_query = f"""
    SELECT 
        country,
        COUNT(*) as requests,
        COUNT(CASE WHEN attack_type != 'normal' THEN 1 END) as attacks
    FROM {DATABASE}.{TABLE}
    WHERE from_iso8601_timestamp(timestamp) >= current_timestamp - interval '1' hour
    GROUP BY country
    ORDER BY attacks DESC
    LIMIT 10
    """
    
    geo_results = execute_athena_query(geo_query, "Geographic Analysis")
    geo_data = parse_athena_results(geo_results) if geo_results else []
    
    # Métriques par pays
    for country_data in geo_data:
        metrics_to_publish.append({
            'MetricName': 'AttacksByCountry',
            'Value': country_data['attacks'],
            'Unit': 'Count',
            'Timestamp': datetime.utcnow(),
            'Dimensions': [
                {'Name': 'Country', 'Value': str(country_data['country'])}
            ]
        })
    
    # ============================================
    # PUBLICATION DES MÉTRIQUES CLOUDWATCH
    # ============================================
    logger.info(f"Publishing {len(metrics_to_publish)} metrics to CloudWatch...")
    
    try:
        # CloudWatch accepte max 20 métriques par appel
        for i in range(0, len(metrics_to_publish), 20):
            batch = metrics_to_publish[i:i+20]
            cloudwatch.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=batch
            )
            logger.info(f"Published batch {i//20 + 1} ({len(batch)} metrics)")
        
        logger.info("✅ All metrics published successfully")
        
    except Exception as e:
        logger.error(f"❌ Error publishing metrics: {str(e)}")
    
    # ============================================
    # ENVOI DES ALERTES SNS
    # ============================================
    if alerts_to_send and SNS_TOPIC_ARN:
        logger.info(f"Sending {len(alerts_to_send)} alerts via SNS...")
        
        for subject, message in alerts_to_send:
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=subject,
                    Message=message
                )
                logger.info(f"✅ Alert sent: {subject}")
            except Exception as e:
                logger.error(f"❌ Failed to send alert '{subject}': {str(e)}")
    elif alerts_to_send:
        logger.warning(f"⚠️ {len(alerts_to_send)} alerts generated but no SNS_TOPIC_ARN configured")
        for subject, message in alerts_to_send:
            logger.info(f"ALERT: {subject}")
            logger.info(f"Message: {message}")
    
    # ============================================
    # CRÉATION/MISE À JOUR DU DASHBOARD (optionnel)
    # ============================================
    if event.get('create_dashboard', False):
        logger.info("Creating/updating CloudWatch dashboard...")
        try:
            create_cloudwatch_dashboard(cloudwatch, NAMESPACE)
        except Exception as e:
            logger.error(f"Error creating dashboard: {str(e)}")
    
    # ============================================
    # RETOUR DU RÉSUMÉ
    # ============================================
    summary = {
        'timestamp': datetime.utcnow().isoformat(),
        'metrics_published': len(metrics_to_publish),
        'alerts_sent': len(alerts_to_send),
        'summary': {
            'ddos_ips': ddos_ip_count,
            'total_attacks': total_attacks,
            'unique_attackers': total_attackers,
            'total_requests': error_data[0]['total_requests'] if error_data else 0,
            'error_rate': round(error_rate, 2) if error_data else 0,
            'avg_response_time': perf_data[0]['avg_response_time'] if perf_data else 0
        }
    }
    
    logger.info(f"✅ Monitoring completed: {json.dumps(summary, indent=2)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(summary)
    }


def create_cloudwatch_dashboard(cloudwatch, namespace):
    """Crée ou met à jour le dashboard CloudWatch"""
    
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [namespace, "TotalAttacks"],
                        [".", "UniqueAttackers"],
                        [".", "DDosIPsDetected"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": os.environ.get('AWS_REGION', 'us-east-1'),
                    "title": "Security Threats",
                    "period": 300,
                    "yAxis": {
                        "left": {
                            "label": "Count"
                        }
                    }
                }
            },
            {
                "type": "metric",
                "x": 12,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [namespace, "ErrorRate"],
                        [".", "SystemAvailability"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": os.environ.get('AWS_REGION', 'us-east-1'),
                    "title": "System Health",
                    "period": 300,
                    "yAxis": {
                        "left": {
                            "label": "Percent",
                            "min": 0,
                            "max": 100
                        }
                    }
                }
            },
            {
                "type": "metric",
                "x": 0,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [namespace, "AverageResponseTime"],
                        [".", "P95ResponseTime"],
                        [".", "P99ResponseTime"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": os.environ.get('AWS_REGION', 'us-east-1'),
                    "title": "Performance Metrics",
                    "period": 300,
                    "yAxis": {
                        "left": {
                            "label": "Milliseconds"
                        }
                    }
                }
            },
            {
                "type": "metric",
                "x": 12,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [namespace, "TotalRequests"],
                        [".", "ErrorRequests"],
                        [".", "ServerErrors"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": os.environ.get('AWS_REGION', 'us-east-1'),
                    "title": "Traffic & Errors",
                    "period": 300,
                    "yAxis": {
                        "left": {
                            "label": "Count"
                        }
                    }
                }
            }
        ]
    }
    
    try:
        cloudwatch.put_dashboard(
            DashboardName='WebSecurity-Monitoring-Dashboard',
            DashboardBody=json.dumps(dashboard_body)
        )
        logger.info("✅ Dashboard created/updated successfully")
    except Exception as e:
        logger.error(f"❌ Error creating dashboard: {str(e)}")
        raise
