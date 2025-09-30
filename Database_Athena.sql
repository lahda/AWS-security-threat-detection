
-- Create EXTERNAL table for log analysis (EXTERNAL keyword is required)
CREATE EXTERNAL TABLE web_security.access_logs (
    log_line string
)
STORED AS TEXTFILE
LOCATION 's3://security-logs-bucket-012345/raw-logs/'
TBLPROPERTIES ('has_encrypted_data'='false');
-- Check if your bucket path is correct (no spaces!)
-- Bad:  's3://security-logs-bucket-012345 /raw-logs/'  ← space here
-- Good: 's3://security-logs-bucket-012345/raw-logs/'   ← no space

The Threat Detection Algorithms

-- Detect potential DDoS attacks
WITH ip_analysis AS (
    SELECT 
        regexp_extract(log_line, '^([0-9.]+)', 1) as ip_address,
        COUNT(*) as request_count,
        COUNT(DISTINCT regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1)) as unique_pages,
        COUNT(CASE WHEN 
            CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 
            THEN 1 
        END) as failed_requests,
        AVG(CAST(regexp_extract(log_line, ' ([0-9]+)$', 1) AS INTEGER)) as avg_response_size
    FROM access_logs
    WHERE log_line IS NOT NULL
    GROUP BY regexp_extract(log_line, '^([0-9.]+)', 1)
),
threat_classification AS (
    SELECT 
        ip_address,
        request_count,
        unique_pages,
        failed_requests,
        avg_response_size,
        CASE 
            WHEN request_count > 100 THEN 'CRITICAL_DDOS'
            WHEN request_count > 50 THEN 'HIGH_SUSPICIOUS' 
            WHEN request_count > 20 THEN 'MODERATE_RISK'
            ELSE 'NORMAL'
        END as threat_level,
        CASE 
            WHEN ip_address IN ('45.32.15.123', '198.51.100.42', '185.220.101.45') 
            THEN 'KNOWN_MALICIOUS'
            WHEN ip_address LIKE '192.168.%' OR ip_address LIKE '10.0.%'
            THEN 'INTERNAL'
            ELSE 'EXTERNAL'
        END as ip_type
    FROM ip_analysis
)
SELECT 
    ip_address,
    threat_level,
    ip_type,
    request_count,
    unique_pages,
    failed_requests,
    ROUND(avg_response_size, 0) as avg_response_size,
    -- Calculate business impact estimate
    CASE 
        WHEN threat_level = 'CRITICAL_DDOS' THEN request_count * 0.10
        WHEN threat_level = 'HIGH_SUSPICIOUS' THEN request_count * 0.05  
        ELSE 0
    END as estimated_cost_impact
FROM threat_classification
WHERE threat_level != 'NORMAL'
ORDER BY request_count DESC;


--Intrusion Detection Query
-- Detect intrusion attempts on sensitive endpoints
SELECT 
    regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) as target_endpoint,
    COUNT(*) as access_attempts,
    COUNT(DISTINCT regexp_extract(log_line, '^([0-9.]+)', 1)) as unique_attackers,
    COUNT(CASE WHEN 
        CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) = 200 
        THEN 1 
    END) as successful_attempts,
    COUNT(CASE WHEN 
        CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) = 403 
        THEN 1 
    END) as blocked_attempts,
    ROUND(100.0 * COUNT(CASE WHEN 
        CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) = 200 
        THEN 1 
    END) / COUNT(*), 2) as success_rate,
    CASE 
        WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' 
        THEN 'ADMIN_ACCESS'
        WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%.env%' 
        THEN 'CONFIG_FILES'
        WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%backup%' 
        THEN 'BACKUP_FILES'
        ELSE 'OTHER_SENSITIVE'
    END as attack_category
FROM access_logs
WHERE regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' 
   OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%.env%'
   OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%backup%'
   OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%config%'
   OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%phpmyadmin%'
GROUP BY regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1)
HAVING COUNT(*) > 3
ORDER BY access_attempts DESC, success_rate DESC;

-- Bot Detection Query
-- Detect malicious bots and automated tools
WITH user_agent_analysis AS (
    SELECT 
        regexp_extract(log_line, '"([^"]*)"$', 1) as user_agent,
        COUNT(*) as request_count,
        COUNT(DISTINCT regexp_extract(log_line, '^([0-9.]+)', 1)) as unique_ips,
        COUNT(CASE WHEN 
            CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 
            THEN 1 
        END) as failed_requests,
        AVG(CAST(regexp_extract(log_line, ' ([0-9]+)$', 1) AS INTEGER)) as avg_response_size
    FROM access_logs
    WHERE regexp_extract(log_line, '"([^"]*)"$', 1) IS NOT NULL
    GROUP BY regexp_extract(log_line, '"([^"]*)"$', 1)
)
SELECT 
    user_agent,
    request_count,
    unique_ips,
    failed_requests,
    ROUND(100.0 * failed_requests / request_count, 2) as failure_rate,
    ROUND(avg_response_size, 0) as avg_response_size,
    CASE 
        WHEN user_agent LIKE '%sqlmap%' OR user_agent LIKE '%nikto%' 
        THEN 'VULNERABILITY_SCANNER'
        WHEN user_agent LIKE '%python%' OR user_agent LIKE '%curl%' 
        THEN 'AUTOMATED_TOOL'
        WHEN user_agent LIKE '%bot%' AND user_agent NOT LIKE '%Googlebot%'
        THEN 'MALICIOUS_BOT'
        WHEN user_agent LIKE '%Mozilla%' AND user_agent LIKE '%Chrome%'
        THEN 'LEGITIMATE_BROWSER'
        ELSE 'UNKNOWN'
    END as agent_category,
    CASE 
        WHEN user_agent LIKE '%sqlmap%' OR user_agent LIKE '%nikto%' 
        THEN 'HIGH_THREAT'
        WHEN user_agent LIKE '%python%' OR user_agent LIKE '%curl%' 
        THEN 'MEDIUM_THREAT'
        WHEN user_agent LIKE '%Mozilla%' 
        THEN 'LOW_THREAT'
        ELSE 'INVESTIGATE'
    END as risk_level
FROM user_agent_analysis
WHERE request_count > 5
ORDER BY 
    CASE 
        WHEN user_agent LIKE '%sqlmap%' OR user_agent LIKE '%nikto%' THEN 1
        WHEN user_agent LIKE '%python%' OR user_agent LIKE '%curl%' THEN 2
        ELSE 3 
    END,
    request_count DESC;


    -- Run Threat Detection Queries
-- Execute our SQL queries in Athena to see the results:
-- Quick test query
SELECT 
    COUNT(*) as total_requests,
    COUNT(DISTINCT regexp_extract(log_line, '^([0-9.]+)', 1)) as unique_ips,
    COUNT(CASE WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' THEN 1 END) as admin_attempts
FROM access_logs;

-- Advanced Threat Detection
-- Add geographic analysis:

-- Add IP geolocation analysis
WITH ip_analysis AS (
    SELECT 
        regexp_extract(log_line, '^([0-9.]+)', 1) as ip_address,
        CASE 
            WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '103.%' THEN 'ASIA'
            WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '185.%' THEN 'EUROPE'
            WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '198.%' THEN 'NORTH_AMERICA'
            ELSE 'UNKNOWN'
        END as region,
        COUNT(*) as request_count
    FROM access_logs
    GROUP BY regexp_extract(log_line, '^([0-9.]+)', 1)
)
SELECT region, SUM(request_count) as total_requests
FROM ip_analysis  
GROUP BY region
ORDER BY total_requests DESC;