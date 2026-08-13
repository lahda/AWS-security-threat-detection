
-- Create EXTERNAL table for log analysis (EXTERNAL keyword is required)
CREATE EXTERNAL TABLE web_security.access_logs (
    log_line string
)
LOCATION 's3://security-logs-533266963058-us-east-1-an/raw-logs/';


1. Quick Test Query (sanity check)

Objectif : vérifier activité globale
SELECT 
    COUNT(*) as total_requests,

    COUNT(DISTINCT regexp_extract(log_line, '^([0-9.]+)', 1)) as unique_ips,

    COUNT(CASE 
        WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' THEN 1 
    END) as admin_attempts,

    COUNT(CASE 
        WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 THEN 1 
    END) as failed_requests

FROM web_security.access_logs;


2. Requête DDoS Detection (adaptée à tes logs)

SELECT 
    regexp_extract(log_line, '^([0-9.]+)', 1) as ip_address,

    COUNT(*) as request_count,

    COUNT(DISTINCT regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1)) as unique_endpoints,

    COUNT(CASE 
        WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 
        THEN 1 
    END) as error_requests,

    ROUND(
        1.0 * COUNT(*) / 
        NULLIF(COUNT(DISTINCT regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1)), 0),
    2) as requests_per_endpoint_ratio,

    CASE 
        WHEN COUNT(*) > 20 
             AND COUNT(DISTINCT regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1)) <= 3
        THEN 'HIGH_PROBABLE_DDOS'

        WHEN COUNT(*) > 10 
             AND COUNT(CASE 
                    WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) >= 400 
                    THEN 1 
                 END) > 3
        THEN 'SUSPICIOUS_TRAFFIC_SPIKE'

        ELSE 'NORMAL'
    END as ddos_risk_level

FROM web_security.access_logs

GROUP BY regexp_extract(log_line, '^([0-9.]+)', 1)

HAVING COUNT(*) > 5

ORDER BY request_count DESC;

3. Bot Detection Query (outils automatisés)

Objectif : détecter curl, python, scanners

SELECT
    user_agent,
    COUNT(*) AS request_count,
    COUNT(DISTINCT ip) AS unique_ips,

    SUM(
        CASE
            WHEN status_code >= 400 THEN 1
            ELSE 0
        END
    ) AS error_count

FROM (
    SELECT
        regexp_extract(log_line, '^([0-9.]+)', 1) AS ip,
        regexp_extract(log_line, '"([^"]*)"$', 1) AS user_agent,
        CAST(
            regexp_extract(log_line, '" ([0-9]+) ', 1)
            AS INTEGER
        ) AS status_code

    FROM web_security.access_logs
)

WHERE
       user_agent LIKE '%curl%'
    OR user_agent LIKE '%python%'
    OR user_agent LIKE '%Nikto%'
    OR user_agent LIKE '%sqlmap%'
    OR user_agent LIKE '%bot%'

GROUP BY user_agent

ORDER BY request_count DESC;

4. Advanced Threat Detection (scoring comportemental)

Objectif : classifier niveau de menace par IP

SELECT 
    regexp_extract(log_line, '^([0-9.]+)', 1) as ip_address,

    COUNT(*) as total_requests,

    COUNT(CASE 
        WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' 
          OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%.env'
          OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%phpmyadmin%'
        THEN 1 
    END) as sensitive_hits,

    COUNT(CASE 
        WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) IN (401,403,404,500)
        THEN 1 
    END) as error_hits,

    COUNT(CASE 
        WHEN regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%curl%'
          OR regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%python%'
          OR regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%Nikto%'
        THEN 1 
    END) as automation_signals,

    CASE 
        WHEN 
            COUNT(CASE 
                WHEN regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%admin%' 
                  OR regexp_extract(log_line, '"[A-Z]+ ([^ ]+)', 1) LIKE '%.env'
                THEN 1 
            END) > 2
        THEN 'HIGH_RECON'

        WHEN 
            COUNT(CASE 
                WHEN regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%curl%'
                  OR regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%python%'
                  OR regexp_extract(log_line, '"([^"]*)"$', 1) LIKE '%Nikto%'
                THEN 1 
            END) > 1
        THEN 'AUTOMATED_TOOL'

        WHEN 
            COUNT(CASE 
                WHEN CAST(regexp_extract(log_line, '" ([0-9]+) ', 1) AS INTEGER) IN (401,403,500)
                THEN 1 
            END) > 3
        THEN 'FAILED_INTRUSION'

        ELSE 'NORMAL'
    END as threat_level

FROM web_security.access_logs
GROUP BY regexp_extract(log_line, '^([0-9.]+)', 1)

HAVING COUNT(*) > 3

ORDER BY total_requests DESC;

5. IP Geolocation Analysis (approximation via prefix)

Objectif : regrouper trafic par région (proxy GeoIP)

SELECT 
    CASE 
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '10.%' THEN 'PRIVATE_NETWORK'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '192.168.%' THEN 'PRIVATE_NETWORK'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '172.16.%' THEN 'PRIVATE_NETWORK'

        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '185.%' THEN 'EUROPE'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '198.%' THEN 'NORTH_AMERICA'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '45.%' THEN 'UNKNOWN_PUBLIC'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '103.%' THEN 'ASIA'
        WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '41.%' THEN 'AFRICA'

        ELSE 'UNKNOWN'
    END as region,

    COUNT(*) as request_count

FROM web_security.access_logs
GROUP BY CASE 
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '10.%' THEN 'PRIVATE_NETWORK'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '192.168.%' THEN 'PRIVATE_NETWORK'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '172.16.%' THEN 'PRIVATE_NETWORK'

    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '185.%' THEN 'EUROPE'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '198.%' THEN 'NORTH_AMERICA'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '45.%' THEN 'UNKNOWN_PUBLIC'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '103.%' THEN 'ASIA'
    WHEN regexp_extract(log_line, '^([0-9.]+)', 1) LIKE '41.%' THEN 'AFRICA'

    ELSE 'UNKNOWN'
END

ORDER BY request_count DESC;
