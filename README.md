# AWS-security-threat-detection

This repository contains an end-to-end solution for detecting, analyzing, and monitoring web security threats using AWS-native services. It provides tooling to generate and analyze access logs, detect suspicious or malicious behavior, and publish actionable security metrics and alerts.

## Features

- **Automated Log Generation:** Simulate realistic web server logs, including both legitimate and malicious activity, for testing and validation.
- **Threat Detection & Analysis:** Run automated queries to detect Distributed Denial of Service (DDoS) patterns, intrusion attempts, bot activity, and suspicious endpoint access.
- **Metrics & Alerts:** Publishes custom security metrics to AWS CloudWatch and sends alerts when suspicious activity exceeds defined thresholds.
- **Serverless & Scalable:** Uses AWS Lambda, Amazon S3, Athena, and CloudWatch for a fully serverless, scalable architecture.
- **Ready-to-Query SQL:** Includes Athena SQL scripts for advanced threat analytics and reporting.

## Repository Contents

- [`automated_monitoringfunction.py`](https://github.com/lahda/AWS-security-threat-detection/blob/main/automated_monitoringfunction.py):  
  Lambda function that orchestrates the entire threat detection process.  
  - Runs Athena queries to analyze logs for DDoS, intrusion, and error patterns.
  - Publishes detailed metrics to CloudWatch.
  - Sends alerts (via SNS) if threat levels meet or exceed thresholds.
  - Estimates security impact and cost.

- [`security-metrics-processor.py`](https://github.com/lahda/AWS-security-threat-detection/blob/main/security-metrics-processor.py):  
  Lambda function to process log data, extract security metrics, and automate alerting.
  - Detects suspicious IPs, intrusion attempts, and calculates error/availability rates.
  - Publishes metrics and triggers AWS SNS alerts for actionable events.
  - Returns a detailed summary of metrics and alerts sent.

- [`log_generator.py`](https://github.com/lahda/AWS-security-threat-detection/blob/main/log_generator.py):  
  Lambda function to generate synthetic Apache/Nginx-style log files.
  - Simulates both legitimate and attack traffic (DDoS, intrusion, bots).
  - Stores generated logs in S3 for downstream analysis.

- [`Database_Athena.sql`](https://github.com/lahda/AWS-security-threat-detection/blob/main/Database_Athena.sql):  
  Athena DDL and advanced threat detection queries.
  - Defines external table for logs in S3.
  - Contains SQL for DDoS, intrusion, and bot detection, plus business impact analytics.

- [`LambdaExecutionRole.txt`](https://github.com/lahda/AWS-security-threat-detection/blob/main/LambdaExecutionRole.txt):  
  Example IAM policy for Lambda functions.
  - Grants permissions for S3 access, CloudWatch metrics, and logging.

## How It Works

1. **Log Generation:**  
   `log_generator.py` creates realistic access logs, mixing normal and malicious traffic, and stores them in an S3 bucket.

2. **Threat Analysis:**  
   The main Lambda function(s) (`automated_monitoringfunction.py`, `security-metrics-processor.py`) run Athena queries on the logs to:
   - Count suspicious IPs (potential DDoS sources)
   - Detect intrusion attempts on sensitive endpoints
   - Analyze traffic volume and error rates
   - Identify bot and automated tool activity

3. **Metrics & Alerting:**  
   Results are published as CloudWatch metrics. If any metric exceeds a security threshold (e.g., too many suspicious IPs), an SNS alert is triggered.

4. **Visualization & Response:**  
   Use CloudWatch dashboards and alarms to visualize trends and enable automated incident response.

## Setup

1. **Deploy Lambda Functions:**  
   - Upload the Python scripts to AWS Lambda.
   - Assign the provided IAM role/policy (`LambdaExecutionRole.txt`).

2. **Configure S3 & Athena:**  
   - Create an S3 bucket for log storage.
   - Deploy the Athena table using `Database_Athena.sql`.

3. **Set up CloudWatch & SNS:**  
   - Create CloudWatch metrics/alarms for key indicators.
   - Set up an SNS topic for security alerts and subscribe your email/SMS.

4. **Run & Monitor:**  
   - Schedule log generation and analysis Lambda functions (e.g., via EventBridge).
   - Monitor CloudWatch for security insights and alerts.

## Requirements

- AWS Account with permissions to use Lambda, S3, Athena, CloudWatch, and SNS
- Python 3.8+ for Lambda runtime

## License

This project is provided as-is, with no warranty. Please review and adapt for production use.

---

**Contributions and feedback are welcome!**
