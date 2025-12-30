# Guide de Configuration - Lambda Monitoring Corrigée

## Principales Corrections Apportées

### Problèmes de l'Ancien Code

1. **Requêtes Athena incorrectes** : Utilisait `regexp_extract` sur `log_line` au lieu des colonnes structurées
2. **Pas de gestion d'erreurs robuste** : Crashait si une requête échouait
3. **Métriques CloudWatch mal configurées** : Pas de dimensions appropriées
4. **SNS Topic hardcodé** : ARN fictif qui ne fonctionnait pas
5. **Pas de logging détaillé** : Difficile de debugger
6. **Dashboard non créé automatiquement** : Fonction manquante

### Solutions Implémentées

1. **Requêtes Athena corrigées** : Utilisent les bonnes colonnes (`ip`, `country`, `attack_type`, etc.)
2. **Gestion d'erreurs complète** : Try/catch partout avec logging
3. **Métriques CloudWatch optimisées** : 15+ métriques avec dimensions
4. **Configuration via variables d'environnement** : Flexible et sécurisé
5. **Logging détaillé** : Chaque étape est tracée
6. **Dashboard automatique** : Créé avec 4 graphiques


---

## Configuration des Variables d'Environnement

### Via Console AWS Lambda

1. Ouvrez votre fonction Lambda dans la console
2. Allez dans **Configuration** → **Environment variables**
3. Cliquez sur **Edit**
4. Ajoutez ces variables :

| Key | Value | Description |
|-----|-------|-------------|
| `DATABASE` | `web_security_logs` | Nom de la base Glue/Athena |
| `TABLE` | `access_logs` | Nom de la table |
| `S3_OUTPUT_LOCATION` | `s3://VOTRE-BUCKET-athena-results/monitoring/` | Bucket pour résultats Athena |
| `CLOUDWATCH_NAMESPACE` | `WebSecurity/Monitoring` | Namespace CloudWatch |
| `SNS_TOPIC_ARN` | `arn:aws:sns:us-east-1:ACCOUNT:security-alerts` | ARN du topic SNS |
| `AWS_REGION` | `us-east-1` | Région AWS |

### Via AWS CLI

```bash
# Remplacer les valeurs
FUNCTION_NAME="web-security-monitoring-monitoring"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ATHENA_BUCKET="web-security-monitoring-athena-results-${AWS_ACCOUNT_ID}"
SNS_TOPIC_ARN="arn:aws:sns:us-east-1:${AWS_ACCOUNT_ID}:web-security-monitoring-security-alerts"

# Mettre à jour les variables
aws lambda update-function-configuration \
  --function-name $FUNCTION_NAME \
  --environment "Variables={
    DATABASE=web_security_logs,
    TABLE=access_logs,
    S3_OUTPUT_LOCATION=s3://${ATHENA_BUCKET}/monitoring/,
    CLOUDWATCH_NAMESPACE=WebSecurity/Monitoring,
    SNS_TOPIC_ARN=${SNS_TOPIC_ARN},
    AWS_REGION=us-east-1
  }"
```

---

## Déploiement du Code Corrigé

### Méthode 1 : Via Console AWS

1. **Ouvrir la Lambda** :
   ```
   Console Lambda → Functions → web-security-monitoring-monitoring
   ```

2. **Éditer le code** :
   - Dans l'onglet **Code**
   - Sélectionner tout le code existant
   - Remplacer par le nouveau code de l'artifact "Lambda Monitoring Automatisé - Version Corrigée"
   - Cliquer sur **Deploy**

3. **Augmenter le timeout** (important !) :
   ```
   Configuration → General configuration → Edit
   Timeout: 15 minutes (900 secondes)
   Memory: 512 MB
   ```

### Méthode 2 : Via AWS CLI

```bash
# 1. Créer le fichier
cat > lambda_function.py << 'EOF'
# Coller le code de l'artifact ici
EOF

# 2. Créer le package ZIP
zip monitoring-fixed.zip lambda_function.py

# 3. Uploader
aws lambda update-function-code \
  --function-name web-security-monitoring-monitoring \
  --zip-file fileb://monitoring-fixed.zip

# 4. Mettre à jour la configuration
aws lambda update-function-configuration \
  --function-name web-security-monitoring-monitoring \
  --timeout 900 \
  --memory-size 512
```

---

## Tests du Monitoring Corrigé

### Test 1 : Invocation Manuelle Simple

```bash
# Via CLI
aws lambda invoke \
  --function-name web-security-monitoring-monitoring \
  --region us-east-1 \
  response.json

# Voir la réponse
cat response.json | jq '.'
```

**Résultat attendu :**
```json
{
  "statusCode": 200,
  "body": "{
    \"timestamp\": \"2024-12-30T10:30:00.000Z\",
    \"metrics_published\": 18,
    \"alerts_sent\": 0,
    \"summary\": {
      \"ddos_ips\": 2,
      \"total_attacks\": 45,
      \"unique_attackers\": 8,
      \"total_requests\": 200,
      \"error_rate\": 12.5,
      \"avg_response_time\": 350.5
    }
  }"
}
```

### Test 2 : Avec Création du Dashboard

```bash
# Via CLI avec payload
aws lambda invoke \
  --function-name web-security-monitoring-monitoring \
  --payload '{"create_dashboard": true}' \
  --region us-east-1 \
  response-dashboard.json

cat response-dashboard.json | jq '.'
```

### Test 3 : Vérifier les Logs

```bash
# Voir les logs en temps réel
aws logs tail /aws/lambda/web-security-monitoring-monitoring \
  --follow \
  --region us-east-1
```

**Logs attendus :**
```
INFO Starting monitoring analysis - Database: web_security_logs, Table: access_logs
INFO Analyzing DDoS patterns...
INFO Executing query: DDoS Detection
INFO Query ID: abc123...
INFO DDoS Detection completed successfully
INFO DDoS Analysis: 2 suspicious IPs detected, max requests: 150
INFO Analyzing attack patterns...
...
INFO Publishing 18 metrics to CloudWatch...
INFO Published batch 1 (18 metrics)
INFO ✅ All metrics published successfully
INFO ✅ Monitoring completed
```

### Test 4 : Vérifier les Métriques CloudWatch

```bash
# Lister les métriques
aws cloudwatch list-metrics \
  --namespace "WebSecurity/Monitoring" \
  --region us-east-1

# Obtenir des valeurs
aws cloudwatch get-metric-statistics \
  --namespace "WebSecurity/Monitoring" \
  --metric-name TotalAttacks \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum \
  --region us-east-1
```

---

## Métriques Générées

Le code corrigé génère automatiquement ces métriques :

### Sécurité
- `TotalAttacks` - Nombre total d'attaques
- `UniqueAttackers` - IPs malveillantes uniques
- `DDosIPsDetected` - IPs en comportement DDoS
- `MaxRequestsPerHour` - Pic de requêtes par IP
- `AttacksByType` - Avec dimension AttackType (sql_injection, xss, etc.)
- `AttacksByCountry` - Avec dimension Country

### Performance
- `AverageResponseTime` - Temps de réponse moyen (ms)
- `P95ResponseTime` - 95e percentile (ms)
- `P99ResponseTime` - 99e percentile (ms)
- `MaxResponseTime` - Temps max (ms)

### Trafic & Erreurs
- `TotalRequests` - Requêtes totales
- `ErrorRequests` - Requêtes en erreur
- `ServerErrors` - Erreurs 5xx
- `ClientErrors` - Erreurs 4xx
- `ErrorRate` - Taux d'erreur (%)
- `SystemAvailability` - Disponibilité (%)

---

## Alertes Configurées

Le monitoring envoie des alertes SNS automatiquement si :

| Condition | Type d'Alerte | Seuil |
|-----------|---------------|-------|
| IPs suspectes > 3 | DDoS Detection | 3+ IPs avec >100 req/h |
| Attaques > 100 | High Attack Volume | >100 attaques/heure |
| Disponibilité < 95% | Low Availability | <95% |
| P95 temps réponse > 2s | Performance Degradation | >2000ms |

### Format des Alertes

```
Subject: DDoS Detection Alert

Body:
DDoS ALERT: 5 IPs with >100 requests/hour detected!
Max requests from single IP: 250
Top offender: 45.32.15.123 (RU) - 250 requests
```

---

## 🔍 Debug et Troubleshooting

### Problème 1 : "No data in Athena"

**Cause** : Les logs ne sont pas encore générés

**Solution** :
```bash
# 1. Générer des logs d'abord
aws lambda invoke \
  --function-name web-security-monitoring-log-generator \
  response.json

# 2. Attendre 1 minute

# 3. Relancer le monitoring
aws lambda invoke \
  --function-name web-security-monitoring-monitoring \
  response.json
```

### Problème 2 : "Query Failed"

**Cause** : Problème avec les requêtes Athena

**Solution** :
```bash
# Vérifier les logs Lambda
aws logs tail /aws/lambda/web-security-monitoring-monitoring \
  --since 5m

# Regarder l'erreur spécifique et vérifier :
# - La table existe : SHOW TABLES IN web_security_logs;
# - Les partitions existent : SHOW PARTITIONS access_logs;
# - Les colonnes existent : DESCRIBE access_logs;
```

### Problème 3 : "Metrics not appearing in CloudWatch"

**Cause** : Permissions IAM ou namespace incorrect

**Solution** :
```bash
# 1. Vérifier les permissions IAM
aws iam get-role-policy \
  --role-name web-security-monitoring-monitoring-role \
  --policy-name AthenaAndCloudWatchAccess

# 2. Vérifier le namespace
aws cloudwatch list-metrics \
  --namespace "WebSecurity/Monitoring"

# 3. Forcer la publication
aws lambda invoke \
  --function-name web-security-monitoring-monitoring \
  --log-type Tail \
  response.json
```

### Problème 4 : "SNS Alerts not sent"

**Cause** : SNS_TOPIC_ARN manquant ou incorrect

**Solution** :
```bash
# 1. Vérifier le topic ARN
aws cloudformation describe-stacks \
  --stack-name web-security-monitoring \
  --query 'Stacks[0].Outputs[?OutputKey==`SNSTopicArn`].OutputValue' \
  --output text

# 2. Mettre à jour la variable
SNS_ARN="arn:aws:sns:us-east-1:123456789:web-security-monitoring-security-alerts"

aws lambda update-function-configuration \
  --function-name web-security-monitoring-monitoring \
  --environment "Variables={...,SNS_TOPIC_ARN=${SNS_ARN}}"

# 3. Tester
aws sns publish \
  --topic-arn $SNS_ARN \
  --subject "Test Alert" \
  --message "This is a test"
```

---

## Visualisation du Dashboard

### Accéder au Dashboard

1. **Via Console CloudWatch** :
   ```
   https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=WebSecurity-Monitoring-Dashboard
   ```

2. **Ou** :
   ```
   Console CloudWatch → Dashboards → WebSecurity-Monitoring-Dashboard
   ```

### Widgets du Dashboard

Le dashboard contient 4 graphiques :

1. **Security Threats** (en haut à gauche)
   - TotalAttacks
   - UniqueAttackers
   - DDosIPsDetected

2. **System Health** (en haut à droite)
   - ErrorRate
   - SystemAvailability

3. **Performance Metrics** (en bas à gauche)
   - AverageResponseTime
   - P95ResponseTime
   - P99ResponseTime

4. **Traffic & Errors** (en bas à droite)
   - TotalRequests
   - ErrorRequests
   - ServerErrors

---

## Scheduling Automatique

### Vérifier EventBridge

```bash
# Lister les rules
aws events list-rules \
  --name-prefix web-security-monitoring

# Voir les détails
aws events describe-rule \
  --name web-security-monitoring-monitoring-schedule
```

**Configuration actuelle :**
- Fréquence : Toutes les 15 minutes
- Payload : `{"create_dashboard": true}` (crée le dashboard à chaque run)

### Modifier la Fréquence

**Via Console** :
```
EventBridge → Rules → web-security-monitoring-monitoring-schedule → Edit
Schedule expression: rate(10 minutes)  # Exemple : toutes les 10 minutes
```

**Via CLI** :
```bash
aws events put-rule \
  --name web-security-monitoring-monitoring-schedule \
  --schedule-expression "rate(10 minutes)" \
  --state ENABLED
```

---

## Checklist de Vérification

Après le déploiement du code corrigé :

- [ ] Code Lambda mis à jour
- [ ] Variables d'environnement configurées
- [ ] Timeout augmenté à 15 minutes
- [ ] Memory augmentée à 512 MB
- [ ] Test manuel réussi
- [ ] Logs détaillés visibles
- [ ] Métriques apparaissent dans CloudWatch
- [ ] Dashboard créé et fonctionnel
- [ ] EventBridge rule active
- [ ] SNS topic configuré
- [ ] Email SNS confirmé
- [ ] Alertes de test reçues

---

## Différences Clés avec l'Ancien Code

### Ancien Code 
```python
# Requête incorrecte
query = "SELECT COUNT(*) FROM access_logs WHERE log_line LIKE '%admin%'"
# Utilise log_line au lieu des colonnes
```

### Nouveau Code 
```python
# Requête correcte
query = f"""
SELECT COUNT(*) 
FROM {DATABASE}.{TABLE}
WHERE attack_type != 'normal'
"""
# Utilise les colonnes structurées
```

### Ancien Code 
```python
# SNS hardcodé
topic_arn = 'arn:aws:sns:us-east-1:YOUR-ACCOUNT:security-alerts'
# Ne fonctionne pas
```

### Nouveau Code 
```python
# SNS depuis variable d'environnement
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
# Flexible et configurable
```

---

## Bonnes Pratiques

1. **Toujours tester après modification** : Invoquer manuellement avant de compter sur le scheduling

2. **Surveiller les logs** : Les 3 premiers runs pour détecter les problèmes

3. **Vérifier les coûts Athena** : Chaque requête scanne les données

4. **Ajuster les seuils d'alerte** : Selon votre trafic réel

5. **Documenter les changements** : Noter les modifications dans les tags Lambda

---

**Votre monitoring est maintenant fonctionnel et automatisé !**