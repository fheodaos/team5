import json
import boto3
import gzip
import base64
import os
import urllib.request
import pymysql
from datetime import datetime, timezone, timedelta


def ask_llama(client_ip, country, uri, method, rule, args):
    bedrock = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
    log_summary = f"IP: {client_ip} | 국가: {country} | URI: {uri} | 메서드: {method} | 차단규칙: {rule} | 파라미터: {args}"
    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
당신은 사이버 보안 관제 전문가입니다. 아래 보안 로그를 분석하여 정해진 형식에 맞게 한국어로 작성하세요.
반드시 아래 형식 그대로 3문장으로만 출력하세요. 추가 설명, 번호, 항목명 없이 문장만 출력하세요.
<|eot_id|><|start_header_id|>user<|end_header_id|>
다음 보안 로그를 분석하여 아래 형식에 맞게 정확히 3문장으로 작성하세요.

[형식]
1문장: [공격 유형]을 통해 [공격 의도]로 보입니다. [URI]에 [메서드] 방식으로 접근을 시도했습니다.
2문장: 현재 해당 IP {client_ip} 사용자를 차단한 상태이며, 추가 접근 시도가 있을 수 있습니다.
3문장: [관련 시스템 또는 경로]에 문제가 있는지 확인하는 것을 추천드립니다.

로그: {log_summary}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""
    native_request = {"prompt": prompt, "max_gen_len": 512, "temperature": 0.3, "top_p": 0.9}
    response = bedrock.invoke_model(modelId="us.meta.llama3-1-8b-instruct-v1:0", body=json.dumps(native_request))
    model_response = json.loads(response["body"].read())
    return model_response.get("generation", "분석 실패").strip()


def add_ip_to_blocklist(client_ip):
    admin_ips = [ip.strip() for ip in os.environ.get('ADMIN_IPS', '').split(',') if ip.strip()]
    if client_ip in admin_ips:
        print(f"관리자 IP 제외: {client_ip}")
        return
    wafv2 = boto3.client('wafv2', region_name='us-east-1')
    ipset_id = os.environ.get('BLOCKED_IPSET_ID')
    response = wafv2.get_ip_set(Name='BlockedIPSet-tf', Scope='CLOUDFRONT', Id=ipset_id)
    current_addresses = response['IPSet']['Addresses']
    lock_token = response['LockToken']
    new_ip = f"{client_ip}/32"
    if new_ip in current_addresses:
        print(f"이미 차단된 IP: {client_ip}")
        return
    current_addresses.append(new_ip)
    wafv2.update_ip_set(
        Name='BlockedIPSet-tf',
        Scope='CLOUDFRONT',
        Id=ipset_id,
        Addresses=current_addresses,
        LockToken=lock_token
    )
    print(f"IP 차단 목록 추가 완료: {client_ip}")


DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')


def send_discord(time_str, client_ip, country, uri, method, rule_kor, args, summary):
    webhook_url = DISCORD_WEBHOOK_URL
    payload = {
        "embeds": [
            {
                "title": "🚨 보안 관제 이상 탐지 알림",
                "color": 16711680,
                "fields": [
                    {"name": "📅 탐지 시각",     "value": time_str,                   "inline": False},
                    {"name": "🌐 공격 IP",        "value": f"{client_ip} ({country})", "inline": True},
                    {"name": "⚔️ 공격 기법",      "value": rule_kor,                   "inline": True},
                    {"name": "🛡️ 현재 상태",      "value": "차단됨 (BLOCK)",           "inline": True},
                    {"name": "🔗 요청 URL",        "value": uri,                        "inline": False},
                    {"name": "📡 요청 방식",       "value": method,                     "inline": True},
                    {"name": "📝 공격 파라미터",   "value": args or "없음",             "inline": True},
                    {"name": "🤖 AI 관제 요약",    "value": summary,                    "inline": False},
                ],
                "footer": {"text": "⚠️ 즉각적인 확인 및 조치가 필요합니다."},
            }
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.7.1"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        print(f"Discord 알림 전송 완료: HTTP {resp.status}")


def save_to_mysql(time_str, client_ip, country, uri, method, rule_kor, args, summary):
    try:
        conn = pymysql.connect(
            host=os.environ.get('RDS_HOST'),
            user=os.environ.get('RDS_USER'),
            password=os.environ.get('RDS_PASSWORD'),
            database=os.environ.get('RDS_DATABASE'),
            connect_timeout=5
        )
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    detected_at VARCHAR(50),
                    client_ip   VARCHAR(50),
                    country     VARCHAR(10),
                    uri         VARCHAR(500),
                    method      VARCHAR(10),
                    attack_type VARCHAR(100),
                    parameters  VARCHAR(500),
                    ai_summary  TEXT,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                INSERT INTO attack_logs
                    (detected_at, client_ip, country, uri, method, attack_type, parameters, ai_summary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (time_str, client_ip, country, uri, method, rule_kor, args, summary))
        conn.commit()
        conn.close()
        print(f"MySQL 저장 완료: {client_ip} | {rule_kor}")
    except Exception as e:
        print(f"MySQL 저장 실패: {str(e)}")


def lambda_handler(event, context):
    compressed = base64.b64decode(event['awslogs']['data'])
    log_data = json.loads(gzip.decompress(compressed).decode('utf-8'))
    ses = boto3.client('ses', region_name='us-east-1')
    rule_map = {
        "AWS-AWSManagedRulesSQLiRuleSet": "SQL Injection",
        "AWS-AWSManagedRulesCommonRuleSet": "공통 공격 (XSS 등)",
        "AWS-AWSManagedRulesLinuxRuleSet": "Linux 파일 탐색 (LFI)",
        "AWS-AWSManagedRulesKnownBadInputsRuleSet": "알려진 악성 입력",
        "AWS-AWSManagedRulesAnonymousIpList": "익명 IP 접근",
        "AWS-AWSManagedRulesAmazonIpReputationList": "악성 IP 접근",
        "GeoRule": "해외 IP 접근",
        "BlockedIP-Reaccess": "차단 IP 재접속",
        "AdminPath-Protect": "관리자 경로 접근 시도",
    }
    for log_event in log_data['logEvents']:
        log = json.loads(log_event['message'])
        if log.get('action') != 'BLOCK':
            continue
        timestamp_ms = log.get('timestamp', 0)
        kst = timezone(timedelta(hours=9))
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=kst)
        time_str = dt.strftime("%Y년 %m월 %d일 %H시 %M분 %S초")
        client_ip = log.get('httpRequest', {}).get('clientIp', '알 수 없음')
        country   = log.get('httpRequest', {}).get('country', '알 수 없음')
        uri       = log.get('httpRequest', {}).get('uri', '알 수 없음')
        method    = log.get('httpRequest', {}).get('httpMethod', '알 수 없음')
        args      = log.get('httpRequest', {}).get('args', '없음')
        rule      = log.get('terminatingRuleId', '알 수 없음')
        rule_kor  = rule_map.get(rule, rule)

        try:
            add_ip_to_blocklist(client_ip)
        except Exception as e:
            print(f"IP Set 추가 실패: {str(e)}")

        try:
            summary = ask_llama(client_ip, country, uri, method, rule, args)
        except Exception as e:
            summary = f"LLM 분석 실패: {str(e)}"

        subject = f"[보안 관제] {rule_kor} 탐지 - {client_ip} ({time_str})"
        body = f"""
╔══════════════════════════════════════╗
       🚨 보안 관제 이상 탐지 알림
╚══════════════════════════════════════╝
📅 탐지 시각  : {time_str}
🌐 공격 IP    : {client_ip} ({country})
🔗 요청 URL   : {uri}
📡 요청 방식  : {method}
⚔️  공격 기법  : {rule_kor}
📝 공격 파라미터: {args}
🛡️  현재 상태  : 차단됨 (BLOCK)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 AI 관제 요약
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{summary}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  즉각적인 확인 및 조치가 필요합니다.
        """
        try:
            alert_email = os.environ.get('ALERT_EMAIL')
            ses.send_email(
                Source=alert_email,
                Destination={'ToAddresses': [alert_email]},
                Message={
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {'Text': {'Data': body, 'Charset': 'UTF-8'}}
                }
            )
            print(f"이메일 알림 전송 완료: {client_ip} | {rule_kor}")
        except Exception as e:
            print(f"이메일 알림 실패: {str(e)}")

        try:
            send_discord(time_str, client_ip, country, uri, method, rule_kor, args, summary)
        except Exception as e:
            print(f"Discord 알림 실패: {str(e)}")

        save_to_mysql(time_str, client_ip, country, uri, method, rule_kor, args, summary)

    return {'statusCode': 200}
