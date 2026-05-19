from datetime import datetime
import ipaddress
import json
import os


# ============================================
# 0. 정상 IP 설정 파일
# ============================================

TRUSTED_IPS_FILE = "trusted_ips.json"


def load_trusted_ips():
    if not os.path.exists(TRUSTED_IPS_FILE):
        return {}

    try:
        with open(TRUSTED_IPS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


TRUSTED_IPS = load_trusted_ips()


# ============================================
# 1. 이벤트 기본 점수표
# AWS Security Hub, GuardDuty, Elastic Rule, MITRE ATT&CK 개념 참고
# ============================================

BASE_EVENT_SCORES = {
    # 로그인
    "ConsoleLogin": 15,

    # EC2 관련
    "StartInstances": 10,
    "StopInstances": 30,
    "RunInstances": 35,
    "TerminateInstances": 55,

    # IAM 사용자 관련
    "CreateUser": 40,
    "DeleteUser": 50,

    # IAM 권한 변경
    "AttachUserPolicy": 55,
    "DetachUserPolicy": 35,
    "PutUserPolicy": 55,
    "DeleteUserPolicy": 40,

    # Access Key 관련
    "CreateAccessKey": 55,
    "DeleteAccessKey": 30,

    # Security Group 관련
    "AuthorizeSecurityGroupIngress": 55,
    "RevokeSecurityGroupIngress": 25,

    # CloudTrail 방어 회피
    "StopLogging": 60,
    "DeleteTrail": 65,
    "UpdateTrail": 40,

    # S3 관련
    "PutBucketPolicy": 55,
    "DeleteBucket": 55,
    "PutBucketAcl": 50,

    # IAM Role 관련 (추가)
    "CreateRole": 45,
    "DeleteRole": 40,
    "AttachRolePolicy": 55,
    "DetachRolePolicy": 35,
    "PutRolePolicy": 55,
    "DeleteRolePolicy": 40,
    "AssumeRole": 40,
    "UpdateAssumeRolePolicy": 50,
}


# ============================================
# 2. 위험 이벤트 분류
# ============================================

HIGH_RISK_EVENTS = {
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateAccessKey",
    "AuthorizeSecurityGroupIngress",
    "TerminateInstances",
    "DeleteUser",
    "StopLogging",
    "DeleteTrail",
    "PutBucketPolicy",
    "DeleteBucket",
    # IAM Role 관련 (추가)
    "AttachRolePolicy",
    "PutRolePolicy",
    "UpdateAssumeRolePolicy",
}

MEDIUM_RISK_EVENTS = {
    "StopInstances",
    "DetachUserPolicy",
    "DeleteAccessKey",
    "DeleteUserPolicy",
    "RunInstances",
    "CreateUser",
    "UpdateTrail",
    "PutBucketAcl",
    # IAM Role 관련 (추가)
    "CreateRole",
    "DeleteRole",
    "DetachRolePolicy",
    "DeleteRolePolicy",
    "AssumeRole",
}


# ============================================
# 3. 공격 유형 분류
# ============================================

ATTACK_TYPES = {
    "ConsoleLogin": "비정상 로그인 시도",
    "StartInstances": "일반 EC2 운영 활동",
    "StopInstances": "서비스 중단 가능 활동",
    "RunInstances": "리소스 악용 가능 활동",
    "TerminateInstances": "서비스 종료 공격",
    "CreateUser": "지속성 확보 의심",
    "DeleteUser": "계정 삭제 공격",
    "AttachUserPolicy": "권한 상승 공격",
    "DetachUserPolicy": "보안 정책 우회 의심",
    "PutUserPolicy": "권한 상승 공격",
    "DeleteUserPolicy": "보안 정책 우회 의심",
    "CreateAccessKey": "인증 정보 생성 / 계정 탈취 의심",
    "DeleteAccessKey": "인증 정보 삭제 / 흔적 은폐 의심",
    "AuthorizeSecurityGroupIngress": "외부 접근 허용 / 침입 가능성",
    "RevokeSecurityGroupIngress": "접근 정책 변경",
    "StopLogging": "CloudTrail 로깅 중지 / 방어 회피",
    "DeleteTrail": "CloudTrail 삭제 / 방어 회피",
    "UpdateTrail": "CloudTrail 설정 변경",
    "PutBucketPolicy": "S3 공개 정책 변경",
    "DeleteBucket": "S3 삭제 공격",
    "PutBucketAcl": "S3 접근 권한 변경",
    # IAM Role 관련 (추가)
    "CreateRole": "IAM Role 생성 / 백도어 의심",
    "DeleteRole": "IAM Role 삭제",
    "AttachRolePolicy": "Role 권한 상승 공격",
    "DetachRolePolicy": "Role 보안 정책 우회 의심",
    "PutRolePolicy": "Role 권한 상승 공격",
    "DeleteRolePolicy": "Role 보안 정책 우회 의심",
    "AssumeRole": "역할 가장 / 권한 탈취 의심",
    "UpdateAssumeRolePolicy": "신뢰 정책 변경 / 백도어 의심",
}


# ============================================
# 4. 위험도 등급 분류
# AWS Security Hub 정규화 심각도 방식 참고
# ============================================

def classify_risk(score):
    if score == 0:
        return "INFORMATIONAL"
    elif score <= 39:
        return "LOW"
    elif score <= 69:
        return "MEDIUM"
    elif score <= 89:
        return "HIGH"
    else:
        return "CRITICAL"


# ============================================
# 5. 유틸 함수
# ============================================

def get_hour(event_time):
    try:
        return datetime.fromisoformat(event_time).hour
    except Exception:
        return -1


def is_external_ip(ip):
    if not ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False


def is_trusted_ip(actor, ip):
    if not actor or not ip:
        return False

    trusted_list = TRUSTED_IPS.get(actor, [])
    return ip in trusted_list


def is_open_to_world(cidr_ip):
    return cidr_ip == "0.0.0.0/0"


def is_admin_policy(policy_arn):
    if not policy_arn:
        return False

    admin_keywords = [
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess",
    ]

    return any(keyword in policy_arn for keyword in admin_keywords)


def is_sensitive_port(from_port, to_port):
    # 443(HTTPS), 80(HTTP) 추가
    sensitive_ports = {22, 80, 443, 3389, 3306, 5432, 6379, 9200}

    try:
        fp = int(from_port) if from_port is not None else None
        tp = int(to_port) if to_port is not None else None
    except ValueError:
        return False

    if fp is None or tp is None:
        return False

    for port in sensitive_ports:
        if fp <= port <= tp:
            return True

    return False


# ============================================
# 6. 위험도 계산 핵심 함수
# 단일 이벤트 / 여러 이벤트 모두 처리
# ============================================

def calculate_risk(events, ai_results=None):
    if not isinstance(events, list):
        events = [events]

    if ai_results and not isinstance(ai_results, list):
        ai_results = [ai_results]

    reasons = []

    base_score = 0
    context_bonus = 0
    anomaly_bonus = 0

    has_high_risk_root = False
    has_root_activity = False

    # ----------------------------------------
    # 1. 이벤트 기본 점수 + ContextBonus 계산
    # ----------------------------------------
    for event in events:
        event_name = event.get("EventName", "")
        actor = event.get("Actor")
        source_ip = event.get("SourceIP")
        event_time = event.get("EventTime")
        error_code = event.get("ErrorCode")
        policy_arn = event.get("PolicyArn")
        cidr_ip = event.get("CidrIp")
        from_port = event.get("FromPort")
        to_port = event.get("ToPort")

        event_score = BASE_EVENT_SCORES.get(event_name, 10)
        base_score += event_score
        reasons.append(f"{event_name} 이벤트 +{event_score}")

        hour = get_hour(event_time)

        # 야간 시간대 활동
        if 0 <= hour <= 6:
            if event_name in HIGH_RISK_EVENTS:
                context_bonus += 5
                reasons.append(f"{event_name} 야간 고위험 이벤트 +5")
            elif event_name in MEDIUM_RISK_EVENTS:
                context_bonus += 3
                reasons.append(f"{event_name} 야간 중위험 이벤트 +3")
            else:
                context_bonus += 1
                reasons.append(f"{event_name} 야간 활동 +1")

        # 외부 IP 접근
        if is_external_ip(source_ip):
            if event_name in HIGH_RISK_EVENTS:
                context_bonus += 5
                reasons.append(f"{event_name} 외부 IP 고위험 이벤트 +5")
            else:
                context_bonus += 3
                reasons.append(f"{event_name} 외부 IP 접근 +3")

        # 등록된 정상 IP 사용 시 감점
        if is_trusted_ip(actor, source_ip):
            if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]:
                context_bonus -= 10
                reasons.append("등록된 root 정상 IP 사용 -10")
            else:
                context_bonus -= 5
                reasons.append("등록된 정상 IP 사용 -5")

        # ErrorCode 발생
        if error_code:
            context_bonus += 3
            reasons.append(f"{event_name} API 오류 또는 실패 +3")

        # 관리자급 정책 부여
        if event_name in {"AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy"} and is_admin_policy(policy_arn):
            context_bonus += 10
            reasons.append("관리자급 정책 부여 +10")

        # 보안그룹 전체 개방 및 민감 포트 개방
        if event_name == "AuthorizeSecurityGroupIngress":
            if is_open_to_world(cidr_ip):
                context_bonus += 10
                reasons.append("0.0.0.0/0 전체 개방 +10")

            if is_sensitive_port(from_port, to_port):
                context_bonus += 7
                reasons.append("민감 포트 개방 +7")

        # root/고권한 계정 활동 여부
        if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]:
            has_root_activity = True

            if event_name in HIGH_RISK_EVENTS:
                has_high_risk_root = True

    # ----------------------------------------
    # 2. AI 이상 탐지 점수
    # ----------------------------------------
    if ai_results:
        if any(result and result.get("is_anomaly") for result in ai_results):
            anomaly_bonus += 10
            reasons.append("AI 이상 탐지 결과 +10")

    # ----------------------------------------
    # 3. CriticalityMultiplier
    # ----------------------------------------
    criticality_multiplier = 1.0

    if has_high_risk_root:
        criticality_multiplier = 1.15
        reasons.append("root/고권한 계정의 고위험 이벤트 ×1.15")
    elif has_root_activity:
        criticality_multiplier = 1.05
        reasons.append("root/고권한 계정 활동 ×1.05")

    # ----------------------------------------
    # 4. 최종 점수 계산
    # ----------------------------------------
    raw_score = round(
        (base_score + context_bonus + anomaly_bonus)
        * criticality_multiplier
    )

    if raw_score < 0:
        raw_score = 0

    final_score = min(100, raw_score)

    risk_level = classify_risk(final_score)

    return {
        "risk_score": final_score,
        "raw_score": raw_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "base_score": base_score,
        "context_bonus": context_bonus,
        "anomaly_bonus": anomaly_bonus,
        "criticality_multiplier": criticality_multiplier,
    }


# ============================================
# 7. 공격 유형 분류
# ============================================

def classify_attack(events):
    if not isinstance(events, list):
        events = [events]

    event_names = [event.get("EventName", "") for event in events]

    if "StopLogging" in event_names or "DeleteTrail" in event_names:
        return "CloudTrail 방어 회피 공격"

    if "AttachUserPolicy" in event_names or "PutUserPolicy" in event_names:
        return "권한 상승 공격"

    if "AttachRolePolicy" in event_names or "PutRolePolicy" in event_names:
        return "Role 권한 상승 공격"

    if "CreateRole" in event_names or "UpdateAssumeRolePolicy" in event_names:
        return "IAM Role 백도어 의심"

    if "AssumeRole" in event_names:
        return "역할 가장 / 권한 탈취 의심"

    if "CreateAccessKey" in event_names:
        return "인증 정보 생성 / 계정 탈취 의심"

    if "AuthorizeSecurityGroupIngress" in event_names:
        return "외부 접근 허용 / 침입 가능성"

    if "PutBucketPolicy" in event_names or "PutBucketAcl" in event_names:
        return "S3 공개화 또는 권한 변경 의심"

    if "TerminateInstances" in event_names:
        return "서비스 종료 공격"

    if "DeleteUser" in event_names:
        return "계정 삭제 공격"

    if "ConsoleLogin" in event_names:
        return "비정상 로그인 시도"

    return "일반 활동"


# ============================================
# 8. 블랙리스트 판단
# ============================================

def should_blacklist_ip(events, risk):
    if not isinstance(events, list):
        events = [events]

    has_external_ip = any(
        is_external_ip(event.get("SourceIP"))
        for event in events
    )

    if not has_external_ip:
        return False

    event_names = [event.get("EventName", "") for event in events]

    if risk["risk_level"] == "CRITICAL":
        return True

    if risk["risk_level"] == "HIGH" and any(
        name in HIGH_RISK_EVENTS for name in event_names
    ):
        return True

    return False