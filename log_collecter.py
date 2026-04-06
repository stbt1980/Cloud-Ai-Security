import boto3
from botocore.exceptions import ClientError

regions = [
    "ap-southeast-2",
    "ap-northeast-2",
    "us-east-1"
]

important_events = {
    "ConsoleLogin",
    "StartInstances",
    "StopInstances",
    "RunInstances",
    "TerminateInstances",
    "CreateUser",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress"
}

seen_event_ids = set()

# 함수로 감쌈
def collect_logs():
    collected = []

    for region in regions:
        try:
            client = boto3.client("cloudtrail", region_name=region)
            response = client.lookup_events(MaxResults=20)
            events = response.get("Events", [])

            for event in events:
                event_id = event.get("EventId")
                event_name = event.get("EventName")

                if event_id in seen_event_ids:
                    continue
                if event_name not in important_events:
                    continue

                seen_event_ids.add(event_id)
                # ← print 대신 리스트에 추가
                collected.append(event)

        except ClientError as e:
            print(f"[{region}] AWS 오류:", e)

# 수집한 이벤트 반환
    return collected