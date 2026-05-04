#Isolation Forest 이상 탐지 모델

import numpy as np
#Isolation Forest 모델 불러오기
from sklearn.ensemble import IsolationForest
import joblib
import os
import json

#모델 저장 경로
MODEL_PATH = "Iforest_model.pki"
#누적 데이터 저장 경로
DATA_PATH = "accumulataed_data.json"

#Isolation Forest 모델 생성
IForest = IsolationForest(
    #전체의 5%를 이상치로 간주
    contamination=0.05,
    #매번 같은 결과 나오도록 고정
    random_state=1234
)

#시작할 때 저장된 모델 호출
if os.path.exists(MODEL_PATH):
    IForest = joblib.load(MODEL_PATH)
    is_trained = True
    print("저장된 모델 불러오기 완료")
else:
    is_trained = False

#시작할 때 저장된 누적 데이터 호출
if os.path.exists(DATA_PATH):
    with open(DATA_PATH, "r") as f:
        accumulated_data = json.load(f)
        print(f"저장된 데이터 {len(accumulated_data)}개 불러오기 완료")
else:
    accumulated_data = []

def detect_anomaly(features):
    #함수 안에서 밖에 있는 is_trained변수를 수정하겠다는 선언
    global is_trained

accumulated_data = []


def detect_anomaly(features):
    global is_trained, accumulated_data

    #데이터 누적 및 저장
    for row in features:
        #numpy -> list 변환
        accumulated_data.append(row.tolist())

    with open(DATA_PATH, "w") as f:
        json.dump(accumulated_data, f)

    print(f"데이터 수집중 ({len(accumulated_data)}/10)")


    #데이터가 10개 이상 모였는지 확인 / 10개 미만이면 학습하기 너무 적음
    if not is_trained:
        #데이터 10개 이상 시 학습 시작
        #완료 후 is_trained = True로 변경 / 차후부턴 학습 건너뛰고 바로 예측
        if len(accumulated_data) >= 10:
            IForest.fit(accumulated_data)
            is_trained = True
            #학습 후 바로 저장
            joblib.dump(IForest, MODEL_PATH)
            print("모델 학습 완료")
        else:
            #데이터가 10개 미만이라 학습 못함
            #수집된 개수 출력하고 빈 리스트 반환
            return[]

    #학습된 모델로 예측 / 1=정상 -1=이상
    preds = IForest.predict(features)
    #각 데이터의 이상 점수 계산
    #양수에 가까울수록 정상 / 음수에 가까울수록 이상
    scores = IForest.decision_function(features)

#결과 담을 빈 리스트 생성
    results = []
    #예측 값(preds)과 점수(scores)를 하나씩 같이 꺼내 처리
    for pred, score in zip(preds, scores):
        #각 이벤트마다 결과를 딕셔너리로 저장
        #pred==-1 True면 이상, False면 정상
        #round(float(score),4) -> 점수를 소수점 4자리로 반올림
        results.append({
            "is_anomaly": pred == -1, #1이면 이상
            "score": round(float(score),4)
        })

#결과를 메인으로 넘겨줌
    return results