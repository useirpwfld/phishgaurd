# PhishGuard

## 프로젝트 소개

피싱 사이트나 악성 URL은 정상적인 사이트와 비슷한 주소를 사용하기도 하고, 주소만 보고 위험한지 판단하기 어려운 경우가 있습니다.

PhishGuard는 사용자가 입력한 URL을 분석해 위험도를 보여주는 모바일 앱입니다. CNN 모델로 URL 문자열을 분석하고, URL에 포함된 의심 키워드나 구조적인 특징도 함께 검사합니다. 검사한 주소는 기록으로 남겨 나중에 다시 확인할 수 있습니다.

## 프로젝트 목표

- URL 입력만으로 위험도를 확인할 수 있는 앱 구현
- CNN 모델과 규칙 기반 검사를 활용한 URL 분석
- 검사 근거와 AI 요약을 통해 결과를 쉽게 확인
- 검사 기록 저장 및 조회

## 주요 기능

### URL 위험도 검사
- 입력한 URL을 CNN 모델과 규칙 기반으로 분석
- 0~100% 위험도와 안전·주의·위험 상태 표시
- HTTP 사용, IP 주소 포함, 의심 키워드, URL 길이 등 검사 근거 제공

### AI 요약
- 검사 결과와 탐지 근거를 바탕으로 설명 생성
- Gemini API를 설정하지 않은 경우 기본 설명 출력

### 검사 기록
- 검사한 URL, 위험도, URL 유형, 탐지 근거, 검사 시간 저장
- 이전 검사 결과 조회

### VirusTotal 조회
- VirusTotal API를 통해 기존 분석 결과 조회
- API 키 설정 시 사용 가능

## 기술 스택

**Frontend**
- React Native
- Expo
- TypeScript

**Backend**
- Python
- FastAPI
- SQLAlchemy

**Database / Infra**
- PostgreSQL
- Docker Compose

**AI / External API**
- PyTorch (1D CNN)
- Gemini API
- VirusTotal API

## 구현 사항

### URL 검사

<img src="docs/images/home.png" width="300" alt="URL 검사 화면">

### 검사 기록

<img src="docs/images/history.png" width="300" alt="검사 기록 화면">

### 시스템 구성

```text
React Native (Expo)
        │
        ▼
      FastAPI
        ├── CNN 모델 (PyTorch)
        ├── URL 규칙 검사
        ├── Gemini / VirusTotal API
        └── PostgreSQL (Docker)
```

**Backend API**
- `GET /health` : 서버 상태 확인
- `POST /scan` : URL 검사
- `GET /scans` : 검사 기록 조회

## 모델

URL 전체 문자열을 문자 단위로 입력받는 CNN 모델을 사용했습니다. 서로 다른 크기의 합성곱 필터를 이용해 URL의 문자열 패턴을 분석합니다.

학습 및 검증에 사용한 데이터는 Kaggle Malicious URLs 등 공개 URL 데이터로, 원본 데이터는 저장소에 포함하지 않았습니다.

**검증 결과** (`artifacts/cnn_metrics_report.txt` 기준)

| Accuracy | Precision | Recall | F1-score | AUC |
| --- | --- | --- | --- | --- |
| 99.83% | 99.99% | 99.61% | 99.80% | 99.91% |

위 수치는 학습 시 분리한 검증 데이터 기준이며, 실제 서비스 환경에서의 탐지율을 의미하지 않습니다.
