from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import httpx


ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=False)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

# .env에 GEMINI_TIMEOUT 또는 GEMINI_TIMEOUT_SEC 둘 중 아무거나 써도 동작
GEMINI_TIMEOUT_SEC = float(
    os.getenv("GEMINI_TIMEOUT_SEC") or os.getenv("GEMINI_TIMEOUT") or "8"
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _risk_label(score: int) -> str:
    if score >= 80:
        return "위험"
    if score >= 55:
        return "주의"
    return "안전"


def _plain_url_type(url_type: Any) -> str:
    """
    백엔드 내부 URL 유형명을 사용자에게 자연스러운 설명으로 바꿈.
    특히 '일반 정보형'은 사용자 화면에 그대로 보여주지 않음.
    """
    raw = str(url_type or "").strip()

    mapping = {
        "로그인/계정 유도형": "로그인이나 계정 확인을 유도하는 주소",
        "결제/금융 유도형": "결제나 금융 정보를 요구할 수 있는 주소",
        "배송/택배 사칭형": "배송이나 택배 안내처럼 보이는 주소",
        "보안 경고 유도형": "보안 경고나 인증을 요구하는 주소",
        "이벤트/쿠폰 유도형": "이벤트나 쿠폰으로 접속을 유도하는 주소",
        "단축 URL형": "실제 목적지를 숨길 수 있는 짧은 주소",
        "IP 직접 접속형": "도메인 대신 IP 주소로 직접 접속하는 주소",
        "긴 URL/쿼리 과다형": "주소가 지나치게 길거나 복잡한 주소",
        "하위 도메인 과다형": "도메인이 여러 단계로 길게 이어진 주소",
        "난독화/특수문자형": "숫자나 특수문자가 많아 확인하기 어려운 주소",
        "의심 TLD형": "주의가 필요한 도메인 끝자리를 사용하는 주소",
        "리다이렉트 도메인 변경형": "접속 중 다른 도메인으로 이동하는 주소",
        "파일 다운로드 유도형": "파일 다운로드를 유도할 수 있는 주소",
    }

    if raw in ("", "일반 정보형"):
        return ""

    return mapping.get(raw, raw)


def _fallback_summary(
    *,
    score: int,
    cnn_proba: float | None,
    reason_details: list[str],
    features: dict[str, Any],
) -> str:
    url_type = _plain_url_type(features.get("url_type"))

    vt = features.get("virustotal") or {}
    malicious = _as_int(vt.get("malicious"))
    suspicious = _as_int(vt.get("suspicious"))

    signals: list[str] = []

    if features.get("has_http") == 1:
        signals.append("암호화되지 않은 HTTP 사용")
    if features.get("path_has_login_like") == 1:
        signals.append("로그인이나 계정 확인 유도")
    if _as_int(features.get("keyword_hit_count")) > 0:
        signals.append("의심 키워드 포함")
    if features.get("suspicious_tld") == 1:
        signals.append("주의가 필요한 도메인 끝자리 사용")
    if features.get("has_ip") == 1:
        signals.append("IP 주소 직접 사용")
    if features.get("is_shortener") == 1:
        signals.append("짧은 주소 사용")
    if features.get("has_at") == 1:
        signals.append("@ 문자 포함")
    if features.get("sm_final_host_changed") == 1:
        signals.append("접속 중 다른 도메인으로 이동")

    if not signals:
        for r in reason_details:
            if "로그인" in r or "계정" in r:
                signals.append("로그인이나 계정 확인 유도")
            elif "의심 키워드" in r:
                signals.append("의심 키워드 포함")
            elif "HTTP" in r:
                signals.append("암호화되지 않은 HTTP 사용")
            elif "TLD" in r:
                signals.append("주의가 필요한 도메인 끝자리 사용")
            elif "리다이렉트" in r or "최종 도메인 변경" in r:
                signals.append("접속 중 다른 도메인으로 이동")

    signals = list(dict.fromkeys(signals))[:3]

    label = _risk_label(score)

    if malicious > 0:
        vt_text = f"VirusTotal에서 {malicious}개 보안 엔진이 악성으로 탐지했습니다."
    elif suspicious > 0:
        vt_text = f"VirusTotal에서 {suspicious}개 보안 엔진이 의심으로 분류했습니다."
    else:
        vt_text = "VirusTotal에서는 뚜렷한 악성 탐지가 확인되지 않았습니다."

    if signals:
        signal_text = ", ".join(signals)

        if url_type:
            return (
                f"최종 위험도는 {score}%로 {label} 수준입니다. "
                f"{vt_text} 이 주소는 {url_type}로 보이며, "
                f"{signal_text} 같은 위험 신호가 확인되어 주의가 필요합니다."
            )

        return (
            f"최종 위험도는 {score}%로 {label} 수준입니다. "
            f"{vt_text} 이 주소에서는 {signal_text} 같은 위험 신호가 확인되어 주의가 필요합니다."
        )

    return (
        f"최종 위험도는 {score}%로 {label} 수준입니다. "
        f"{vt_text} 현재 주소에서는 로그인 유도, 짧은 주소, 의심 도메인 같은 "
        f"뚜렷한 위험 신호가 크게 확인되지 않았습니다."
    )


def _build_prompt(
    *,
    url: str,
    score: int,
    cnn_proba: float | None,
    reason_details: list[str],
    features: dict[str, Any],
) -> str:
    vt = features.get("virustotal") or {}
    vt_summary = features.get("vt_model_summary") or {}

    malicious = _as_int(vt.get("malicious"))
    suspicious = _as_int(vt.get("suspicious"))
    harmless = _as_int(vt.get("harmless"))
    undetected = _as_int(vt.get("undetected"))

    model_score = _as_int(features.get("model_score"))
    vt_score = _as_int(features.get("vt_score"))
    final_score = _as_int(features.get("final_score"), score)

    raw_url_type = features.get("url_type") or ""
    user_url_type = _plain_url_type(raw_url_type) or "특별한 위험 유형 없음"

    url_type_reasons = features.get("url_type_reasons") or []
    keyword_hits = features.get("keyword_hits") or []

    important_features = {
        "has_http": features.get("has_http"),
        "has_ip": features.get("has_ip"),
        "has_at": features.get("has_at"),
        "is_shortener": features.get("is_shortener"),
        "suspicious_tld": features.get("suspicious_tld"),
        "path_has_login_like": features.get("path_has_login_like"),
        "keyword_hit_count": features.get("keyword_hit_count"),
        "url_len": features.get("url_len"),
        "query_param_count": features.get("query_param_count"),
        "host_hyphen_count": features.get("host_hyphen_count"),
        "subdomain_depth": features.get("subdomain_depth"),
        "sm_final_host_changed": features.get("sm_final_host_changed"),
    }

    return f"""
너는 모바일 악성 URL 탐지 앱의 사용자용 안내 문구를 작성하는 보안 설명 도우미다.

반드시 한국어로 작성해라.
문장은 2문장, 최대 180자 이내로 작성해라.
반드시 완성된 문장으로 끝내고, 문장 중간에서 끊지 마라.
일반 사용자가 이해하기 쉽게 설명해라.
"일반 정보형"이라는 표현은 절대 쓰지 마라.
특별한 위험 유형이 없으면 "뚜렷한 위험 신호가 크게 확인되지 않았습니다"라고 설명해라.
"100% 악성", "확실히 피싱"처럼 단정하지 마라.
URL 원문을 길게 반복하지 마라.
점수는 바꾸지 말고 그대로 설명해라.
VirusTotal 결과와 자체 모델 결과가 다르면 그 차이를 짧게 설명해라.

[검사 URL]
{url}

[최종 위험도]
{final_score}%

[점수 구성]
- 자체 CNN/룰 기반 점수: {model_score}
- VirusTotal 점수: {vt_score}
- 최종 통합 위험도: {final_score}

[VirusTotal 결과]
- malicious: {malicious}
- suspicious: {suspicious}
- harmless: {harmless}
- undetected: {undetected}

[자체 모델 결과]
- CNN 피싱 확률: {cnn_proba}
- 사용자 표시용 유형 설명: {user_url_type}
- 내부 유형 근거: {url_type_reasons}
- 의심 키워드: {keyword_hits}

[주요 구조 신호]
{important_features}

[판단 근거]
{reason_details}

[비교 결과]
{vt_summary}

출력 형식:
요약 문장만 출력해라. 제목, 불릿, JSON, 따옴표는 쓰지 마라.
""".strip()


def _extract_text(data: dict[str, Any]) -> str:
    candidates = data.get("candidates") or []

    if not candidates:
        return ""

    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []

    texts: list[str] = []

    for part in parts:
        text = part.get("text")
        if text:
            texts.append(str(text).strip())

    return "\n".join(texts).strip()


def _clean_summary_text(text: str) -> str:
    cleaned = str(text or "").replace("\n", " ").strip()
    cleaned = cleaned.strip('"\'` ')

    while "  " in cleaned:
        cleaned = cleaned.replace("  ", " ")

    return cleaned


def _looks_incomplete_summary(text: str) -> bool:
    cleaned = _clean_summary_text(text)

    if len(cleaned) < 18:
        return True

    if "일반 정보형" in cleaned:
        return True

    complete_endings = (
        ".",
        "!",
        "?",
        "다",
        "요",
        "함",
        "됨",
        "임",
        "합니다",
        "됩니다",
        "있습니다",
        "없습니다",
        "필요합니다",
    )

    if not cleaned.endswith(complete_endings):
        return True

    incomplete_tails = (
        "가",
        "이",
        "은",
        "는",
        "을",
        "를",
        "에",
        "에서",
        "으로",
        "로",
        "와",
        "과",
        "및",
        "또는",
        "때문",
        "때문에",
        "같은",
        "등",
    )

    if cleaned.endswith(incomplete_tails):
        return True

    return False


def _limit_summary(text: str, limit: int = 220) -> str:
    cleaned = _clean_summary_text(text)

    if len(cleaned) <= limit:
        return cleaned

    cut = cleaned[:limit].rstrip()

    # 중간에서 끊긴 문장 방지: 마지막 문장부호까지만 사용
    last_positions = [
        cut.rfind("."),
        cut.rfind("!"),
        cut.rfind("?"),
    ]
    last_pos = max(last_positions)

    if last_pos >= 30:
        return cut[: last_pos + 1].strip()

    return ""


def generate_llm_summary(
    *,
    url: str,
    score: int,
    cnn_proba: float | None,
    reason_details: list[str],
    features: dict[str, Any],
) -> str:
    fallback = _fallback_summary(
        score=score,
        cnn_proba=cnn_proba,
        reason_details=reason_details,
        features=features,
    )

    if not GEMINI_API_KEY:
        return fallback

    prompt = _build_prompt(
        url=url,
        score=score,
        cnn_proba=cnn_proba,
        reason_details=reason_details,
        features=features,
    )

    endpoint = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "topP": 0.8,
            "maxOutputTokens": 180,
        },
    }

    try:
        with httpx.Client(timeout=GEMINI_TIMEOUT_SEC) as client:
            res = client.post(
                endpoint,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": GEMINI_API_KEY,
                },
                json=payload,
            )

        if not res.is_success:
            return fallback

        data = res.json()
        text = _clean_summary_text(_extract_text(data))
        text = _limit_summary(text)

        # AI 응답이 비었거나 문장 중간에서 끊기거나 내부 분류명을 그대로 쓰면 기본 요약문 사용
        if not text or _looks_incomplete_summary(text):
            return fallback

        return text

    except Exception:
        return fallback