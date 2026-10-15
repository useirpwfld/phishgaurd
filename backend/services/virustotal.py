from __future__ import annotations

import base64
import os
from typing import Any

import httpx


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VT_ENABLED = os.getenv("VT_ENABLED", "0").strip() == "1"
VT_TIMEOUT_SEC = float(os.getenv("VT_TIMEOUT_SEC", "6"))


def _url_id(url: str) -> str:
    raw = str(url or "").encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def vt_lookup(url: str) -> dict[str, Any]:
    """
    VirusTotal URL 리포트 조회.
    분석 요청이 아니라 기존 리포트 조회 방식이다.
    """
    if not VT_ENABLED:
        return {
            "ok": False,
            "enabled": False,
            "found": False,
            "error": "VirusTotal disabled",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "vt_detected": False,
        }

    if not VT_API_KEY:
        return {
            "ok": False,
            "enabled": True,
            "found": False,
            "error": "VIRUSTOTAL_API_KEY missing",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "vt_detected": False,
        }

    endpoint = f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}"

    try:
        with httpx.Client(timeout=VT_TIMEOUT_SEC) as client:
            resp = client.get(endpoint, headers={"x-apikey": VT_API_KEY})

        if resp.status_code == 404:
            return {
                "ok": True,
                "enabled": True,
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "vt_detected": False,
            }

        resp.raise_for_status()
        data = resp.json()

        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)

        return {
            "ok": True,
            "enabled": True,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "vt_detected": malicious >= 1 or suspicious >= 1,
        }

    except Exception as e:
        return {
            "ok": False,
            "enabled": True,
            "found": False,
            "error": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "vt_detected": False,
        }


def vt_score_from_result(vt_result: dict[str, Any]) -> int:
    """
    VirusTotal malicious / suspicious 결과를 0~95점으로 변환한다.

    기준:
    - malicious 0, suspicious 0 -> 0
    - suspicious 1~2 -> 40
    - suspicious 3 이상 -> 55
    - malicious 1~2 -> 70
    - malicious 3~5 -> 85
    - malicious 6 이상 -> 95
    """
    malicious = int(vt_result.get("malicious") or 0)
    suspicious = int(vt_result.get("suspicious") or 0)

    if malicious >= 6:
        return 95

    if malicious >= 3:
        return 85

    if malicious >= 1:
        return 70

    if suspicious >= 3:
        return 55

    if suspicious >= 1:
        return 40

    return 0


def combine_model_and_vt_score(model_score: int, vt_score: int) -> int:
    """
    자체 CNN/룰 점수와 VirusTotal 점수를 통합한다.

    기준:
    - 한쪽이라도 55점 이상이면 위험 신호가 있다고 보고 높은 점수(max)를 사용
    - 둘 다 55점 미만이면 안전 구간으로 보고 낮은 점수(min)를 사용
    - 둘 다 위험 신호가 있으면 +5점 보정
    - 최종 점수는 0~100점으로 제한
    """
    model_score = int(model_score or 0)
    vt_score = int(vt_score or 0)

    model_risky = model_score >= 55
    vt_risky = vt_score >= 55

    if model_risky or vt_risky:
        final_score = max(model_score, vt_score)

        if model_risky and vt_risky:
            final_score += 5
    else:
        final_score = min(model_score, vt_score)

    return max(0, min(100, final_score))


def build_vt_model_summary(
    *,
    vt_result: dict[str, Any],
    model_score: int,
    vt_score: int,
    final_score: int,
) -> dict[str, Any]:
    """
    자체 분석과 VirusTotal 결과의 관계를 요약한다.
    이 값은 features에 저장되고 AI 요약 근거로도 사용된다.
    """
    malicious = int(vt_result.get("malicious") or 0)
    suspicious = int(vt_result.get("suspicious") or 0)

    model_detected = int(model_score or 0) >= 55
    vt_detected = int(vt_score or 0) >= 55

    if model_detected and vt_detected:
        case = "자체 분석과 VirusTotal 모두 위험 신호 탐지"
        message = "자체 CNN/룰 기반 분석과 VirusTotal 외부 평판 모두에서 위험 신호가 확인되었습니다."
    elif model_detected and not vt_detected:
        case = "VirusTotal 미탐지, 자체 분석 탐지"
        message = "VirusTotal에서는 뚜렷한 탐지가 없었지만, URL 구조와 문자열 패턴에서 위험 신호가 확인되었습니다."
    elif not model_detected and vt_detected:
        case = "VirusTotal 탐지, 자체 분석 낮음"
        message = "URL 구조상 위험 신호는 낮지만, VirusTotal 외부 평판에서 악성 또는 의심 탐지 결과가 확인되었습니다."
    else:
        case = "자체 분석과 VirusTotal 모두 낮은 위험"
        message = "자체 분석과 VirusTotal 결과 모두에서 강한 위험 신호는 확인되지 않았습니다."

    return {
        "case": case,
        "message": message,
        "model_detected": model_detected,
        "vt_detected": vt_detected,
        "model_score": int(model_score or 0),
        "vt_score": int(vt_score or 0),
        "final_score": int(final_score or 0),
        "malicious": malicious,
        "suspicious": suspicious,
    }


def make_combined_result(vt_result: dict[str, Any], cnn_proba: float | None) -> dict[str, Any]:
    """
    기존 explain_ai.py 호환용.
    기존 코드에서 features['combined']를 쓰고 있을 수 있으므로 유지한다.
    """
    vt_score = vt_score_from_result(vt_result)

    vt_detected = vt_score >= 55
    cnn_detected = cnn_proba is not None and float(cnn_proba) >= 0.5

    combined_detected = vt_detected or cnn_detected

    if vt_detected and cnn_detected:
        case = "VirusTotal과 CNN 모두 탐지"
        message = "외부 보안 엔진과 자체 CNN 모델이 모두 위험 신호를 탐지했습니다."
    elif not vt_detected and cnn_detected:
        case = "VirusTotal 미탐지, CNN 탐지"
        message = "VirusTotal에서는 탐지되지 않았지만, 자체 CNN 모델이 URL 문자열의 위험 패턴을 감지했습니다."
    elif vt_detected and not cnn_detected:
        case = "VirusTotal 탐지, CNN 미탐지"
        message = "자체 CNN 모델의 위험도는 낮지만, VirusTotal에서 악성 또는 의심으로 탐지되었습니다."
    else:
        case = "둘 다 미탐지"
        message = "VirusTotal과 자체 CNN 모델 모두 큰 위험 신호를 탐지하지 않았습니다."

    return {
        "vt_detected": vt_detected,
        "cnn_detected": cnn_detected,
        "combined_detected": combined_detected,
        "case": case,
        "message": message,
        "vt_score": vt_score,
    }