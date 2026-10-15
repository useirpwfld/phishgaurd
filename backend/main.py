from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import Integer, desc, func, or_
from sqlalchemy.orm import Session

from db import get_db
from models import ScanResult
from schemas import DatasetRow, LabelRequest, ScanRequest, ScanResponse
from services.ml import ml_predict
from services.safe_fetch import safe_head_fetch

from init_db import init_db
from services.explain_ai import generate_llm_summary

from services.virustotal import (
    vt_lookup,
    vt_score_from_result,
    combine_model_and_vt_score,
    build_vt_model_summary,
)

logger = logging.getLogger("phishguard.api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="PhishGuard API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "bank", "confirm", "payment", "wallet",
]

URL_TYPE_KEYWORDS = {
    "로그인/계정 유도형": [
        "login", "signin", "sign-in", "account", "verify", "verification",
        "auth", "password", "reset", "confirm", "secure", "security",
    ],
    "결제/금융 유도형": [
        "pay", "payment", "billing", "card", "bank", "wallet",
        "invoice", "refund", "deposit", "loan",
    ],
    "배송/조회 유도형": [
        "delivery", "parcel", "tracking", "track", "post",
        "shipment", "shipping", "courier",
    ],
    "파일 다운로드 유도형": [
        "download", "file", "apk", "exe", "zip", "setup",
        "install", "update", "patch",
    ],
}

FILE_EXTENSIONS = {
    ".apk", ".exe", ".zip", ".rar", ".7z", ".msi", ".scr", ".bat", ".cmd",
}

SHORTENER_HOSTS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "tiny.one", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "tk", "top", "xyz", "click", "buzz", "work", "country", "gq", "ml", "cf",
}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_creative_format", "utm_marketing_tactic",
    "gclid", "gbraid", "wbraid", "gad_source", "gad_campaignid",
    "fbclid", "msclkid", "yclid", "dclid",
    "c_id", "c_agid", "c_crid", "c_kwid", "c_ims", "c_pms", "c_nw", "c_dvc",
}

TRUSTED_HOSTS = {
    "chatgpt.com",
    "www.chatgpt.com",
    "openai.com",
    "www.openai.com",
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "naver.com",
    "www.naver.com",
    "github.com",
    "www.github.com",
    "microsoft.com",
    "www.microsoft.com",
    "apple.com",
    "www.apple.com",
}

VERDICT_PRIORITY = {"malicious": 3, "suspicious": 2, "safe": 1}


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request, exc):
    return PlainTextResponse("rate limit exceeded", status_code=429)


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "phishguard-api",
        "version": app.version,
    }


def normalize_url(url: str) -> str:
    u = str(url).strip().lower()

    if not u:
        return ""

    if "://" not in u:
        u = "https://" + u

    return u


def validate_input_url(url: str) -> tuple[bool, str]:
    u = normalize_url(url)

    if not u:
        return False, "URL을 입력하세요."

    parsed = urlparse(u)
    host = (parsed.hostname or "").strip()

    if not host:
        return False, "도메인 또는 IP가 없는 URL입니다."

    if len(u) > 2048:
        return False, "URL 길이가 너무 깁니다."

    return True, u


def same_root_domain(a: str, b: str) -> bool:
    a = (a or "").lower().strip(".")
    b = (b or "").lower().strip(".")

    if not a or not b:
        return False

    pa = [x for x in a.split(".") if x]
    pb = [x for x in b.split(".") if x]

    if len(pa) < 2 or len(pb) < 2:
        return a == b

    return ".".join(pa[-2:]) == ".".join(pb[-2:])


def score_to_verdict(score: int) -> str:
    if score >= 80:
        return "malicious"

    if score >= 55:
        return "suspicious"

    return "safe"


def simple_score(url: str) -> tuple[int, str, str, list[str]]:
    u = normalize_url(url)

    score = 0
    reasons: list[str] = []

    if u.startswith("http://"):
        score += 20
        reasons.append("HTTP 사용")

    hit = [w for w in SUSPICIOUS_WORDS if w in u]

    if hit:
        score += 20
        reasons.append(f"의심 키워드 {len(hit)}개")

    if "@" in u:
        score += 30
        reasons.append("@ 포함")

    verdict = score_to_verdict(score)
    reason = "; ".join(reasons) if reasons else "특이 패턴 없음"

    return score, verdict, reason, reasons


def extract_features(url: str) -> dict:
    u = normalize_url(url)
    p = urlparse(u)

    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""

    host_parts = [x for x in host.split(".") if x]
    tld = host_parts[-1] if len(host_parts) >= 2 else ""
    subdomain_depth = max(len(host_parts) - 2, 0)

    digit_count = sum(ch.isdigit() for ch in u)
    alpha_count = sum(ch.isalpha() for ch in u)
    special_count = sum(not ch.isalnum() for ch in u)

    host_digit_count = sum(ch.isdigit() for ch in host)
    path_token_count = len([x for x in path.split("/") if x])

    query_pairs = parse_qsl(query, keep_blank_values=True)
    query_param_count = len(query_pairs)

    tracking_param_count = sum(
        1 for k, _ in query_pairs if str(k).lower() in TRACKING_PARAMS
    )
    non_tracking_param_count = max(query_param_count - tracking_param_count, 0)

    hit_words = [w for w in SUSPICIOUS_WORDS if w in u]

    has_punycode = host.startswith("xn--") or ".xn--" in host
    is_shortener = host in SHORTENER_HOSTS
    suspicious_tld = tld in SUSPICIOUS_TLDS
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    is_trusted_host = host in TRUSTED_HOSTS

    brand_keywords = [
        "google", "naver", "kakao", "microsoft",
        "apple", "paypal", "amazon", "github", "openai", "chatgpt",
    ]

    brand_hit_count = sum(1 for b in brand_keywords if b in host or b in path)

    return {
        "scheme": p.scheme,
        "host": host,
        "tld": tld,
        "has_https": int(p.scheme == "https"),
        "has_http": int(p.scheme == "http"),
        "has_at": int("@" in u),
        "has_ip": int(has_ip),
        "path_len": len(path),
        "query_len": len(query),
        "url_len": len(u),
        "keyword_hit_count": len(hit_words),
        "domain_len": len(host),
        "host_dot_count": host.count("."),
        "host_hyphen_count": host.count("-"),
        "digit_count": digit_count,
        "digit_ratio": round(digit_count / max(len(u), 1), 6),
        "alpha_ratio": round(alpha_count / max(len(u), 1), 6),
        "special_ratio": round(special_count / max(len(u), 1), 6),
        "host_digit_count": host_digit_count,
        "host_digit_ratio": round(host_digit_count / max(len(host), 1), 6),
        "subdomain_depth": subdomain_depth,
        "path_token_count": path_token_count,
        "query_param_count": query_param_count,
        "tracking_param_count": tracking_param_count,
        "non_tracking_param_count": non_tracking_param_count,
        "has_punycode": int(has_punycode),
        "is_shortener": int(is_shortener),
        "suspicious_tld": int(suspicious_tld),
        "is_trusted_host": int(is_trusted_host),
        "keyword_hits": hit_words,
        "path_has_login_like": int(
            any(w in path.lower() for w in ["login", "signin", "verify", "account"])
        ),
        "brand_hit_count": brand_hit_count,
    }


def analyze_url_type(url: str, features: dict) -> dict:
    u = normalize_url(url)
    p = urlparse(u)

    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    query = (p.query or "").lower()
    full_text = f"{host} {path} {query}".lower()

    type_items: list[dict[str, Any]] = []

    def add_type(type_name: str, score: int, reasons: list[str]):
        if score <= 0:
            return

        type_items.append({
            "type": type_name,
            "score": score,
            "reasons": reasons,
        })

    for type_name, words in URL_TYPE_KEYWORDS.items():
        hits = [w for w in words if w in full_text]

        if hits:
            score = min(100, 40 + len(hits) * 15)
            reasons = [f"관련 키워드 포함: {', '.join(hits[:5])}"]
            add_type(type_name, score, reasons)

    if int(features.get("is_shortener") or 0) == 1:
        add_type(
            "단축 URL형",
            90,
            ["bit.ly, t.co, tinyurl 등 단축 URL 도메인 사용"],
        )

    if int(features.get("has_ip") or 0) == 1:
        add_type(
            "IP 직접 접속형",
            95,
            ["도메인 이름 대신 IP 주소를 직접 사용"],
        )

    url_len = int(features.get("url_len") or 0)
    query_len = int(features.get("query_len") or 0)
    query_param_count = int(features.get("query_param_count") or 0)
    tracking_param_count = int(features.get("tracking_param_count") or 0)
    non_tracking_param_count = int(
        features.get("non_tracking_param_count", query_param_count) or 0
    )

    long_query_reasons = []

    if url_len >= 120:
        long_query_reasons.append(f"URL 길이 김: {url_len}자")

    if query_len >= 80:
        if tracking_param_count >= 5 and non_tracking_param_count <= 2:
            long_query_reasons.append(f"광고/추적 파라미터 길이 김: {query_len}자")
        else:
            long_query_reasons.append(f"쿼리 길이 김: {query_len}자")

    if non_tracking_param_count >= 5:
        long_query_reasons.append(f"쿼리 파라미터 많음: {non_tracking_param_count}개")
    elif query_param_count >= 8 and tracking_param_count >= 5:
        long_query_reasons.append(f"광고/추적 파라미터 많음: {tracking_param_count}개")

    if long_query_reasons:
        score = 50

        if tracking_param_count >= 5 and non_tracking_param_count <= 2:
            score = 30
        else:
            if url_len >= 180:
                score += 20

            if non_tracking_param_count >= 8:
                score += 20

        add_type(
            "긴 URL/쿼리 과다형",
            min(score, 100),
            long_query_reasons,
        )

    subdomain_depth = int(features.get("subdomain_depth") or 0)
    host_dot_count = int(features.get("host_dot_count") or 0)

    if subdomain_depth >= 3 or host_dot_count >= 4:
        add_type(
            "하위 도메인 과다형",
            min(100, 50 + subdomain_depth * 10),
            [
                f"하위 도메인 깊이: {subdomain_depth}",
                f"도메인 점 개수: {host_dot_count}",
            ],
        )

    obfuscation_reasons = []

    if int(features.get("has_at") or 0) == 1:
        obfuscation_reasons.append("@ 문자 포함")

    if int(features.get("has_punycode") or 0) == 1:
        obfuscation_reasons.append("punycode 사용")

    if int(features.get("host_hyphen_count") or 0) >= 2:
        obfuscation_reasons.append(f"하이픈 많음: {features.get('host_hyphen_count')}개")

    if float(features.get("digit_ratio") or 0) >= 0.25:
        obfuscation_reasons.append(f"숫자 비율 높음: {features.get('digit_ratio')}")

    if float(features.get("host_digit_ratio") or 0) >= 0.20:
        obfuscation_reasons.append(f"도메인 숫자 비율 높음: {features.get('host_digit_ratio')}")

    if obfuscation_reasons:
        add_type(
            "난독화/특수문자형",
            min(100, 55 + len(obfuscation_reasons) * 10),
            obfuscation_reasons,
        )

    if int(features.get("suspicious_tld") or 0) == 1:
        add_type(
            "의심 TLD형",
            65,
            [f"의심 TLD 사용: .{features.get('tld')}"],
        )

    if int(features.get("sm_final_host_changed") or 0) == 1:
        add_type(
            "리다이렉트 도메인 변경형",
            85,
            [
                f"입력 도메인: {features.get('host')}",
                f"최종 도메인: {features.get('sm_final_host')}",
            ],
        )

    if any(path.endswith(ext) for ext in FILE_EXTENSIONS):
        ext = next((e for e in FILE_EXTENSIONS if path.endswith(e)), "")
        add_type(
            "파일 다운로드 유도형",
            90,
            [f"실행/압축 파일 확장자 포함: {ext}"],
        )

    if not type_items:
        return {
            "primary_type": "일반 정보형",
            "primary_score": 0,
            "types": [],
            "reasons": ["특정 위험 유형으로 분류할 만한 URL 구조 특징이 적음"],
        }

    type_items.sort(key=lambda x: x["score"], reverse=True)
    primary = type_items[0]

    summary_reasons: list[str] = []

    for item in type_items[:3]:
        item_reasons = item.get("reasons") or []

        if item_reasons:
            summary_reasons.append(f"{item['type']}: {item_reasons[0]}")

    return {
        "primary_type": primary["type"],
        "primary_score": primary["score"],
        "types": type_items,
        "reasons": summary_reasons,
    }


def cnn_score_from_ml(ml_proba: float) -> int:
    """
    전체 URL CNN 점수: 최대 40점.
    """
    if ml_proba >= 0.995:
        return 40

    if ml_proba >= 0.990:
        return 34

    if ml_proba >= 0.970:
        return 28

    if ml_proba >= 0.930:
        return 22

    if ml_proba >= 0.880:
        return 16

    if ml_proba >= 0.780:
        return 10

    if ml_proba >= 0.650:
        return 5

    return 0


def rule_score_from_scan(features: dict, sm_info: dict | None) -> tuple[int, list[str]]:
    """
    URL 구조 룰 점수: 최대 60점.
    """
    score = 0
    reasons: list[str] = []

    keyword_hit_count = int(features.get("keyword_hit_count") or 0)
    has_http = int(features.get("has_http") or 0)
    has_at = int(features.get("has_at") or 0)
    has_ip = int(features.get("has_ip") or 0)
    is_shortener = int(features.get("is_shortener") or 0)
    has_punycode = int(features.get("has_punycode") or 0)
    suspicious_tld = int(features.get("suspicious_tld") or 0)
    subdomain_depth = int(features.get("subdomain_depth") or 0)
    host_hyphen_count = int(features.get("host_hyphen_count") or 0)
    path_has_login_like = int(features.get("path_has_login_like") or 0)
    query_param_count = int(features.get("query_param_count") or 0)
    tracking_param_count = int(features.get("tracking_param_count") or 0)
    non_tracking_param_count = int(
        features.get("non_tracking_param_count", query_param_count) or 0
    )
    query_len = int(features.get("query_len") or 0)
    url_len = int(features.get("url_len") or 0)
    brand_hit_count = int(features.get("brand_hit_count") or 0)
    digit_ratio = float(features.get("digit_ratio") or 0)
    host_dot_count = int(features.get("host_dot_count") or 0)

    if has_http == 1:
        score += 10
        reasons.append("HTTP 사용")

    if keyword_hit_count >= 3:
        score += 12
        reasons.append(f"의심 키워드 {keyword_hit_count}개")
    elif keyword_hit_count >= 1:
        score += 6
        reasons.append(f"의심 키워드 {keyword_hit_count}개")

    if has_at == 1:
        score += 40
        reasons.append("@ 포함")

    if has_ip == 1:
        score += 25
        reasons.append("IP 주소 사용")

    if is_shortener == 1:
        score += 8
        reasons.append("축약 URL")

    if has_punycode == 1:
        score += 16
        reasons.append("punycode")

    if suspicious_tld == 1:
        score += 10
        reasons.append("의심 TLD")

    if subdomain_depth >= 4:
        score += 12
        reasons.append("서브도메인 과다")
    elif subdomain_depth >= 3:
        score += 8
        reasons.append("서브도메인 많음")

    if host_hyphen_count >= 2:
        score += 6
        reasons.append("하이픈 과다")

    if path_has_login_like == 1:
        score += 10
        reasons.append("로그인/계정 경로")

    if non_tracking_param_count >= 6:
        score += 8
        reasons.append("쿼리 파라미터 많음")
    elif non_tracking_param_count >= 3:
        score += 4
        reasons.append("쿼리 파라미터 존재")
    elif query_param_count >= 6 and tracking_param_count >= 5:
        score += 2
        reasons.append("광고/추적 파라미터 많음")

    if query_len >= 80:
        if tracking_param_count >= 5 and non_tracking_param_count <= 2:
            score += 2
            reasons.append("광고/추적 파라미터 길이 김")
        else:
            score += 8
            reasons.append("쿼리 길이 김")
    elif query_len >= 30:
        score += 4
        reasons.append("쿼리 길이 다소 김")

    if url_len >= 120:
        if tracking_param_count >= 5 and non_tracking_param_count <= 2:
            score += 2
            reasons.append("광고 URL 길이 김")
        else:
            score += 6
            reasons.append("URL 길이 김")

    if digit_ratio >= 0.30:
        if tracking_param_count >= 5 and non_tracking_param_count <= 2:
            score += 1
            reasons.append("광고 추적 ID 포함")
        else:
            score += 5
            reasons.append("숫자 비율 높음")

    if brand_hit_count >= 1 and path_has_login_like == 1:
        score += 8
        reasons.append("브랜드 + 로그인 경로 조합")

    if host_dot_count == 0 and has_ip == 0:
        score += 15
        reasons.append("도트 없는 host")

    if sm_info:
        if sm_info.get("ok"):
            rc = int(sm_info.get("redirect_count") or 0)
            st = int(sm_info.get("http_status") or 0)

            if rc >= 3:
                score += 12
                reasons.append("리다이렉트 3회 이상")
            elif rc >= 2:
                score += 8
                reasons.append("리다이렉트 2회 이상")

            if st in (403, 429):
                score += 4
                reasons.append(f"응답 제한 {st}")

            if int(features.get("sm_final_host_changed") or 0) == 1:
                score += 12
                reasons.append("최종 도메인 변경")

        elif sm_info.get("blocked"):
            score += 10
            reasons.append("내부/로컬 대상 차단")

    return min(60, score), reasons


def combine_scores(cnn_score: int, rule_score: int, features: dict, sm_info: dict | None) -> tuple[int, list[str]]:
    """
    최종 자체 모델 점수.
    CNN 전체 URL 패턴 점수 + URL 구조 룰 점수 + 위험 조합 보너스.
    """
    bonus = 0
    bonus_reasons: list[str] = []

    has_ip = int(features.get("has_ip") or 0)
    has_at = int(features.get("has_at") or 0)
    has_http = int(features.get("has_http") or 0)
    path_has_login_like = int(features.get("path_has_login_like") or 0)
    suspicious_tld = int(features.get("suspicious_tld") or 0)

    if cnn_score >= 22 and path_has_login_like == 1:
        bonus += 8
        bonus_reasons.append("CNN 위험 패턴 + 로그인 경로")

    if cnn_score >= 22 and suspicious_tld == 1:
        bonus += 6
        bonus_reasons.append("CNN 위험 패턴 + 의심 TLD")

    if has_ip == 1 and has_http == 1:
        bonus += 10
        bonus_reasons.append("HTTP + IP 조합")

    if has_at == 1 and path_has_login_like == 1:
        bonus += 10
        bonus_reasons.append("@ + 로그인 경로 조합")

    if sm_info and int(features.get("sm_final_host_changed") or 0) == 1 and cnn_score >= 16:
        bonus += 8
        bonus_reasons.append("CNN 위험 패턴 + 최종 도메인 변경")

    if has_at == 1:
        bonus += 20
        bonus_reasons.append("@ 단독 고위험")

    final_score = min(100, cnn_score + rule_score + bonus)

    if has_at == 1:
        final_score = max(final_score, 70)

    is_trusted_host = int(features.get("is_trusted_host") or 0)
    tracking_param_count = int(features.get("tracking_param_count") or 0)
    non_tracking_param_count = int(features.get("non_tracking_param_count") or 0)

    if (
        is_trusted_host == 1
        and tracking_param_count >= 5
        and non_tracking_param_count <= 2
        and has_http == 0
        and path_has_login_like == 0
        and suspicious_tld == 0
        and has_at == 0
        and has_ip == 0
    ):
        final_score = min(final_score, 30)
        bonus_reasons.append("신뢰 도메인 광고 URL 보정")

    return final_score, bonus_reasons


def build_response(
    row: ScanResult | None,
    *,
    url: str,
    normalized_url: str,
    score: int,
    verdict: str,
    reason: str,
    reason_details: list[str],
    features: dict[str, Any],
    model_version: str,
    created_at: datetime,
    persisted: bool,
    label: str | None,
    ml_proba: float | None,
    ml_proba_local: float | None,
    ml_proba_public: float | None,
    safe_mode: dict[str, Any] | None,
    row_id: int,
    llm_summary: str | None,
) -> ScanResponse:
    return ScanResponse(
        id=row.id if row else row_id,
        url=url,
        normalized_url=normalized_url,
        score=score,
        verdict=verdict,
        reason=reason,
        reason_details=reason_details,
        features=features,
        model_version=model_version,
        created_at=created_at,
        persisted=persisted,
        label=label,
        ml_proba=ml_proba,
        ml_proba_local=ml_proba_local,
        ml_proba_public=ml_proba_public,
        safe_mode=safe_mode or {},
        llm_summary=llm_summary,
    )


@app.post("/scan", response_model=ScanResponse)
@limiter.limit("30/minute")
def scan(request: Request, req: ScanRequest, db: Session = Depends(get_db)):
    ok, normalized_or_message = validate_input_url(req.url)

    if not ok:
        raise HTTPException(status_code=422, detail=normalized_or_message)

    url_str = str(req.url).strip()
    normalized_url = normalized_or_message

    features = extract_features(normalized_url)
    sm_info: dict[str, Any] | None = None

    try:
        sm = safe_head_fetch(normalized_url, max_redirects=3, timeout_sec=2.5)

        if sm:
            features.update(sm)
            sm_info = sm.get("safe_mode") if isinstance(sm, dict) else None

            if isinstance(sm_info, dict):
                features["sm_ok"] = 1 if sm_info.get("ok") else 0
                features["sm_redirect_count"] = int(sm_info.get("redirect_count") or 0)
                features["sm_http_status"] = int(sm_info.get("http_status") or 0)
                features["sm_latency_ms"] = int(sm_info.get("latency_ms") or 0)
                features["sm_used_get_fallback"] = int(bool(sm_info.get("used_get_fallback")))

                final_url = sm_info.get("final_url") or ""
                final_host = (urlparse(final_url).hostname or "").lower() if final_url else ""
                input_host = (urlparse(normalized_url).hostname or "").lower()

                features["sm_final_host"] = final_host
                features["sm_final_host_changed"] = int(
                    bool(final_host) and not same_root_domain(final_host, input_host)
                )

    except Exception:
        logger.exception("safe_head_fetch failed")

    url_type_info = analyze_url_type(normalized_url, features)
    features["url_type"] = url_type_info["primary_type"]
    features["url_type_score"] = url_type_info["primary_score"]
    features["url_types"] = url_type_info["types"]
    features["url_type_reasons"] = url_type_info["reasons"]

    ml_proba = None
    ml_proba_local = None
    ml_proba_public = None
    reason_details: list[str] = []

    m = ml_predict(features, normalized_url)

    if m is not None:
        proba, model_version, meta = m
        ml_proba = float(proba)

        cnn_score = cnn_score_from_ml(ml_proba)
        rule_score, rule_reasons = rule_score_from_scan(features, sm_info)
        score, bonus_reasons = combine_scores(cnn_score, rule_score, features, sm_info)

        features["cnn_proba"] = ml_proba
        features["cnn_score"] = cnn_score
        features["ml_meta"] = meta
        features["cnn_input"] = meta.get("cnn_input")
        features["ml_input_mode"] = meta.get("input_mode")

        reason_details = [
            "CNN 전체 URL 패턴 분석",
            f"dl={ml_proba:.3f}",
            f"cnn_score={cnn_score}",
            f"rule_score={rule_score}",
        ]

        if rule_reasons:
            reason_details.extend(rule_reasons)

        if bonus_reasons:
            reason_details.extend(bonus_reasons)

        verdict = score_to_verdict(score)
        reason = "; ".join(reason_details)

    else:
        score, verdict, reason, reason_details = simple_score(normalized_url)
        model_version = "rule_v1"

    model_score = int(score)

    vt_result = vt_lookup(normalized_url)
    vt_score = vt_score_from_result(vt_result)

    final_score = combine_model_and_vt_score(model_score, vt_score)

    vt_model_summary = build_vt_model_summary(
        vt_result=vt_result,
        model_score=model_score,
        vt_score=vt_score,
        final_score=final_score,
    )

    features["model_score"] = model_score
    features["virustotal"] = vt_result
    features["vt_score"] = vt_score
    features["final_score"] = final_score
    features["vt_model_summary"] = vt_model_summary

    reason_details.append(f"model_score={model_score}")
    reason_details.append(f"vt_score={vt_score}")
    reason_details.append(f"final_score={final_score}")
    reason_details.append(vt_model_summary["case"])

    score = final_score
    verdict = score_to_verdict(score)
    reason = "; ".join(reason_details)

    llm_summary = generate_llm_summary(
        url=normalized_url,
        score=score,
        cnn_proba=ml_proba,
        reason_details=reason_details,
        features=features,
    )

    try:
        row = ScanResult(
            url=normalized_url,
            score=score,
            verdict=verdict,
            reason=reason,
            features=features,
            model_version=model_version,
            label=None,
            ml_proba=ml_proba,
            ml_proba_local=ml_proba_local,
            ml_proba_public=ml_proba_public,
        )

        db.add(row)
        db.commit()
        db.refresh(row)

        return build_response(
            row,
            url=url_str,
            normalized_url=normalized_url,
            score=row.score,
            verdict=row.verdict,
            reason=row.reason,
            reason_details=reason_details,
            features=row.features,
            model_version=row.model_version,
            created_at=row.created_at,
            persisted=True,
            label=row.label,
            ml_proba=row.ml_proba,
            ml_proba_local=row.ml_proba_local,
            ml_proba_public=row.ml_proba_public,
            safe_mode=features.get("safe_mode"),
            row_id=row.id,
            llm_summary=llm_summary,
        )

    except Exception:
        logger.exception("DB save failed")

        try:
            db.rollback()
        except Exception:
            logger.exception("DB rollback failed")

        return build_response(
            None,
            url=url_str,
            normalized_url=normalized_url,
            score=score,
            verdict=verdict,
            reason=reason,
            reason_details=reason_details,
            features=features,
            model_version=model_version,
            created_at=datetime.now(timezone.utc),
            persisted=False,
            label=None,
            ml_proba=ml_proba,
            ml_proba_local=ml_proba_local,
            ml_proba_public=ml_proba_public,
            safe_mode=features.get("safe_mode"),
            row_id=-1,
            llm_summary=llm_summary,
        )


@app.get("/scans", response_model=list[ScanResponse])
@limiter.limit("120/minute")
def scans(
    request: Request,
    verdict: str | None = Query(default=None),
    label: str | None = Query(default=None),
    sort: str = Query(default="recent"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(ScanResult)

    if verdict in {"safe", "suspicious", "malicious"}:
        query = query.filter(ScanResult.verdict == verdict)

    if label == "none":
        query = query.filter(ScanResult.label.is_(None))
    elif label in {"safe", "unknown", "malicious"}:
        query = query.filter(ScanResult.label == label)

    if sort == "score_desc":
        query = query.order_by(desc(ScanResult.score), desc(ScanResult.id))
    elif sort == "score_asc":
        query = query.order_by(ScanResult.score.asc(), desc(ScanResult.id))
    else:
        query = query.order_by(desc(ScanResult.id))

    rows = query.limit(limit).all()
    out: list[ScanResponse] = []

    for r in rows:
        reason_details = [x.strip() for x in (r.reason or "").split(";") if x.strip()]

        out.append(
            build_response(
                r,
                url=r.url,
                normalized_url=r.url,
                score=r.score,
                verdict=r.verdict,
                reason=r.reason,
                reason_details=reason_details,
                features=r.features or {},
                model_version=r.model_version,
                created_at=r.created_at,
                persisted=True,
                label=r.label,
                ml_proba=r.ml_proba,
                ml_proba_local=r.ml_proba_local,
                ml_proba_public=r.ml_proba_public,
                safe_mode=(r.features or {}).get("safe_mode") if isinstance(r.features, dict) else {},
                row_id=r.id,
                llm_summary=None,
            )
        )

    return out


@app.get("/stats")
@limiter.limit("120/minute")
def stats(request: Request, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    scans_24h = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.created_at >= last_24h)
        .scalar()
        or 0
    )

    scans_7d = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.created_at >= last_7d)
        .scalar()
        or 0
    )

    total = db.query(func.count(ScanResult.id)).scalar() or 0

    by_verdict_rows = (
        db.query(ScanResult.verdict, func.count(ScanResult.id))
        .group_by(ScanResult.verdict)
        .all()
    )

    by_model_rows = (
        db.query(ScanResult.model_version, func.count(ScanResult.id))
        .group_by(ScanResult.model_version)
        .all()
    )

    labeled = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.label.in_(["safe", "malicious"]))
        .scalar()
        or 0
    )

    ml_used = (
        db.query(func.count(ScanResult.id))
        .filter(
            or_(
                ScanResult.model_version.like("ml_%"),
                ScanResult.model_version.like("public_%"),
                ScanResult.model_version.like("ensemble_gate(%"),
            )
        )
        .scalar()
        or 0
    )

    avg_score = db.query(func.avg(ScanResult.score)).scalar()

    ensemble_used = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.model_version.like("ensemble_gate(%"))
        .scalar()
        or 0
    )

    safe_mode_ok = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.features["sm_ok"].astext == "1")
        .scalar()
        or 0
    )

    redirect_ge_2 = (
        db.query(func.count(ScanResult.id))
        .filter(
            func.coalesce(ScanResult.features["sm_redirect_count"].astext, "0")
            .cast(Integer) >= 2
        )
        .scalar()
        or 0
    )

    by_verdict = {v: c for v, c in by_verdict_rows}
    verdict_ratio = {k: (v / total if total else 0) for k, v in by_verdict.items()}

    return {
        "total_scans": total,
        "labeled_scans": labeled,
        "ml_used_scans": ml_used,
        "ml_used_ratio": (ml_used / total) if total else 0,
        "avg_score": float(avg_score) if avg_score is not None else None,
        "by_verdict": by_verdict,
        "by_verdict_ratio": verdict_ratio,
        "by_model_version": {m: c for m, c in by_model_rows},
        "updated_at": datetime.now(timezone.utc),
        "recent": {
            "scans_24h": scans_24h,
            "scans_7d": scans_7d,
        },
        "ensemble_used_scans": ensemble_used,
        "ensemble_used_ratio": (ensemble_used / total) if total else 0,
        "safe_mode_ok_scans": safe_mode_ok,
        "safe_mode_ok_ratio": (safe_mode_ok / total) if total else 0,
        "redirect_ge_2_scans": redirect_ge_2,
        "redirect_ge_2_ratio": (redirect_ge_2 / total) if total else 0,
    }


@app.patch("/scans/{scan_id}/label")
def set_label(scan_id: int, req: LabelRequest, db: Session = Depends(get_db)):
    row = db.query(ScanResult).filter(ScanResult.id == scan_id).first()

    if not row:
        raise HTTPException(status_code=404, detail="scan not found")

    row.label = req.label
    db.commit()
    db.refresh(row)

    return {
        "id": row.id,
        "label": row.label,
    }


@app.get("/dataset", response_model=list[DatasetRow])
def dataset(db: Session = Depends(get_db)):
    rows = (
        db.query(ScanResult)
        .filter(ScanResult.label.in_(["safe", "malicious"]))
        .order_by(ScanResult.id.desc())
        .limit(5000)
        .all()
    )

    return rows