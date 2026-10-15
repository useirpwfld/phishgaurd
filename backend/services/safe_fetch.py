from __future__ import annotations

from urllib.parse import urljoin, urlparse
import ipaddress
import socket
import time
from typing import Any, Dict, List, Optional

import httpx


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
HEAD_FALLBACK_STATUSES = {403, 405, 429, 501}


def _is_private_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, None)
    ips = []
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ips.append(sockaddr[0])
        elif family == socket.AF_INET6:
            ips.append(sockaddr[0])
    return list(dict.fromkeys(ips))


def _is_blocked_host(host: str) -> bool:
    if not host:
        return True

    h = host.lower().strip()
    if h in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ipaddress.ip_address(h)
        return _is_private_ip(h)
    except ValueError:
        pass

    try:
        ips = _resolve_host_ips(h)
        if not ips:
            return True
        return any(_is_private_ip(ip) for ip in ips)
    except Exception:
        return True


def _normalize_url(url: str) -> str:
    p = urlparse(str(url).strip())
    if not p.scheme:
        return "https://" + str(url).strip()
    return str(url).strip()


def _summarize_headers(response: httpx.Response) -> Dict[str, Any]:
    return {
        "server": response.headers.get("server"),
        "content_type": response.headers.get("content-type"),
        "location": response.headers.get("location"),
    }


def _request_once(client: httpx.Client, url: str, method: str) -> httpx.Response:
    if method == "GET":
        req = client.build_request(method, url, headers={"Range": "bytes=0-0"})
        resp = client.send(req, stream=True)
        resp.read()
        resp.close()
        return resp
    return client.request(method, url)


def safe_head_fetch(
    url: str,
    *,
    max_redirects: int = 3,
    timeout_sec: float = 2.5,
) -> Optional[Dict[str, Any]]:
    """
    Safe Browse Mode:
    - 기본은 HEAD 요청
    - HEAD가 막히면 GET fallback으로 헤더/최종 URL만 수집
    - 리다이렉트 최대 N회
    - SSRF 방지: 사설/로컬 IP 차단
    """
    url = _normalize_url(url)
    p0 = urlparse(url)

    if _is_blocked_host(p0.hostname or ""):
        return {
            "safe_mode": {
                "ok": False,
                "blocked": True,
                "reason": "SSRF 방지: 내부/로컬 대상 차단",
                "start_url": url,
                "request_method": "HEAD",
            }
        }

    redirects: List[Dict[str, Any]] = []
    start = time.perf_counter()
    headers_summary = {"server": None, "content_type": None, "location": None}

    try:
        with httpx.Client(
            timeout=timeout_sec,
            follow_redirects=False,
            headers={"User-Agent": "PhishGuardSafeFetch/1.1"},
        ) as client:
            cur = url
            status_code: Optional[int] = None
            request_method = "HEAD"
            used_get_fallback = False

            for hop in range(max_redirects + 1):
                parsed = urlparse(cur)
                host = parsed.hostname or ""
                if _is_blocked_host(host):
                    return {
                        "safe_mode": {
                            "ok": False,
                            "blocked": True,
                            "reason": "SSRF 방지: 리다이렉트 대상 차단",
                            "start_url": url,
                            "final_url": cur,
                            "redirect_count": len(redirects),
                            "redirects": redirects,
                            "request_method": request_method,
                            "used_get_fallback": used_get_fallback,
                        }
                    }

                response = _request_once(client, cur, request_method)
                status_code = response.status_code
                headers_summary = _summarize_headers(response)

                if request_method == "HEAD" and status_code in HEAD_FALLBACK_STATUSES:
                    request_method = "GET"
                    used_get_fallback = True
                    response = _request_once(client, cur, request_method)
                    status_code = response.status_code
                    headers_summary = _summarize_headers(response)

                loc = headers_summary.get("location")
                if status_code in REDIRECT_STATUSES and loc:
                    redirects.append(
                        {
                            "hop": hop + 1,
                            "from": cur,
                            "status": status_code,
                            "to": loc,
                            "method": request_method,
                        }
                    )
                    cur = urljoin(cur, loc)
                    request_method = "HEAD"
                    continue

                break

            latency_ms = int((time.perf_counter() - start) * 1000)
            return {
                "safe_mode": {
                    "ok": True,
                    "blocked": False,
                    "start_url": url,
                    "final_url": cur,
                    "redirect_count": len(redirects),
                    "redirects": redirects,
                    "http_status": status_code,
                    "server": headers_summary.get("server"),
                    "content_type": headers_summary.get("content_type"),
                    "latency_ms": latency_ms,
                    "request_method": request_method,
                    "used_get_fallback": used_get_fallback,
                }
            }
    except Exception as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return {
            "safe_mode": {
                "ok": False,
                "blocked": False,
                "reason": f"fetch 실패: {type(e).__name__}",
                "start_url": url,
                "latency_ms": latency_ms,
                "request_method": "HEAD",
                "used_get_fallback": False,
            }
        }
