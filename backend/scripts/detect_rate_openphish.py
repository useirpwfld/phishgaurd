import csv
import time
from pathlib import Path

import requests


API_URL = "http://127.0.0.1:8000/scan"

BASE_DIR = Path(__file__).resolve().parent
URL_FILE = BASE_DIR / "openphish_50.txt"
OUT_CSV = BASE_DIR / "openphish_detection_result.csv"


APP_THRESHOLD = 55


def is_vt_detected(features: dict) -> bool:
    vt = features.get("virustotal") or {}

    malicious = int(vt.get("malicious") or 0)
    suspicious = int(vt.get("suspicious") or 0)

    return malicious >= 1 or suspicious >= 1


def main():
    if not URL_FILE.exists():
        raise FileNotFoundError(f"URL file not found: {URL_FILE}")

    urls = [
        line.strip()
        for line in URL_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        raise RuntimeError("URL list is empty.")

    print(f"[TEST URL COUNT] {len(urls)}")
    print("[INFO] 모든 URL은 OpenPhish 피싱 URL로 간주하고 탐지율만 계산합니다.")
    print()

    results = []

    vt_detect_count = 0
    app_detect_count = 0
    both_detect_count = 0
    app_only_count = 0
    vt_only_count = 0
    both_miss_count = 0

    for idx, url in enumerate(urls, start=1):
        print(f"[{idx}/{len(urls)}] scan: {url}")

        try:
            resp = requests.post(
                API_URL,
                json={"url": url},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()

            features = data.get("features") or {}
            vt = features.get("virustotal") or {}

            app_score = int(data.get("score") or 0)
            model_score = int(features.get("model_score") or 0)
            vt_score = int(features.get("vt_score") or 0)

            vt_malicious = int(vt.get("malicious") or 0)
            vt_suspicious = int(vt.get("suspicious") or 0)
            vt_harmless = int(vt.get("harmless") or 0)
            vt_undetected = int(vt.get("undetected") or 0)

            vt_detected = vt_malicious >= 1 or vt_suspicious >= 1
            app_detected = app_score >= APP_THRESHOLD

            if vt_detected:
                vt_detect_count += 1

            if app_detected:
                app_detect_count += 1

            if vt_detected and app_detected:
                both_detect_count += 1
            elif app_detected and not vt_detected:
                app_only_count += 1
            elif vt_detected and not app_detected:
                vt_only_count += 1
            else:
                both_miss_count += 1

            results.append({
                "url": url,
                "vt_detected": int(vt_detected),
                "app_detected": int(app_detected),
                "app_score": app_score,
                "model_score": model_score,
                "vt_score": vt_score,
                "vt_malicious": vt_malicious,
                "vt_suspicious": vt_suspicious,
                "vt_harmless": vt_harmless,
                "vt_undetected": vt_undetected,
                "verdict": data.get("verdict", ""),
                "reason": data.get("reason", ""),
            })

        except Exception as e:
            print(f"[ERROR] {url}: {e}")

            results.append({
                "url": url,
                "vt_detected": -1,
                "app_detected": -1,
                "app_score": -1,
                "model_score": -1,
                "vt_score": -1,
                "vt_malicious": -1,
                "vt_suspicious": -1,
                "vt_harmless": -1,
                "vt_undetected": -1,
                "verdict": "error",
                "reason": str(e),
            })

        # VirusTotal API 제한이나 서버 부하 방지용.
        # 너무 느리면 2~3으로 줄이고, 429가 나오면 20 이상으로 늘려라.
        time.sleep(5)

    valid = [
        r for r in results
        if int(r["vt_detected"]) >= 0 and int(r["app_detected"]) >= 0
    ]

    total = len(valid)

    vt_rate = vt_detect_count / total if total else 0
    app_rate = app_detect_count / total if total else 0

    with OUT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        fieldnames = [
            "url",
            "vt_detected",
            "app_detected",
            "app_score",
            "model_score",
            "vt_score",
            "vt_malicious",
            "vt_suspicious",
            "vt_harmless",
            "vt_undetected",
            "verdict",
            "reason",
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print()
    print("========== OpenPhish 탐지율 비교 ==========")
    print(f"테스트 URL 수: {total}")
    print()
    print("+----------------+----------+----------+")
    print("| 방식           | 탐지 수  | 탐지율   |")
    print("+----------------+----------+----------+")
    print(f"| VirusTotal 단독 | {vt_detect_count:>8} | {vt_rate:>7.2%} |")
    print(f"| 본 앱           | {app_detect_count:>8} | {app_rate:>7.2%} |")
    print("+----------------+----------+----------+")
    print()
    print("========== 탐지 차이 ==========")
    print(f"둘 다 탐지        : {both_detect_count}")
    print(f"본 앱만 탐지      : {app_only_count}")
    print(f"VirusTotal만 탐지 : {vt_only_count}")
    print(f"둘 다 미탐        : {both_miss_count}")
    print()
    print(f"[결과 저장] {OUT_CSV}")


if __name__ == "__main__":
    main()