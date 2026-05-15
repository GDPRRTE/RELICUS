import json
import re
import csv
import os
from urllib.parse import urlparse

# ------------ helpers ------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UUID_RE  = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

def safe_str(x):
    if x is None:
        return ""
    if isinstance(x, (dict, list)):
        return json.dumps(x, ensure_ascii=False)
    return str(x)

def truncate(s, n=500):
    s = safe_str(s)
    return s if len(s) <= n else s[:n] + "…[truncated]"

def get_host(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def contains_email(text):
    return bool(EMAIL_RE.search(safe_str(text)))

def contains_uuid(text):
    return bool(UUID_RE.search(safe_str(text)))

def looks_like_profile_payload(text):
    t = safe_str(text).lower()
    keywords = [
        "email", "firstname", "lastname", "username",
        "profile", "account", "createdat", "updatedat", "userid"
    ]
    return any(k in t for k in keywords)

# ------------ robust JSON loader ------------

def load_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    if os.path.getsize(path) == 0:
        raise ValueError("JSON file is empty")

    # handle UTF-8 BOM safely
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)

# ------------ extraction ------------

def extract_network_requests(data):
    if isinstance(data, dict) and "network_requests" in data:
        return data["network_requests"]
    if isinstance(data, list):
        return data
    return []

def export_network_csv(input_json, output_csv):
    data = load_json(input_json)
    items = extract_network_requests(data)

    if not items:
        print("No network_requests found.")
        return

    fieldnames = [
        "timestamp",
        "request_url",
        "request_host",
        "request_method",
        "response_status_code",
        "request_user_agent",
        "request_referer",
        "request_origin",
        "request_cookie_header_present",
        "request_content_type",
        "response_content_type",
        "request_body_trunc",
        "response_body_trunc",
        "flag_contains_email",
        "flag_contains_uuid",
        "flag_profile_like_payload"
    ]

    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            escapechar="\\",
            extrasaction="ignore"
        )
        writer.writeheader()

        for entry in items:
            req = entry.get("request", {})
            res = entry.get("response", {})

            url = req.get("url", "")
            headers_req = req.get("headers", {}) or {}
            headers_res = res.get("headers", {}) or {}

            ua = headers_req.get("User-Agent") or headers_req.get("user-agent") or ""
            referer = headers_req.get("Referer") or headers_req.get("referer") or ""
            origin = headers_req.get("Origin") or headers_req.get("origin") or ""
            req_ct = headers_req.get("Content-Type") or headers_req.get("content-type") or ""
            res_ct = headers_res.get("Content-Type") or headers_res.get("content-type") or ""

            req_body = req.get("body")
            res_body = res.get("body")

            combined = safe_str(req_body) + "\n" + safe_str(res_body)

            writer.writerow({
                "timestamp": safe_str(entry.get("timestamp")),
                "request_url": safe_str(url),
                "request_host": get_host(url),
                "request_method": safe_str(req.get("method")),
                "response_status_code": safe_str(res.get("status_code")),
                "request_user_agent": truncate(ua, 200),
                "request_referer": truncate(referer, 200),
                "request_origin": truncate(origin, 200),
                "request_cookie_header_present": "cookie" in {k.lower() for k in headers_req},
                "request_content_type": truncate(req_ct, 120),
                "response_content_type": truncate(res_ct, 120),
                "request_body_trunc": truncate(req_body, 700),
                "response_body_trunc": truncate(res_body, 700),
                "flag_contains_email": contains_email(combined),
                "flag_contains_uuid": contains_uuid(combined),
                "flag_profile_like_payload": looks_like_profile_payload(combined),
            })

    print(f"✅ Saved CSV: {output_csv}  (rows={len(items)})")

# ------------ run ------------

if __name__ == "__main__":
    INPUT_JSON = r"D:\Sec_GDPR\Sec_GDPR_Code_Final\CookieSniffer-main\profiles\manomano_fr\data.json"
    OUTPUT_CSV = r"D:\Sec_GDPR\Sec_GDPR_Code_Final\CookieSniffer-main\profiles\manomano_fr\network_requests_After.csv"
    export_network_csv(INPUT_JSON, OUTPUT_CSV)
