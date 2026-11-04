"""Kick the (S3) Bucket: analyze a User-Agent-gated S3 resource policy.

The CTF's publicly released S3 resource policy allows s3:GetObject only
when aws:UserAgent matches aws-sdk-go*. An arbitrary HTTP client can set
this request header, unlike the signature protecting a presigned URL.
Reconstruct policy matching and SigV4 URL expiry OFFLINE. Do not contact AWS
or retrieve any real bucket object; the published 2025 URL has expired.
"""
import argparse
import datetime as dt
import fnmatch
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

UTC = dt.timezone.utc


def load_policy(text: str) -> dict:
    document = json.loads(text)
    if document.get("Version") != "2012-10-17":
        raise ValueError("Unexpected AWS policy language version")
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise ValueError("Missing resource-policy statements")
    return document


def user_agent_condition(policy: dict) -> str:
    statements = policy["Statement"]
    matches = [
        st.get("Condition", {}).get("StringLike", {}).get("aws:UserAgent")
        for st in statements if st.get("Effect") == "Allow"
        and "s3:GetObject" in st.get("Action", [])
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError("Cannot find single expected S3 User-Agent condition")
    return matches[0]


def offline_authorized_user_agent(policy: dict, user_agent: str) -> bool:
    """Evaluate ONLY the original policy's spoofable UA condition.

    This is not an AWS authorizer: principal/resource/signature and the
    request's other IAM policies are intentionally evaluated separately.
    """
    if not isinstance(user_agent, str):
        raise ValueError("User Agent must be text")
    return fnmatch.fnmatchcase(user_agent, user_agent_condition(policy))


def parse_presigned_url(text: str) -> dict:
    parsed = urlparse(text.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Expected HTTPS S3 presigned URL")
    q = parse_qs(parsed.query, strict_parsing=True)
    def get(name):
        value = q.get(name)
        if not value or len(value) != 1:
            raise ValueError("Missing presigned URL parameter: " + name)
        return value[0]
    if get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256":
        raise ValueError("Unexpected signature algorithm")
    signed_headers = get("X-Amz-SignedHeaders").lower().split(";")
    if "host" not in signed_headers:
        raise ValueError("Host must be a signed header")
    issued = dt.datetime.strptime(get("X-Amz-Date"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    lifetime = int(get("X-Amz-Expires"))
    if lifetime < 1 or lifetime > 604800:
        raise ValueError("Invalid SigV4 maximum expiration")
    credential_scope = get("X-Amz-Credential").split("/")
    if len(credential_scope) != 5 or credential_scope[-1] != "aws4_request":
        raise ValueError("Unexpected AWS signing credential scope")
    return {
        "host": parsed.hostname,
        "path": parsed.path,
        "issued": issued,
        "expires": issued + dt.timedelta(seconds=lifetime),
        "signed_headers": signed_headers,
        "credential_scope": credential_scope[1:],
    }


def analyse(policy_text: str, original_url: str, at: dt.datetime | None = None) -> dict:
    policy = load_policy(policy_text)
    url_info = parse_presigned_url(original_url)
    now = dt.datetime.now(UTC) if at is None else at
    if now.tzinfo is None:
        raise ValueError("Comparison timestamp must have a timezone")
    if "user-agent" in url_info["signed_headers"]:
        raise ValueError("This challenge assumes User-Agent is not signed")
    condition = user_agent_condition(policy)
    if not offline_authorized_user_agent(policy, "aws-sdk-go-ctf-local-test"):
        raise ValueError("Condition cannot be satisfied by client header")
    if offline_authorized_user_agent(policy, "curl/8.0"):
        raise ValueError("Original UA gate unexpectedly accepts ordinary curl")
    return {
        "required_pattern": condition,
        "matching_user_agent": "aws-sdk-go-ctf-local-test",
        "issued_at": url_info["issued"],
        "expires_at": url_info["expires"],
        "expired": now >= url_info["expires"],
        "user_agent_is_signed": False,
        "url_path": url_info["path"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_policy", type=Path)
    parser.add_argument("original_presigned_url", type=Path)
    args = parser.parse_args()
    result = analyse(
        args.original_policy.read_text(encoding="utf-8"),
        args.original_presigned_url.read_text(encoding="utf-8"),
    )
    print("AWS S3 User-Agent condition:", result["required_pattern"])
    print("Matching mock header:", result["matching_user_agent"])
    print("Historical presigned URL expires:", result["expires_at"].isoformat())
    print("Presigned URL expired:", result["expired"])
    print("No AWS network access or hosted flag retrieval attempted.")


if __name__ == "__main__":
    main()
