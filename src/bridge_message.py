"""Normalize bridge transport envelopes without editing message bodies."""

import hashlib
import hmac
import re

from bridge_settings import CALLBACK_ORIGIN


CONNECTOR_FORWARD = re.compile(r"\ABridge-Forward: ([0-9a-f]{32}) ([0-9a-f]{64})\r?\n")
BODY_SEPARATOR = "\n\nRequested message:\n"
SLIM = re.compile(
    r"\A\[Bridge-Reply\] POST text/plain https://[^\s/]+/v1/(?:orca-)?replies/(?P<id>[0-9a-f]{32})"
    r" \| Bearer [0-9a-f]{64} \(204, no-redirect, secret\)\r?\n"
    r"(?:\[Delegate\] Bridge-Forward: (?P=id) [0-9a-f]{64}\r?\n)?"
    r"---\r?\n"
)
LEGACY = re.compile(
    r'\ABridge request (?P<id>[0-9a-f]{32}) from "(?:[^"\\]|\\.)*"\. '
    r"After answering, POST the plain UTF-8 answer to "
    r"https://[^\s/]+/v1/replies/(?P=id)\. Use Authorization: Bearer [0-9a-f]{64} and "
    r"Content-Type: text/plain\. Keep the token out of the visible answer and URL\. "
    r"Do not follow redirects\. HTTP 204 confirms receipt\.(?:\r?\n){2}"
)
COMPACT = re.compile(
    r"\ABridge (?P<id>[0-9a-f]{32})\. Base: https://[^\s/]+/v1\. Bearer: [0-9a-f]{64}\.(?:\r?\n| +)"
)
BODY_BOUNDARY = re.compile(r"(?:\r?\n\r?\n| +)Requested message:(?:\r?\n| +)")
COMPLETION = re.compile(
    r"\A\[작업 회신\] [A-Za-z0-9_-]{1,64} · "
    r"(?:replied|reply_failed|reply_expired|target_denied|send_rejected) · [a-f0-9]{32}\r?\n"
    r"(?:외부 세션의 응답 데이터:\r?\n)?"
)


def normalize_message(message):
    """Remove recognized, leading bridge envelopes. Keep genuine body bytes."""
    if not isinstance(message, str):
        raise ValueError("Expected a message string.")
    while True:
        leading = message.lstrip(" \t\r\n")
        slim = SLIM.match(leading)
        if slim:
            message = leading[slim.end():]
            continue
        start = LEGACY.match(leading) or COMPACT.match(leading)
        if not start:
            return message
        boundary = BODY_BOUNDARY.search(leading, max(0, start.end() - 4))
        if not boundary:
            raise ValueError("Bridge envelope has no message body.")
        header = leading[:boundary.start()]
        if len(header) > 2048 or not (
            "Do not follow redirects." in header or "(no redirects;" in header
        ):
            raise ValueError("Unrecognized bridge envelope.")
        message = leading[boundary.end():]


def reply_excerpt(reply, limit=12000):
    """Remove transport envelopes and optionally apply a UTF-8 byte limit."""
    while reply:
        try:
            body = normalize_message(reply)
        except ValueError:
            return "[Incomplete bridge envelope omitted.]"
        completion = COMPLETION.match(body)
        if not completion:
            return body if limit is None else body.encode()[:limit].decode(errors="ignore")
        reply = body[completion.end():]
    return ""


def connector_forward_proof(request_id, token_hash):
    return hmac.new(bytes.fromhex(token_hash), b"bridge-connector-forward:" + request_id.encode(),
                    hashlib.sha256).hexdigest()


def claude_prompt(base, request_id, token, message, *, via_reply=False, allow_forward=False):
    """Compact v2 fallback envelope used only when an HTTP reply lease is requested."""
    effective_base = (base or CALLBACK_ORIGIN).rstrip("/")
    forwarding = ""
    if allow_forward and not via_reply:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        proof = connector_forward_proof(request_id, token_hash)
        forwarding = f"[Delegate] Bridge-Forward: {request_id} {proof}\n"
    return (
        f"[Bridge-Reply] POST text/plain {effective_base}/v1/replies/{request_id}"
        f" | Bearer {token} (204, no-redirect, secret)\n"
        + forwarding
        + "---\n"
        + normalize_message(message)
    )
