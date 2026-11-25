"""Phase 1: Email File Ingestion & Parser Setup (.eml and .msg)."""
from __future__ import annotations

import email
from email import policy
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import extract_msg  # type: ignore
except ImportError:
    extract_msg = None


def _extract_address_list(raw_values: List[str] | None) -> List[str]:
    if not raw_values:
        return []
    return [addr for _, addr in getaddresses(raw_values) if addr]


def parse_eml_bytes(raw_bytes: bytes, filename: str = "uploaded.eml") -> Dict[str, Any]:
    """Parse a raw RFC 5322 .eml file into structured metadata, headers, body, and attachments."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    from_raw = str(msg.get("From", ""))
    reply_to_raw = str(msg.get("Reply-To", ""))
    return_path_raw = str(msg.get("Return-Path", ""))
    to_list = _extract_address_list(msg.get_all("To", []))
    cc_list = _extract_address_list(msg.get_all("Cc", []))
    subject = str(msg.get("Subject", "(No Subject)"))
    date_raw = str(msg.get("Date", ""))
    message_id = str(msg.get("Message-ID", ""))

    timestamp_iso = ""
    if date_raw:
        try:
            timestamp_iso = parsedate_to_datetime(date_raw).isoformat()
        except Exception:
            timestamp_iso = date_raw

    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get_content_disposition() or "")
            content_type = part.get_content_type()
            part_filename = part.get_filename()

            if part_filename or content_disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": part_filename or "unnamed_attachment",
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "payload": payload,
                })
            elif content_type == "text/plain" and content_disposition != "attachment":
                try:
                    body_text_parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_text_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html" and content_disposition != "attachment":
                try:
                    body_html_parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if content_type == "text/html":
            body_html_parts.append(str(content))
        else:
            body_text_parts.append(str(content))

    all_headers: List[Tuple[str, str]] = [(k, str(v)) for k, v in msg.items()]
    received_headers = [str(v) for v in msg.get_all("Received", [])]
    auth_results_headers = [str(v) for v in msg.get_all("Authentication-Results", [])]
    received_spf_headers = [str(v) for v in msg.get_all("Received-SPF", [])]
    dkim_sig_headers = [str(v) for v in msg.get_all("DKIM-Signature", [])]

    return {
        "source_filename": filename,
        "format": "eml",
        "envelope": {
            "from_raw": from_raw,
            "from_addresses": _extract_address_list([from_raw]),
            "reply_to_raw": reply_to_raw,
            "reply_to_addresses": _extract_address_list([reply_to_raw]),
            "return_path_raw": return_path_raw,
            "return_path_addresses": _extract_address_list([return_path_raw]),
            "to_addresses": to_list,
            "cc_addresses": cc_list,
            "subject": subject,
            "date_raw": date_raw,
            "timestamp_iso": timestamp_iso,
            "message_id": message_id,
        },
        "headers": {
            "all": all_headers,
            "received": received_headers,
            "authentication_results": auth_results_headers,
            "received_spf": received_spf_headers,
            "dkim_signature": dkim_sig_headers,
        },
        "body": {
            "text": "\n".join(body_text_parts).strip(),
            "html": "\n".join(body_html_parts).strip(),
        },
        "attachments": attachments,
    }


def parse_msg_file(file_path: str | Path) -> Dict[str, Any]:
    """Parse an Outlook .msg file using extract_msg into the unified schema."""
    if extract_msg is None:
        raise RuntimeError(
            "extract_msg is not installed. Run `pip install extract-msg` to parse .msg files."
        )
    path = Path(file_path)
    msg = extract_msg.Message(str(path))
    try:
        header_dict = dict(msg.header or {})
        raw_headers = [(k, str(v)) for k, v in header_dict.items()]
        received_headers = [
            str(v) for k, v in raw_headers if k.lower() == "received"
        ]
        auth_results = [
            str(v) for k, v in raw_headers if k.lower() == "authentication-results"
        ]
        received_spf = [
            str(v) for k, v in raw_headers if k.lower() == "received-spf"
        ]
        dkim_sig = [
            str(v) for k, v in raw_headers if k.lower() == "dkim-signature"
        ]

        attachments: List[Dict[str, Any]] = []
        for att in getattr(msg, "attachments", []) or []:
            data = getattr(att, "data", b"") or b""
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            attachments.append({
                "filename": getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or "unnamed_attachment",
                "content_type": "application/octet-stream",
                "size_bytes": len(data),
                "payload": data,
            })

        sender = str(getattr(msg, "sender", "") or "")
        to_raw = str(getattr(msg, "to", "") or "")
        cc_raw = str(getattr(msg, "cc", "") or "")
        html_body = getattr(msg, "htmlBody", b"") or b""
        if isinstance(html_body, bytes):
            html_body = html_body.decode("utf-8", errors="replace")

        return {
            "source_filename": path.name,
            "format": "msg",
            "envelope": {
                "from_raw": sender,
                "from_addresses": _extract_address_list([sender]),
                "reply_to_raw": str(header_dict.get("Reply-To", "")),
                "reply_to_addresses": _extract_address_list([str(header_dict.get("Reply-To", ""))]),
                "return_path_raw": str(header_dict.get("Return-Path", "")),
                "return_path_addresses": _extract_address_list([str(header_dict.get("Return-Path", ""))]),
                "to_addresses": _extract_address_list([to_raw]),
                "cc_addresses": _extract_address_list([cc_raw]),
                "subject": str(getattr(msg, "subject", "(No Subject)") or "(No Subject)"),
                "date_raw": str(getattr(msg, "date", "") or ""),
                "timestamp_iso": str(getattr(msg, "date", "") or ""),
                "message_id": str(header_dict.get("Message-ID", "")),
            },
            "headers": {
                "all": raw_headers,
                "received": received_headers,
                "authentication_results": auth_results,
                "received_spf": received_spf,
                "dkim_signature": dkim_sig,
            },
            "body": {
                "text": str(getattr(msg, "body", "") or "").strip(),
                "html": str(html_body).strip(),
            },
            "attachments": attachments,
        }
    finally:
        msg.close()


def parse_email_file(file_path: str | Path) -> Dict[str, Any]:
    """Dispatch email parsing by file extension (.eml or .msg)."""
    path = Path(file_path)
    ext = path.suffix.lower()
    if ext == ".eml":
        return parse_eml_bytes(path.read_bytes(), filename=path.name)
    if ext == ".msg":
        return parse_msg_file(path)
    raise ValueError(f"Unsupported email artifact extension: {ext}. Expected .eml or .msg.")
