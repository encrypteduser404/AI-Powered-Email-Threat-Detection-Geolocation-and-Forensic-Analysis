import hashlib
import ipaddress
import re
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from urllib.parse import urlsplit

from app.core.config import settings
from app.schemas.email import (
    AuthenticationEvidence,
    EmailAttachment,
    EmailBody,
    EmailData,
    EmailHeader,
    EmailHeaders,
    EmailMetadata,
    EmailStatistics,
    EmailUrl,
    ReceivedHop,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
USEFUL_HEADERS = {
    "received",
    "authentication-results",
    "arc-authentication-results",
    "dkim-signature",
    "received-spf",
    "mime-version",
    "content-type",
    "x-mailer",
    "user-agent",
}


def _decode_header(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(make_header(decode_header(value))).strip()
    except (UnicodeError, ValueError):
        return value.strip()


def _addresses(value: str | None) -> list[str]:
    if not value:
        return []
    decoded = _decode_header(value) or ""
    result: list[str] = []
    for display_name, address in getaddresses([decoded]):
        if address:
            result.append(f"{display_name.strip()} <{address}>" if display_name.strip() else address)
    return result


def _single_address(value: str | None) -> str | None:
    addresses = _addresses(value)
    if addresses:
        return addresses[0]
    return _decode_header(value)


def _header_values(message: Message, name: str) -> list[str]:
    return [(_decode_header(value) or "")[: settings.max_header_value_chars] for value in message.get_all(name, [])]


def _received_hops(message: Message) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for index, raw in enumerate(_header_values(message, "Received")):
        candidates: list[str] = []
        for candidate in IP_PATTERN.findall(raw):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in candidates:
                candidates.append(candidate)
        hops.append(ReceivedHop(raw=raw, index=index, observed_ip_candidates=candidates))
    return hops


def _authentication(message: Message) -> AuthenticationEvidence:
    return AuthenticationEvidence(
        authentication_results=_header_values(message, "Authentication-Results"),
        arc_authentication_results=_header_values(message, "ARC-Authentication-Results"),
        received_spf=_header_values(message, "Received-SPF"),
        dkim_signature=_header_values(message, "DKIM-Signature"),
    )


def _text_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload if isinstance(raw_payload, str) else ""
    charset = part.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


def _extract_body_and_attachments(message: Message) -> tuple[EmailBody, list[EmailAttachment], int]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[EmailAttachment] = []
    mime_part_count = 0
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        mime_part_count += 1
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename is not None:
            payload = part.get_payload(decode=True) or b""
            attachments.append(EmailAttachment(
                filename=_decode_header(filename) or "unnamed_attachment",
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                content_disposition=disposition,
            ))
            continue
        if part.get_content_maintype() != "text":
            continue
        text = _text_payload(part)
        if part.get_content_subtype() == "plain":
            plain_parts.append(text)
        elif part.get_content_subtype() == "html":
            html_parts.append(text)
    plain_text = "\n\n".join(plain_parts)[: settings.max_body_chars] or None
    html = "\n\n".join(html_parts)[: settings.max_body_chars] or None
    return EmailBody(plain_text=plain_text, html=html), attachments, mime_part_count


def _extract_urls(body: EmailBody) -> list[EmailUrl]:
    results: list[EmailUrl] = []
    seen: set[tuple[str, str]] = set()
    for source, text in (("plain_text", body.plain_text), ("html", body.html)):
        if not text:
            continue
        for match in URL_PATTERN.findall(text):
            value = match.rstrip(".,;:!?)]}")
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            key = (value, source)
            if key in seen:
                continue
            seen.add(key)
            results.append(EmailUrl(url=value, source=source, domain=parsed.hostname, scheme=parsed.scheme))
    return results


def parse_email(raw_bytes: bytes) -> EmailData:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    metadata = EmailMetadata(
        from_address=_single_address(message.get("From")),
        to=_addresses(message.get("To")),
        cc=_addresses(message.get("Cc")),
        bcc=_addresses(message.get("Bcc")),
        reply_to=_addresses(message.get("Reply-To")),
        return_path=_single_address(message.get("Return-Path")),
        subject=_decode_header(message.get("Subject")),
        date=_decode_header(message.get("Date")),
        message_id=_decode_header(message.get("Message-ID")),
    )
    useful = [
        EmailHeader(name=name, value=value)
        for name, value in message.raw_items()
        if name.lower() in USEFUL_HEADERS
    ]
    headers = EmailHeaders(useful=useful, received=_received_hops(message), authentication=_authentication(message))
    body, attachments, mime_part_count = _extract_body_and_attachments(message)
    urls = _extract_urls(body)
    statistics = EmailStatistics(
        attachment_count=len(attachments),
        url_count=len(urls),
        header_count=len(list(message.raw_items())),
        mime_part_count=mime_part_count,
    )
    return EmailData(metadata=metadata, headers=headers, body=body, urls=urls, attachments=attachments, statistics=statistics)