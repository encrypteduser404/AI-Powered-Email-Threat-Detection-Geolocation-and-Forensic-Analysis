from typing import Literal

from pydantic import BaseModel, Field


class EmailMetadata(BaseModel):
    from_address: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None


class EmailHeader(BaseModel):
    name: str
    value: str


class ReceivedHop(BaseModel):
    raw: str
    index: int
    observed_ip_candidates: list[str] = Field(default_factory=list)


class AuthenticationEvidence(BaseModel):
    authentication_results: list[str] = Field(default_factory=list)
    arc_authentication_results: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    dkim_signature: list[str] = Field(default_factory=list)


class EmailHeaders(BaseModel):
    useful: list[EmailHeader] = Field(default_factory=list)
    received: list[ReceivedHop] = Field(default_factory=list)
    authentication: AuthenticationEvidence


class EmailBody(BaseModel):
    plain_text: str | None = None
    html: str | None = None


class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    content_disposition: str | None = None


class EmailUrl(BaseModel):
    url: str
    source: Literal["plain_text", "html"]
    domain: str
    scheme: Literal["http", "https"]


class EmailStatistics(BaseModel):
    attachment_count: int
    url_count: int
    header_count: int
    mime_part_count: int


class EmailData(BaseModel):
    metadata: EmailMetadata
    headers: EmailHeaders
    body: EmailBody
    urls: list[EmailUrl] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)
    statistics: EmailStatistics