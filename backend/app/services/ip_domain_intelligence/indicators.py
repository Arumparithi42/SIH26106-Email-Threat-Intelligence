"""Collect IPs, domains, URLs, email addresses and attachments with ROLES.

Roles record where an indicator came from (sending_ip, reply_to_domain, url ...)
and decide how much external lookup effort it deserves.
Stable ids: ip:1.2.3.4, domain:example.com, url:<url>, email:user@example.com, file:<sha256>.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.core.utils import is_public_ip, parse_ip, registrable_domain


class IndicatorSet:
    def __init__(self) -> None:
        self.ips: dict[str, dict] = {}
        self.domains: dict[str, dict] = {}
        self.urls: dict[str, dict] = {}
        self.addresses: dict[str, dict] = {}
        self.attachments: dict[str, dict] = {}

    @staticmethod
    def _add(bucket: dict, key: str, prefix: str, role: str, **extra) -> dict:
        item = bucket.setdefault(key, {"id": f"{prefix}:{key}", "value": key, "roles": [], **extra})
        if role not in item["roles"]:
            item["roles"].append(role)
        return item

    def ip(self, value: str | None, role: str) -> None:
        if value and parse_ip(value):
            ip = str(parse_ip(value))
            self._add(self.ips, ip, "ip", role if is_public_ip(ip) else "private_ip", is_public=is_public_ip(ip))

    def domain(self, value: str | None, role: str) -> None:
        if not value or parse_ip(value):
            return
        reg = registrable_domain(value)
        if reg:
            item = self._add(self.domains, reg, "domain", role)
            host = value.lower().strip(".")
            if host != reg:
                item.setdefault("hostnames", [])
                if host not in item["hostnames"]:
                    item["hostnames"].append(host)

    def address(self, value: str | None, role: str) -> None:
        if value and "@" in value:
            self._add(self.addresses, value.lower(), "email", role, domain=value.rsplit("@", 1)[1].lower())

    def as_lists(self) -> dict:
        return {
            "ips": list(self.ips.values()), "domains": list(self.domains.values()), "urls": list(self.urls.values()),
            "email_addresses": list(self.addresses.values()), "attachments": list(self.attachments.values()),
        }


def extract_indicators(parsed: dict, header_result: dict) -> IndicatorSet:
    ind = IndicatorSet()
    h = parsed["headers"]
    sending_ip = (header_result.get("sending_ip") or {}).get("ip")
    for hop in header_result.get("received_chain", []):
        if hop.get("ip"):
            ind.ip(hop["ip"], "sending_ip" if hop["ip"] == sending_ip else "relay_ip")
        if hop.get("hostname") and hop["ip"] == sending_ip:
            ind.domain(hop["hostname"], "sending_host_domain")
    if sending_ip:
        ind.ip(sending_ip, "sending_ip")
    if h.get("x_originating_ip"):
        ind.ip(h["x_originating_ip"].strip("[] "), "originating_client_ip")

    for field, role in (("from", "from"), ("reply_to", "reply_to"), ("return_path", "return_path"), ("sender", "sender")):
        a = h.get(field) or {}
        ind.address(a.get("address"), role)
        ind.domain(a.get("domain"), f"{role}_domain")
    for field in ("to", "cc"):
        for a in h.get(field) or []:
            ind.address(a.get("address"), field)
    mid = header_result.get("identity", {}).get("domains", {}).get("message_id")
    ind.domain(mid, "message_id_domain")
    dkim_d = header_result.get("authentication", {}).get("dkim", {}).get("domain")
    ind.domain(dkim_d, "dkim_domain")

    for u in parsed.get("urls", []):
        url = u["url"]
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        ind.urls[url] = {"id": f"url:{url}", "value": url, "roles": ["url"], "hostname": host}
        if host and parse_ip(host):
            ind.ip(host, "url_ip")
        elif host:
            ind.domain(host, "url_domain")
    for att in parsed.get("attachments", []):
        ind.attachments[att["sha256"]] = {"id": f"file:{att['sha256']}", "value": att["filename"], "roles": ["attachment"], "sha256": att["sha256"]}
    return ind
