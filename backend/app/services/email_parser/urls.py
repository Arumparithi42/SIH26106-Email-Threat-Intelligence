"""URL extraction from plain-text and HTML bodies (passive only - URLs are never visited)."""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser

URL_RE = re.compile(r"""\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
_TRAILING = ".,;:!?)]}'\""


def _clean(url: str) -> str:
    url = html.unescape(url.strip()).rstrip(_TRAILING)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []  # (href, visible text)
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and a.get("href"):
            self._href = a["href"]
            self._anchor_text = []
        elif tag in ("img", "form", "iframe") and (a.get("src") or a.get("action")):
            self.links.append((a.get("src") or a.get("action"), ""))
        if tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor_text).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def html_to_text(body_html: str) -> str:
    p = _LinkParser()
    try:
        p.feed(body_html)
    except Exception:  # noqa: BLE001 - malformed HTML
        pass
    return re.sub(r"\n\s*\n+", "\n\n", "".join(p.text)).strip()


def extract_urls(body_text: str, body_html: str) -> list[dict]:
    """Return unique URLs with where they were found and (for HTML links) the visible text."""
    found: dict[str, dict] = {}

    def add(url: str, source: str, display_text: str | None = None) -> None:
        url = _clean(url)
        if not url.lower().startswith(("http://", "https://")):
            return
        entry = found.setdefault(url, {"url": url, "sources": [], "display_texts": []})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if display_text and display_text not in entry["display_texts"]:
            entry["display_texts"].append(display_text)

    for m in URL_RE.finditer(body_text or ""):
        add(m.group(0), "text")
    if body_html:
        p = _LinkParser()
        try:
            p.feed(body_html)
        except Exception:  # noqa: BLE001
            pass
        for href, text in p.links:
            add(href, "html_href", text or None)
        for m in URL_RE.finditer(html_to_text(body_html)):
            add(m.group(0), "html_text")
    return list(found.values())
