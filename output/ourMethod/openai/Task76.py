import sys
import ssl
import urllib.request
import urllib.parse
from html.parser import HTMLParser
from typing import List, Optional


UA: str = "SecureTitleFetcher/1.0 (+https://example.invalid/)"


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title: bool = False
        self._chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "title" and not self._chunks:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title:
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self._chunks) < 1000:
            self._chunks.append(data)

    def get_title(self) -> str:
        raw = "".join(self._chunks).strip()
        # Normalize whitespace
        return " ".join(raw.split())


class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    # Ensure we only follow HTTPS redirects
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme.lower() != "https":
            raise urllib.error.HTTPError(
                newurl, code, "Insecure redirect blocked (non-HTTPS)", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_valid_https_url(url: str, max_len: int = 2048) -> bool:
    if not isinstance(url, str):
        return False
    if not url or len(url) > max_len:
        return False
    if any(c in url for c in ("\r", "\n", "\t")):
        return False
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        return False
    # Disallow userinfo in netloc
    if "@" in parsed.netloc:
        return False
    return True


def create_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2+
    else:
        # Harden for very old Python versions
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    return ctx


def decode_html(body: bytes, headers: Optional[urllib.response.addinfourl]) -> str:
    charset: Optional[str] = None
    try:
        if headers is not None and hasattr(headers, "get_content_charset"):
            charset = headers.get_content_charset()
    except Exception:
        charset = None

    for enc in (charset, "utf-8", "utf-8-sig", "windows-1252", "latin-1"):
        if not enc:
            continue
        try:
            return body.decode(enc, errors="replace")
        except Exception:
            continue
    # Fallback
    return body.decode("utf-8", errors="replace")


def extract_title(html_text: str, max_chars: int = 1000) -> str:
    parser = TitleParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        pass
    title = parser.get_title()
    if len(title) > max_chars:
        title = title[:max_chars]
    return title


def fetch_page_title(url: str, timeout: float = 10.0, max_bytes: int = 2 * 1024 * 1024) -> str:
    if not is_valid_https_url(url):
        raise ValueError("Invalid HTTPS URL")

    ctx = create_tls_context()
    opener = urllib.request.build_opener(
        HTTPSOnlyRedirectHandler(),
        urllib.request.HTTPSHandler(context=ctx)
    )

    req = urllib.request.Request(url=url, method="GET", headers={"User-Agent": UA})

    with opener.open(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        if urllib.parse.urlsplit(final_url).scheme.lower() != "https":
            raise urllib.error.URLError("Insecure redirect to non-HTTPS blocked")

        status = resp.getcode()
        if status is None or status < 200 or status >= 400:
            raise urllib.error.HTTPError(final_url, status or 0, "Unexpected HTTP status", resp.headers, None)

        chunks: List[bytes] = []
        total = 0
        while total < max_bytes:
            chunk = resp.read(min(65536, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        body = b"".join(chunks)
        html_text = decode_html(body, resp.headers)

    return extract_title(html_text)


def main(argv: List[str]) -> int:
    urls = argv[1:]
    if not urls:
        # 5 test cases if no CLI args provided
        urls = [
            "https://www.example.com/",
            "https://www.python.org/",
            "https://www.wikipedia.org/",
            "https://httpbin.org/html",
            "https://www.iana.org/domains/reserved",
        ]
        print("No URL provided; running 5 test cases.", file=sys.stderr)

    exit_code = 0
    for u in urls:
        try:
            title = fetch_page_title(u)
            print(title)
        except Exception as e:
            exit_code = 1
            print("", file=sys.stdout)
            print(f"Error fetching title for {u}: {str(e)}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))