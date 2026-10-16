from urllib.parse import urlparse, urljoin
import requests

DEFAULT_PATHS = ["/admin", "/login", "/robots.txt", "/backup", "/uploads"]


def scan_directories(base_url, paths=None, timeout=5):
    """Check common paths on a site you own or have explicit permission to test."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid URL beginning with http:// or https://")
    if not 0 < timeout <= 30:
        raise ValueError("Timeout must be between 0 and 30 seconds.")
    paths = DEFAULT_PATHS if paths is None else paths
    results = []
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            results.append({"path": path, "url": url, "status_code": response.status_code})
        except requests.RequestException as exc:
            results.append({"path": path, "url": url, "error": str(exc)})
    return {"base_url": base_url, "results": results}
