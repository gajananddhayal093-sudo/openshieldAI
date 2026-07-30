import urllib.request
from urllib.parse import urlparse


def scan_url(url):
    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "headers": {},
        "error": None,
    }

    try:
        parsed = urlparse(url)

        if not parsed.scheme:
            url = "https://" + url

        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "OpenShield-AI-Scanner"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            result["reachable"] = True
            result["status_code"] = response.status
            result["headers"] = dict(response.headers)

    except Exception as e:
        result["error"] = str(e)

    return result
