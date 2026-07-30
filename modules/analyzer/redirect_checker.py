import urllib.request
from urllib.parse import urlparse


def check_redirect(url):
    try:
        if "://" not in url:
            url = "https://" + url

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "OpenShield-AI-Scanner"
            }
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            final_url = response.geturl()

            return {
                "success": True,
                "original_url": url,
                "final_url": final_url,
                "redirected": url != final_url,
                "https": urlparse(final_url).scheme == "https",
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
