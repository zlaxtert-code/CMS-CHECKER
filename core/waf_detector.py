"""Pure WAF detection."""
from __future__ import annotations

from data.waf_signatures import WAF_SIGNS


def detect_waf(resp):
    """Return the WAF name matching headers + body, or None."""
    if resp is None:
        return None
    haystack = ' '.join('%s %s' % (k, v) for k, v in resp.headers.items()).lower()
    haystack += ' ' + resp.text[:3000].lower()
    for name, markers in WAF_SIGNS:
        if any(m in haystack for m in markers):
            return name
    return None
