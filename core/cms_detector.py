"""Pure CMS detection."""
from __future__ import annotations

import base64
import json
import logging
from urllib.parse import unquote, urlparse

from data.cms_signatures import (CMS_SIGNS, FOREIGN_SESSIONS, LARAVEL_HINTS,
                                 LARAVEL_PROBES)

logger = logging.getLogger(__name__)


def _matches(haystack: str, tokens) -> bool:
    return any(t in haystack for t in tokens)


def is_laravel_xsrf(value: str) -> bool:
    """True when an XSRF-TOKEN cookie decodes to a Laravel-encrypted payload."""
    try:
        raw = base64.b64decode(unquote(value) + '=' * (-len(unquote(value)) % 4))
        obj = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as exc:
        logger.debug("xsrf token not laravel-shaped: %s", exc)
        return False
    return isinstance(obj, dict) and {'iv', 'value'} <= set(obj)


def detect_from_response(resp):
    """Detect CMS hits from headers, cookies, and body of a single response."""
    heads = ' '.join('%s: %s' % (k, v) for k, v in resp.headers.items()).lower()
    names = [c.name.lower() for c in resp.cookies]
    cookies = ' '.join(names)
    body = resp.text[:200000].lower()
    hard, soft = [], []
    for name, htokens, ctokens, btokens in CMS_SIGNS:
        if _matches(heads, htokens) or _matches(cookies, ctokens):
            hard.append(name)
        elif _matches(body, btokens):
            soft.append(name)
    xsrf = resp.cookies.get('XSRF-TOKEN')
    if xsrf and is_laravel_xsrf(xsrf) and 'Laravel' not in hard:
        hard.append('Laravel')
    if any(n.startswith('laravel') and n.endswith('_session') for n in names):
        if 'Laravel' not in hard:
            hard.append('Laravel')
    # rails session cookies are always _<app>_session
    if any(n.startswith('_') and n.endswith('_session') for n in names):
        if 'Ruby on Rails' not in hard:
            hard.append('Ruby on Rails')
    # never report the same cms twice (hard + soft)
    soft = [s for s in soft if s not in hard]
    return hard, soft


def confirm_laravel(base: str, fetcher) -> bool:
    """Probe laravel-specific URLs for a 200 containing the expected token."""
    for path, token in LARAVEL_PROBES:
        probe = fetcher.get(base + path)
        if probe is not None and probe.status_code == 200 and token in probe.text.lower():
            return True
    return False


def detect_cms(url, resp, fetcher):
    """Full detection for one URL: hard hits, soft guesses after probe confirmation."""
    
    if resp is None:
        return [], [], 'Connection failed'

    hits, guesses = detect_from_response(resp)
    base = '{0.scheme}://{0.netloc}'.format(urlparse(url))

    low = resp.text[:200000].lower()
    names = [c.name.lower() for c in resp.cookies]
    app_session = any(n.endswith('_session') and not n.startswith('_')
                      and not any(f in n for f in FOREIGN_SESSIONS) for n in names)
    laravel_hint = ('Laravel' in guesses or app_session
                    or (not hits and any(h in low for h in LARAVEL_HINTS)))
    if laravel_hint and 'Laravel' not in hits:
        if confirm_laravel(base, fetcher):
            hits.append('Laravel')
        guesses = [g for g in guesses if g != 'Laravel']

    status = 'LIVE' if resp.status_code < 400 else 'HTTP %d' % resp.status_code
    return hits, guesses, status
