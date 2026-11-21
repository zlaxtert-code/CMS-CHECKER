"""HTTP layer: fetches with fingerprint rotation, returns requests responses."""
from __future__ import annotations

import logging
import random
import threading

import requests
import urllib3

from core.config import Config
from data.user_agents import ACCEPT_LANGUAGES, SPOOF_HEADERS, USER_AGENTS
from data.waf_signatures import BLOCK_MARKERS, BLOCK_STATUS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def random_ip() -> str:
    """Random public-looking IPv4 for spoofed headers."""
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))


def normalize(url: str) -> str:
    """Normalize a weblist line into a bare https URL, or None if blank/comment."""
    url = url.strip()
    if not url or url.startswith('#'):
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


class Fetcher:
    """Retries with rotated fingerprints until the WAF lets us through."""

    def __init__(self, config: Config, proxy_manager=None, stop_event=None):
        # proxy_manager is injected, never imported, so this module stays proxy-agnostic
        self.timeout = config.timeout
        self.stop_event = stop_event
        self.verify_ssl = config.verify_ssl
        self.follow_redirects = config.follow_redirects
        self.spoof_headers = config.spoof_headers
        self.retries = max(1, config.retries)
        self.proxy_manager = proxy_manager
        self.local = threading.local()

    def _session(self):
        if not hasattr(self.local, 's'):
            s = requests.Session()
            s.max_redirects = 5
            self.local.s = s
        return self.local.s

    def _header_sets(self):
        ua = random.choice(USER_AGENTS)
        yield {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }
        for _ in range(self.retries):
            h = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': random.choice(ACCEPT_LANGUAGES),
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
                'Referer': 'https://www.google.com/',
                'Connection': 'close',
            }
            if self.spoof_headers:
                for name in random.sample(SPOOF_HEADERS, 3):
                    h[name] = random_ip()
            yield h

    @staticmethod
    def _blocked(resp):
        if resp is None:
            return True
        if resp.status_code in BLOCK_STATUS:
            return True
        head = resp.text[:2000].lower()
        return any(marker in head for marker in BLOCK_MARKERS)

    def get(self, url):
        """Fetch url, retrying with new fingerprints while blocked. Returns last response or None."""
        last = None
        for headers in self._header_sets():
            if self.stop_event is not None and self.stop_event.is_set():
                logger.debug("stop requested, abandoning %s", url)
                break
            proxies = None
            if self.proxy_manager:
                proxies = self.proxy_manager.proxies_for(url)
            try:
                resp = self._session().get(
                    url, headers=headers, timeout=self.timeout,
                    verify=self.verify_ssl, allow_redirects=self.follow_redirects,
                    proxies=proxies)
            except requests.RequestException as exc:
                logger.debug("request failed for %s: %s", url, exc)
                last = None
                if self.proxy_manager:
                    self.proxy_manager.report_failure(url)
                continue
            last = resp
            if not self._blocked(resp):
                return resp
        return last

    def get_with_scheme_swap(self, url):
        """Fetch url; if unreachable, retry once over the other scheme."""
        resp = self.get(url)
        if resp is None:
            if url.startswith('https://'):
                return self.get('http://' + url[8:])
            if url.startswith('http://'):
                return self.get('https://' + url[7:])
        return resp
