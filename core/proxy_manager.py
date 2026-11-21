"""Proxy pool + rotation."""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _parse_proxy_line(line: str) -> Optional[str]:
    """Normalize one proxy line; host:port gets http:// prefixed. None for blank/comment."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    if not line.startswith(('http://', 'https://', 'socks5://')):
        line = 'http://' + line
    return line


class ProxyManager:
    """Rotating proxy pool: round_robin, random, or failover, with cooldown."""

    def __init__(self, proxy_file: str, rotation: str, max_failures: int,
                 cooldown_seconds: int):
        self.rotation = rotation
        self.max_failures = max_failures
        self.cooldown_seconds = cooldown_seconds
        self.lock = threading.Lock()
        self._proxies: List[str] = []
        self._failures: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}
        self._index = 0
        self._load(proxy_file)

    def _load(self, proxy_file: str) -> None:
        try:
            with open(proxy_file, 'r', encoding='utf-8', errors='replace') as handle:
                self._proxies = [p for p in
                                 (_parse_proxy_line(l) for l in handle) if p]
        except OSError as exc:
            logger.error("cannot read proxy file %s: %s", proxy_file, exc)
            self._proxies = []
        if not self._proxies:
            logger.warning("no usable proxies in %s, continuing without proxy", proxy_file)

    def _pick(self) -> Optional[str]:
        """Select the next live proxy per the rotation strategy."""
        now = time.monotonic()
        live = [p for p in self._proxies
                if self._cooldown_until.get(p, 0) <= now]
        if not live:
            return None
        if self.rotation == 'random':
            return random.choice(live)
        if self.rotation == 'failover':
            return live[0]
        # round_robin
        proxy = live[self._index % len(live)]
        self._index += 1
        return proxy

    def proxies_for(self, url: str) -> Optional[Dict[str, str]]:
        """Return a requests-style proxies dict, or None to go direct."""
        with self.lock:
            proxy = self._pick()
        if not proxy:
            return None
        return {'http': proxy, 'https': proxy}

    def report_failure(self, url: str, proxy: str = None) -> None:
        """Count a failure; after max_failures, cool the last-used proxy down."""
        with self.lock:
            if proxy is None:
                # find the proxy most recently handed out, if any
                proxy = self._proxies[(self._index - 1) % len(self._proxies)] \
                    if self._proxies and self._index else None
            if not proxy:
                return
            self._failures[proxy] = self._failures.get(proxy, 0) + 1
            if self._failures[proxy] >= self.max_failures:
                self._cooldown_until[proxy] = time.monotonic() + self.cooldown_seconds
                self._failures[proxy] = 0
                logger.warning("proxy %s cooling down %ds", proxy, self.cooldown_seconds)

    def report_success(self, proxy: str) -> None:
        """Reset the failure counter for a proxy that worked."""
        with self.lock:
            self._failures[proxy] = 0
