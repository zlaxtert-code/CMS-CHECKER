"""Scan runner: thread pool, result collection, per-CMS file output."""
from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, wait

from core.cms_detector import detect_cms
from core.config import Config
from core.fetcher import Fetcher
from core.ui import ScanPanel
from core.waf_detector import detect_waf

logger = logging.getLogger(__name__)

# Set by the Ctrl+E listener; polled by the result loop so the scan stops promptly.
STOP = threading.Event()


def _sanitize(name: str) -> str:
    """Make a CMS/WAF name safe as a file name."""
    return name.replace(' ', '_').replace('/', '-')


def scan_target(url: str, fetcher: Fetcher):
    """Fetch and classify one URL. Never raises."""
    try:
        resp = fetcher.get_with_scheme_swap(url)
        if resp is None:
            return url, [], [], None, 'Stopped' if STOP.is_set() else 'Connection failed'
        waf = detect_waf(resp)
        hits, guesses, status = detect_cms(url, resp, fetcher)
        if waf and not hits and status != 'LIVE':
            status += ' (blocked)'
        return url, hits, guesses, waf, status
    except Exception as exc:  # single bad target must not kill the run (PRD G9)
        logger.error("target %s failed: %s", url, exc, exc_info=True)
        return url, [], [], None, 'Error: %s' % exc


def run_scan(targets, fetcher: Fetcher, panel: ScanPanel, config: Config) -> None:
    """Scan all targets with a thread pool and stream results into the live panel + files.

    Ctrl+E in the terminal cancels the scan (Ctrl+C exits the process).
    """
    result_dir = config.result_dir
    os.makedirs(os.path.join(result_dir, 'per-cms'), exist_ok=True)
    os.makedirs(os.path.join(result_dir, 'per-waf'), exist_ok=True)
    write_lock = threading.Lock()
    STOP.clear()

    handle = open(os.path.join(result_dir, 'results.txt'), 'a', encoding='utf-8')
    pool = ThreadPoolExecutor(max_workers=config.threads)
    try:
        futures = {pool.submit(scan_target, url, fetcher): url for url in targets}
        remaining = set(futures)
        while remaining and not STOP.is_set():
            done, remaining = wait(remaining, timeout=0.2)
            for future in done:
                url, hits, guesses, waf, status = future.result()
                panel.add(url, hits, guesses, waf, status)
                _save(handle, write_lock, result_dir, config,
                      url, hits, guesses, waf, status)
    finally:
        handle.close()
        # never block the join: in-flight sockets finish or time out on their own
        pool.shutdown(wait=False, cancel_futures=True)


def _save(handle, lock, result_dir, config, url, hits, guesses, waf, status) -> None:
    """Append the flat result line and per-CMS files under a lock."""
    with lock:
        handle.write('{}|{}|{}|{}\n'.format(url, ','.join(hits + guesses) or '-',
                                            waf or '-', status))
        handle.flush()
        if not config.save_per_cms:
            return
        for name in hits + guesses:
            path = os.path.join(result_dir, 'per-cms', _sanitize(name) + '.txt')
            with open(path, 'a', encoding='utf-8') as cms_file:
                cms_file.write(url + '\n')
        if waf:
            path = os.path.join(result_dir, 'per-waf', _sanitize(waf) + '.txt')
            with open(path, 'a', encoding='utf-8') as waf_file:
                waf_file.write(url + '\n')
        if not hits and not guesses:
            path = os.path.join(result_dir, 'per-cms', 'Unknown_CMS.txt')
            with open(path, 'a', encoding='utf-8') as unk:
                unk.write(url + '\n')
