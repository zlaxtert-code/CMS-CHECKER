"""CMS & WAF Checker."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from core.config import Config, load_config
from core.fetcher import Fetcher, normalize
from core.proxy_manager import ProxyManager
from core.scanner import STOP, run_scan
from core.ui import (apply_color_setting, ask_threads, ask_weblist, console,
                     print_error, print_info, run_with_live_panel, show_banner)

VERSION = '1.0.2'
MIN_THREADS, MAX_THREADS = 5, 500


def build_parser() -> argparse.ArgumentParser:
    
    parser = argparse.ArgumentParser(
        prog='cmschecker', description='CMS & WAF fingerprinting engine')
    parser.add_argument('-l', '--list', help='Path to weblist file')
    parser.add_argument('-t', '--threads', type=int, help='Thread count (5-500)')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('--retries', type=int, help='Retry count')
    parser.add_argument('--config', default='settings.ini', help='Path to settings.ini')
    parser.add_argument('--proxy', help='Path to proxy list')
    parser.add_argument('--proxy-enabled', action='store_true', help='Enable proxies')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxies')
    parser.add_argument('--proxy-rotation', choices=['round_robin', 'random', 'failover'])
    parser.add_argument('-o', '--output-dir', help='Result directory (default: result)')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'])
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')
    parser.add_argument('--quiet', action='store_true', help='Suppress per-line output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose debug logs')
    parser.add_argument('--version', action='version', version=VERSION)
    return parser


def load_targets(filename: str):
    """Load a weblist file: normalize, dedupe, skip comments. None if file missing."""
    if not os.path.isfile(filename):
        return None
    targets = []
    with open(filename, 'r', encoding='utf-8', errors='replace') as handle:
        for line in handle:
            site = normalize(line)
            if site and site not in targets:
                targets.append(site)
    return targets


def _install_hotkeys() -> None:
    """Ctrl+E stops the scan now; Ctrl+C keeps its default behavior."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    import threading

    from core.scanner import STOP

    def listener() -> None:
        while True:
            ch = _read_key()
            if ch is None:
                return
            if ch == '\x05':
                STOP.set()
                return

    threading.Thread(target=listener, daemon=True).start()


def _read_key():
    """Block for one keystroke without tripping the stdin lock. None if unavailable."""
    if os.name == 'nt':
        import msvcrt

        return msvcrt.getwch()
    import select

    ready, _w, _x = select.select([sys.stdin], [], [], None)
    return sys.stdin.read(1) if ready else None


def main() -> int:
    args = build_parser().parse_args()
    config: Config = load_config(args.config, vars(args))
    apply_color_setting(config)
    if config.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    show_banner(config)

    # interactive prompt only when neither CLI nor settings.ini provides a value
    list_file = config.weblist
    if args.list is None and list_file == 'weblist.txt' and not os.path.isfile(list_file):
        list_file = ask_weblist(list_file)
    targets = load_targets(list_file)
    if targets is None:
        print_error('File not found: %s' % list_file)
        return 1
    if not targets:
        print_error('List is empty: %s' % list_file)
        return 1
    print_info('Loaded %d unique target(s)' % len(targets))

    threads = args.threads if args.threads is not None else config.threads
    if args.threads is None and not os.path.isfile('settings.ini'):
        threads = ask_threads(threads)
    if threads < MIN_THREADS or threads > MAX_THREADS:
        print_error('Threads must be between %d and %d' % (MIN_THREADS, MAX_THREADS))
        return 1
    config = _with_threads(config, threads)
    print_info('Scanning %d target(s) with %d threads' % (len(targets), threads))

    proxy_manager = None
    if config.proxy_enabled:
        proxy_file = config.proxy_list_override or config.proxy_file
        proxy_manager = ProxyManager(proxy_file, config.proxy_rotation,
                                     max_failures=3, cooldown_seconds=30)
    fetcher = Fetcher(config, proxy_manager=proxy_manager, stop_event=STOP)

    # install Ctrl+E only after all prompts: msvcrt.getwch steals keystrokes
    _install_hotkeys()

    panel = None
    try:
        panel = run_with_live_panel(
            len(targets), config,
            lambda on_result: run_scan(targets, fetcher, _PanelAdapter(on_result), config))
    except KeyboardInterrupt:
        print_info('Stopped by user, partial results kept')
    if panel is not None:
        if STOP.is_set():
            print_info('Stopped by Ctrl+E, partial results kept')
        panel.summary(config.result_dir)
    return 0


class _PanelAdapter:
    """Adapts panel.add(...) to the on_result(url, hits, guesses, waf, status) callback."""

    def __init__(self, on_result):
        self._on_result = on_result

    def add(self, url, hits, guesses, waf, status):
        self._on_result(url, hits, guesses, waf, status)


def _with_threads(config: Config, threads: int) -> Config:
    from dataclasses import replace

    return replace(config, threads=threads)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nAborted')
        sys.exit(130)
