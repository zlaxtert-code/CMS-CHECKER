"""Rich-based TUI: banner, interactive prompts, live scan panel. Only module with print()."""
from __future__ import annotations

import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.banner import get_banner
from core.config import Config

PRIMARY = "#58a6ff"
SUCCESS = "#3fb950"
WARNING = "#d29922"
DANGER = "#f85149"
INFO = "#a371f7"
ACCENT = "#ff7b72"
MUTED = "#6e7681"
FG = "#c9d1d9"

VERSION = "1.0.1"
MIN_THREADS, MAX_THREADS = 5, 500

_console = None


def console() -> Console:
    """Lazily built shared console; rebuilt without ANSI when color is off."""
    global _console
    if _console is None:
        _console = Console(legacy_windows=False)
    return _console


def apply_color_setting(config: Config) -> None:
    """Honor --no-color by switching the shared console to plain output."""
    global _console
    if not config.use_color:
        _console = Console(no_color=True, legacy_windows=False)


def show_banner(config: Config) -> None:
    """Print the banner styled with the house palette."""
    if not config.show_banner:
        return
    text = Text(get_banner(VERSION))
    text.stylize("color " + INFO)
    for line in text.split():
        if "█" in line.plain:
            line.stylize("bold " + PRIMARY)
    console().print(text)
    console().print(Text("   CODE ", style=MUTED) +
                    Text("ZLAXTERT", style="bold " + ACCENT) +
                    Text("  ·  t.me/zlaxtert  ·  v", style=MUTED) +
                    Text(VERSION, style="bold " + ACCENT))
    console().print()


def print_info(text: str) -> None:
    console().print(f"[{SUCCESS}]●[/{SUCCESS}] [{FG}]{text}[/{FG}]")


def print_error(text: str) -> None:
    console().print(f"[{DANGER}]✖[/{DANGER}] [{DANGER}]{text}[/{DANGER}]")


def ask_weblist(default: str) -> str:
    """Interactive prompt: weblist file, defaults on empty/EOF."""
    try:
        raw = input("+ Web list [%s]: " % default)
        return raw.strip() or default
    except (EOFError, KeyboardInterrupt):
        return default


def ask_threads(default: int) -> int:
    """Interactive prompt: thread count, clamped, defaults on EOF."""
    try:
        raw = input("+ Threads [%d-%d, default %d]: " % (MIN_THREADS, MAX_THREADS, default))
    except (EOFError, KeyboardInterrupt):
        return default
    raw = raw.strip()
    if not raw:
        return default
    if not raw.isdigit():
        return default
    return max(MIN_THREADS, min(MAX_THREADS, int(raw)))


class ScanPanel:
    """Live-redrawn panel: stats line + last results table, never scrolls."""

    def __init__(self, total: int, config: Config):
        self.total = total
        self.config = config
        self.done = 0
        self.live_count = 0
        self.found = 0
        self.waf_count = 0
        self.errors = 0
        self.rows = []
        self._start = time.monotonic()

    def _stats_table(self) -> Table:
        elapsed = max(0.001, time.monotonic() - self._start)
        speed = self.done / elapsed
        eta = (self.total - self.done) / speed if speed > 0 and self.done < self.total else 0
        table = Table.grid(padding=(0, 3))
        table.add_column(justify="left")
        table.add_column(justify="left")
        table.add_row(
            f"[{MUTED}]progress[/] [{FG}]{self.done}/{self.total}[/] "
            f"[{PRIMARY}]{100 * self.done / max(1, self.total):5.1f}%[/]",
            f"[{MUTED}]speed[/] [{FG}]{speed:5.1f}[/] [{MUTED}]sites/s[/] "
            f"[{MUTED}]eta[/] [{FG}]{int(eta):02d}s[/]")
        table.add_row(
            f"[{MUTED}]live[/] [{SUCCESS}]{self.live_count}[/] "
            f"[{MUTED}]cms[/] [{PRIMARY}]{self.found}[/] "
            f"[{MUTED}]waf[/] [{INFO}]{self.waf_count}[/]",
            f"[{MUTED}]errors[/] [{DANGER}]{self.errors}[/] "
            f"[{MUTED}]elapsed[/] [{FG}]{int(elapsed):02d}s[/]")
        return table

    def _results_table(self) -> Table:
        table = Table.grid(padding=(0, 2))
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=False, overflow="ellipsis")
        table.add_row(Text("SITE", style=MUTED), Text("CMS", style=MUTED),
                      Text("WAF", style=MUTED), Text("STATUS", style=MUTED))
        for row in self.rows[-12:]:
            table.add_row(*row)
        return table

    def __rich__(self):
        return Panel(
            Group(self._stats_table(), Text(""), self._results_table()),
            title=f"[bold {PRIMARY}]CMSCHECKER · LIVE SCAN",
            border_style=PRIMARY)

    def add(self, url: str, hits, guesses, waf, status: str) -> None:
        """Record one finished target as a colored row (called from pool thread)."""
        self.done += 1
        if status == 'LIVE':
            self.live_count += 1
        elif status.startswith(('Connection', 'Error')):
            self.errors += 1
        if hits:
            cms = Text(", ".join(hits), style="bold " + SUCCESS)
            if guesses:
                cms.append(" +" + ",".join(guesses), style=WARNING)
        elif guesses:
            cms = Text(", ".join(guesses), style=WARNING)
        else:
            cms = Text("-", style=MUTED)
        waf_text = Text(waf, style="bold " + INFO) if waf else Text("-", style=MUTED)
        if status == 'LIVE':
            status_text = Text("LIVE", style=SUCCESS)
        elif status.startswith(('Connection', 'Error')):
            status_text = Text(status, style=DANGER)
        else:
            status_text = Text(status, style=WARNING)
        if hits or guesses:
            self.found += 1
        if waf:
            self.waf_count += 1
        self.rows.append((Text(url, style=FG if hits else MUTED),
                          cms, waf_text, status_text))

    def summary(self, result_dir: str) -> None:
        """Final summary block after the live panel stops."""
        console().rule(f"[bold {PRIMARY}]DONE")
        console().print(f"[{MUTED}]total[/] [{FG}]{self.done}[/]  "
                        f"[{MUTED}]live[/] [{SUCCESS}]{self.live_count}[/]  "
                        f"[{MUTED}]with cms[/] [{PRIMARY}]{self.found}[/]  "
                        f"[{MUTED}]waf[/] [{INFO}]{self.waf_count}[/]  "
                        f"[{MUTED}]errors[/] [{DANGER}]{self.errors}[/]")
        console().print(Text("results ", style=MUTED) +
                        Text(result_dir + "/results.txt", style=ACCENT) +
                        Text("  ") +
                        Text(result_dir + "/per-cms/", style=ACCENT) +
                        Text("  ") +
                        Text(result_dir + "/per-waf/", style=ACCENT))

def run_with_live_panel(total: int, config: Config, worker) -> ScanPanel:
    """Run worker(on_result) while rich Live redraws the panel ~7x/s."""
    panel = ScanPanel(total, config)
    with Live(panel, console=console(), refresh_per_second=7, screen=False):
        worker(panel.add)
    return panel
