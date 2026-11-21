"""Config loader: settings.ini + argparse merge. Only file that reads settings.ini."""
from __future__ import annotations

import configparser
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULTS = {
    "threads": 20,
    "timeout": 15,
    "retries": 3,
    "weblist": "weblist.txt",
    "result_dir": "result",
    "follow_redirects": True,
    "verify_ssl": False,
    "user_agent_rotation": True,
    "spoof_headers": True,
    "max_redirects": 5,
    "proxy_enabled": False,
    "proxy_file": "proxies.txt",
    "proxy_rotation": "round_robin",
    "save_per_cms": True,
    "format": "txt",
    "color": True,
    "banner": True,
    "quiet": False,
    "verbose": False,
    "no_color": False,
    "no_banner": False,
    "max_threads": 500,
    "min_threads": 5,
}


@dataclass(frozen=True)
class Config:
    """Merged configuration."""

    threads: int = DEFAULTS["threads"]
    timeout: int = DEFAULTS["timeout"]
    retries: int = DEFAULTS["retries"]
    weblist: str = DEFAULTS["weblist"]
    result_dir: str = DEFAULTS["result_dir"]
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent_rotation: bool = True
    spoof_headers: bool = True
    max_redirects: int = 5
    proxy_enabled: bool = False
    proxy_file: str = DEFAULTS["proxy_file"]
    proxy_rotation: str = "round_robin"
    save_per_cms: bool = True
    output_format: str = "txt"
    use_color: bool = True
    show_banner: bool = True
    quiet: bool = False
    verbose: bool = False
    proxy_list_override: Optional[str] = None
    threads_override: Optional[int] = None


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_config(ini_path: str, cli_args: Dict[str, Any]) -> Config:
    """Load settings.ini then apply non-None CLI args on top."""
    values: Dict[str, Any] = dict(DEFAULTS)
    if ini_path:
        parser = configparser.ConfigParser()
        read = parser.read(ini_path, encoding="utf-8")
        if not read:
            logger.warning("settings.ini not found at %s, using defaults", ini_path)
        else:
            _merge_ini(values, parser)
    _merge_cli(values, cli_args)
    return Config(
        threads=values["threads"],
        timeout=values["timeout"],
        retries=values["retries"],
        weblist=values["weblist"],
        result_dir=values["result_dir"],
        follow_redirects=values["follow_redirects"],
        verify_ssl=values["verify_ssl"],
        user_agent_rotation=values["user_agent_rotation"],
        spoof_headers=values["spoof_headers"],
        max_redirects=values["max_redirects"],
        proxy_enabled=values["proxy_enabled"],
        proxy_file=values["proxy_file"],
        proxy_rotation=values["proxy_rotation"],
        save_per_cms=values["save_per_cms"],
        output_format=values["format"],
        use_color=not values["no_color"] and values["color"],
        show_banner=not values["no_banner"] and values["banner"],
        quiet=values["quiet"],
        verbose=values["verbose"],
        proxy_list_override=cli_args.get("proxy"),
        threads_override=cli_args.get("threads"),
    )


def _merge_ini(values: Dict[str, Any], parser: configparser.ConfigParser) -> None:
    general = parser["general"] if parser.has_section("general") else {}
    if "threads" in general:
        values["threads"] = int(general["threads"])
    if "timeout" in general:
        values["timeout"] = int(general["timeout"])
    if "retries" in general:
        values["retries"] = int(general["retries"])
    if "weblist" in general:
        values["weblist"] = general["weblist"]
    if "result_dir" in general:
        values["result_dir"] = general["result_dir"]
    if "follow_redirects" in general:
        values["follow_redirects"] = _parse_bool(general["follow_redirects"])
    if "verify_ssl" in general:
        values["verify_ssl"] = _parse_bool(general["verify_ssl"])
    if "user_agent_rotation" in general:
        values["user_agent_rotation"] = _parse_bool(general["user_agent_rotation"])
    if "spoof_headers" in general:
        values["spoof_headers"] = _parse_bool(general["spoof_headers"])
    if "max_redirects" in general:
        values["max_redirects"] = int(general["max_redirects"])
    proxy = parser["proxy"] if parser.has_section("proxy") else {}
    if "enabled" in proxy:
        values["proxy_enabled"] = _parse_bool(proxy["enabled"])
    if "proxy_file" in proxy:
        values["proxy_file"] = proxy["proxy_file"]
    if "rotation" in proxy:
        values["proxy_rotation"] = proxy["rotation"]
    output = parser["output"] if parser.has_section("output") else {}
    if "save_per_cms" in output:
        values["save_per_cms"] = _parse_bool(output["save_per_cms"])
    if "format" in output:
        values["format"] = output["format"]
    ui = parser["ui"] if parser.has_section("ui") else {}
    if "color" in ui:
        values["color"] = _parse_bool(ui["color"])
    if "banner" in ui:
        values["banner"] = _parse_bool(ui["banner"])


def _merge_cli(values: Dict[str, Any], cli_args: Dict[str, Any]) -> None:
    # argparse dests whose names differ from config keys
    aliases = {
        "output_dir": "result_dir",
        "proxy_rotation": "proxy_rotation",
        "list": "weblist",
    }
    for key, value in cli_args.items():
        if value is None:
            continue
        dest = aliases.get(key, key)
        if dest in values:
            values[dest] = value
    if cli_args.get("proxy_enabled"):
        values["proxy_enabled"] = True
    if cli_args.get("no_proxy"):
        values["proxy_enabled"] = False
