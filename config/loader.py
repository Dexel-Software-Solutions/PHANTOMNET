"""
PHANTOMNET Configuration Loader
Validates and loads YAML config with strict schema enforcement.
"""

import os
import yaml
import ipaddress
from pathlib import Path
from typing import Any


REQUIRED_KEYS = ["interface", "network_cidr", "dashboard_port"]

DEFAULTS = {
    "log_level": "INFO",
    "dashboard_port": 8443,
    "morphing_interval_seconds": 30,
    "max_fake_hosts": 50,
    "arp_deception": True,
    "dns_deception": True,
    "forensic_traps_enabled": True,
    "threat_intel_output": "logs/threat_intel.json",
    "topology_complexity": "medium",
}


class ConfigValidationError(Exception):
    pass


class ConfigLoader:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)

    def load(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ConfigValidationError("Config file must be a YAML mapping.")

        # Apply defaults
        config = {**DEFAULTS, **raw}

        # Validate required keys
        for key in REQUIRED_KEYS:
            if key not in config:
                raise ConfigValidationError(f"Missing required config key: '{key}'")

        # Validate interface name
        if not isinstance(config["interface"], str) or not config["interface"].strip():
            raise ConfigValidationError("'interface' must be a non-empty string.")

        # Validate CIDR
        try:
            ipaddress.ip_network(config["network_cidr"], strict=False)
        except ValueError:
            raise ConfigValidationError(
                f"Invalid 'network_cidr': {config['network_cidr']}"
            )

        # Validate port
        port = config["dashboard_port"]
        if not isinstance(port, int) or not (1024 <= port <= 65535):
            raise ConfigValidationError(
                f"'dashboard_port' must be an integer between 1024-65535, got: {port}"
            )

        # Validate log level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if config["log_level"].upper() not in valid_levels:
            raise ConfigValidationError(
                f"Invalid log_level: {config['log_level']}. Must be one of {valid_levels}"
            )
        config["log_level"] = config["log_level"].upper()

        # Validate topology_complexity
        valid_complexity = {"low", "medium", "high"}
        if config["topology_complexity"] not in valid_complexity:
            raise ConfigValidationError(
                f"'topology_complexity' must be one of {valid_complexity}"
            )

        # Validate max_fake_hosts
        mfh = config["max_fake_hosts"]
        if not isinstance(mfh, int) or mfh < 1 or mfh > 500:
            raise ConfigValidationError(
                f"'max_fake_hosts' must be an integer between 1-500, got: {mfh}"
            )

        # Ensure output log directory exists
        intel_path = Path(config["threat_intel_output"])
        intel_path.parent.mkdir(parents=True, exist_ok=True)

        return config
