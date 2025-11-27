"""
Configuration loader for YAML-based scanner settings.

Supports loading scanner configuration from YAML files to replace
long command-line arguments.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValidationError: If config format is invalid
        
    Example:
        >>> config = load_config("cybersec-config.yaml")
        >>> print(config["scanner"]["git"]["enabled"])
    """
    from ..exceptions import ValidationError
    
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            f"Create a config file using: cybersec-scanner init-config"
        )
    
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValidationError(f"Invalid YAML in config file: {e}")
    
    if not isinstance(config, dict):
        raise ValidationError("Config file must contain a YAML dictionary")
    
    return config


def flatten_config(config: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested configuration into dot-notation keys.
    
    Args:
        config: Nested configuration dictionary
        prefix: Key prefix for recursion
        
    Returns:
        Flattened dictionary with dot-notation keys
        
    Example:
        >>> config = {"scanner": {"git": {"enabled": True}}}
        >>> flat = flatten_config(config)
        >>> print(flat["scanner.git.enabled"])  # True
    """
    flat = {}
    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_config(value, full_key))
        else:
            flat[full_key] = value
    return flat


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration structure and values.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        True if valid
        
    Raises:
        ValidationError: If configuration is invalid
    """
    from ..exceptions import ValidationError
    
    # Check for required top-level keys
    if "scanner" not in config and not any(k.startswith("enable_") for k in config):
        raise ValidationError(
            "Config must contain 'scanner' section or enable flags\n"
            "See example config: cybersec-scanner init-config"
        )
    
    # Validate scanner settings if present
    if "scanner" in config:
        scanner_config = config["scanner"]
        
        # Git settings
        if "git" in scanner_config:
            git_config = scanner_config["git"]
            if "max_commits" in git_config:
                if not isinstance(git_config["max_commits"], int) or git_config["max_commits"] <= 0:
                    raise ValidationError("scanner.git.max_commits must be a positive integer")
        
        # Web settings
        if "web" in scanner_config:
            web_config = scanner_config["web"]
            if "target" in web_config and not isinstance(web_config["target"], str):
                raise ValidationError("scanner.web.target must be a string URL")
    
    return True


def create_default_config(output_path: str = "cybersec-config.yaml"):
    """
    Create a default configuration file with all options.
    
    Args:
        output_path: Where to save the config file
        
    Example:
        >>> create_default_config("my-config.yaml")
    """
    default_config = {
        "scanner": {
            "git": {
                "enabled": True,
                "root": ".",
                "max_commits": 50,
                "ignore_patterns": [
                    "*.min.js",
                    "node_modules/",
                    "venv/",
                ],
            },
            "web": {
                "enabled": False,
                "target": "http://localhost:8000",
                "max_pages": 50,
                "timeout": 10,
            },
            "mitm": {
                "enabled": False,
                "traffic_file": "./mitm_traffic.ndjson",
                "port": 8080,
            },
            "runtime": {
                "enabled": False,
            },
        },
        "rag": {
            "enabled": True,
            "model": "gemma3:1b",
            "mode": "graph",
        },
        "output": {
            "audit_report": "audit_report.json",
            "graph_file": "knowledge_graph.gpickle",
            "database": "security_audit.db",
        },
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
    
    print(f"Created default config at: {output_path}")
