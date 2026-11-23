#!/usr/bin/env python3
"""
SCROLL v6.0 - The Ultimate Security Assessment Platform
=======================================================

A revolutionary, professional-grade security assessment tool that combines
advanced scanning capabilities with an intuitive interface and comprehensive
reporting. Built for ethical hackers, penetration testers, and security teams.

Key Features:
- Zero timeout execution (tools run to natural completion)
- Intelligent workflow with interactive control
- Multi-phase parallel execution engine
- Professional reporting system with HTML dashboards
- Modular, extensible architecture

Author: Security Engineering Team
License: GPLv3 - For authorized security testing only
Version: 6.0.0
Release Date: 2024-01-15

Note: This tool must only be used on systems you own or have explicit
      written permission to test. Unauthorized scanning is illegal.
"""

# ============================================================================
# IMPORTS & DEPENDENCIES
# ============================================================================

import os
import sys
import json
import time
import signal
import shutil
import socket
import hashlib
import logging
import threading
import subprocess
import concurrent.futures
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from abc import ABC, abstractmethod
import asyncio
import inspect
import gc
import re
import csv
import html
import urllib.parse
import ipaddress
import ssl
import warnings

# Third-party imports with graceful fallbacks
try:
    from colorama import init, Fore, Back, Style, just_fix_windows_console
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Create dummy classes for colorama
    class DummyColorama:
        Fore = type('Fore', (), {k: '' for k in ['BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'RESET']})
        Back = type('Back', (), {k: '' for k in ['BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'RESET']})
        Style = type('Style', (), {'BRIGHT': '', 'DIM': '', 'NORMAL': '', 'RESET_ALL': ''})
        init = lambda: None
        just_fix_windows_console = lambda: None
    
    Fore = DummyColorama.Fore
    Back = DummyColorama.Back
    Style = DummyColorama.Style
    init = DummyColorama.init
    just_fix_windows_console = DummyColorama.just_fix_windows_console

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

# Initialize colorama if available
if COLORAMA_AVAILABLE:
    init(autoreset=True)
    just_fix_windows_console()

# ============================================================================
# CONSTANTS & GLOBAL CONFIGURATION
# ============================================================================

# Application Metadata
APP_NAME = "SCROLL"
APP_VERSION = "6.0.0"
APP_AUTHOR = "Security Engineering Team"
APP_LICENSE = "GPLv3"
APP_DESCRIPTION = "Ultimate Security Assessment Platform"

# Version Requirements
MIN_PYTHON_VERSION = (3, 8)
RECOMMENDED_PYTHON_VERSION = (3, 9)

# Execution Configuration
MAX_CONCURRENT_TOOLS = 3  # Maximum parallel tool execution
MAX_RETRIES = 2           # Maximum retry attempts for failed tools
REQUEST_TIMEOUT = 30      # HTTP request timeout in seconds
SCAN_TIMEOUT = 0          # Global scan timeout (0 = no timeout)

# File System Configuration
DEFAULT_OUTPUT_DIR = Path("SCROLL_Results")
DEFAULT_WORDLIST_DIR = Path("/usr/share/wordlists")
MAX_LOG_SIZE_MB = 10      # Maximum log file size before rotation
MAX_OUTPUT_AGE_DAYS = 30  # Auto-cleanup after 30 days

# Network Configuration
DEFAULT_USER_AGENT = f"{APP_NAME}/{APP_VERSION}"
MAX_REDIRECTS = 5
CONNECTION_POOL_SIZE = 10
RATE_LIMIT_DELAY = 0.1    # Seconds between requests

# Security Configuration
DISALLOWED_TARGETS = [
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.", "192.168.", "10.", "172.16."
]

# ============================================================================
# ENUMERATIONS
# ============================================================================

class ScanMode(Enum):
    """Defines available scanning modes with descriptions"""
    RECONNAISSANCE = auto()
    STEALTH = auto()
    STANDARD = auto()
    AGGRESSIVE = auto()
    COMPREHENSIVE = auto()
    PENETRATION = auto()
    CUSTOM = auto()
    
    def description(self) -> str:
        """Returns human-readable description of scan mode"""
        descriptions = {
            ScanMode.RECONNAISSANCE: "Passive information gathering only",
            ScanMode.STEALTH: "Minimal interaction, low detectability",
            ScanMode.STANDARD: "Balanced speed and coverage",
            ScanMode.AGGRESSIVE: "Fast scanning, may trigger alerts",
            ScanMode.COMPREHENSIVE: "Thorough assessment, takes time",
            ScanMode.PENETRATION: "Includes exploit verification",
            ScanMode.CUSTOM: "User-configured scan profile"
        }
        return descriptions.get(self, "Unknown scan mode")

class ToolStatus(Enum):
    """Represents execution status of security tools"""
    PENDING = auto()
    PREPARING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()
    TIMED_OUT = auto()
    CANCELLED = auto()
    BACKGROUND = auto()
    
    def is_terminal(self) -> bool:
        """Check if status is terminal (no further changes)"""
        return self in [self.COMPLETED, self.FAILED, self.SKIPPED, self.CANCELLED]

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    
    @property
    def color(self) -> str:
        """Returns ANSI color code for severity"""
        if not COLORAMA_AVAILABLE:
            return ""
        
        colors = {
            Severity.CRITICAL: Fore.RED + Style.BRIGHT,
            Severity.HIGH: Fore.RED,
            Severity.MEDIUM: Fore.YELLOW,
            Severity.LOW: Fore.GREEN,
            Severity.INFO: Fore.CYAN
        }
        return colors.get(self, Fore.WHITE)
    
    @property
    def priority(self) -> int:
        """Returns priority number (lower = more critical)"""
        priorities = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5
        }
        return priorities.get(self, 99)

class Phase(Enum):
    """Scanning phases in sequential order"""
    INITIALIZATION = auto()
    RECONNAISSANCE = auto()
    NETWORK_DISCOVERY = auto()
    WEB_ASSESSMENT = auto()
    VULNERABILITY_SCAN = auto()
    EXPLOIT_VERIFICATION = auto()
    POST_EXPLOITATION = auto()
    REPORTING = auto()
    CLEANUP = auto()

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ToolMetadata:
    """Metadata for security tools"""
    name: str
    version: str = "Unknown"
    author: str = "Unknown"
    license: str = "Unknown"
    homepage: str = ""
    description: str = ""
    installed: bool = False
    path: Optional[Path] = None

@dataclass
class ToolConfiguration:
    """Configuration for individual security tools"""
    name: str
    command_template: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    timeout: int = 0  # 0 means no timeout
    retries: int = 1
    enabled: bool = True
    priority: int = 50  # 1-100, higher = more important
    estimated_duration: int = 300  # Estimated seconds
    dependencies: List[str] = field(default_factory=list)
    wordlists: List[str] = field(default_factory=list)
    
    def resolve_command(self, context: Dict[str, Any]) -> str:
        """Resolve command template with context variables"""
        try:
            return self.command_template.format(**context)
        except KeyError as e:
            raise ValueError(f"Missing context variable: {e}")

@dataclass
class ScanTarget:
    """Represents a target for scanning"""
    url: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    scope: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    
    def validate(self) -> bool:
        """Validate target configuration"""
        if not any([self.url, self.domain, self.ip_address]):
            return False
        
        # Validate IP address if provided
        if self.ip_address:
            try:
                ipaddress.ip_address(self.ip_address)
            except ValueError:
                return False
        
        # Validate URL if provided
        if self.url:
            try:
                parsed = urllib.parse.urlparse(self.url)
                if not parsed.scheme or not parsed.netloc:
                    return False
            except:
                return False
        
        return True
    
    @property
    def display_name(self) -> str:
        """Get display name for target"""
        if self.url:
            return self.url
        elif self.domain:
            return self.domain
        elif self.ip_address:
            return self.ip_address
        return "Unknown Target"

@dataclass
class Finding:
    """Represents a security finding/vulnerability"""
    id: str
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    location: str
    evidence: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.name
        data['timestamp'] = self.timestamp.isoformat()
        data['tags'] = list(self.tags)
        return data

@dataclass
class ScanStatistics:
    """Statistics for scan execution"""
    start_time: datetime
    end_time: Optional[datetime] = None
    tools_executed: int = 0
    tools_failed: int = 0
    tools_skipped: int = 0
    findings_count: int = 0
    findings_by_severity: Dict[Severity, int] = field(default_factory=dict)
    bytes_processed: int = 0
    requests_made: int = 0
    errors_encountered: int = 0
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Calculate scan duration"""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate of tools"""
        if self.tools_executed == 0:
            return 0.0
        successful = self.tools_executed - self.tools_failed
        return (successful / self.tools_executed) * 100

@dataclass
class ScanConfiguration:
    """Complete scan configuration"""
    mode: ScanMode
    target: ScanTarget
    output_directory: Path
    wordlist_directory: Path
    intensity: int  # 1-10
    max_concurrent_tools: int
    enable_bruteforce: bool
    enable_exploitation: bool
    save_session: bool
    generate_reports: bool
    custom_tools: List[str] = field(default_factory=list)
    excluded_tools: List[str] = field(default_factory=list)
    additional_parameters: Dict[str, Any] = field(default_factory=dict)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        if not self.target.validate():
            errors.append("Invalid target configuration")
        
        if not self.output_directory.parent.exists():
            errors.append(f"Output directory parent does not exist: {self.output_directory.parent}")
        
        if not 1 <= self.intensity <= 10:
            errors.append(f"Intensity must be between 1 and 10, got {self.intensity}")
        
        if self.max_concurrent_tools < 1:
            errors.append("Maximum concurrent tools must be at least 1")
        
        return errors

# ============================================================================
# LOGGING SYSTEM
# ============================================================================

class ScrollLogger:
    """
    Advanced logging system with multiple outputs, colors, and log levels.
    Supports file logging, console logging, and in-memory buffering.
    """
    
    # Log level configuration
    LEVELS = {
        'DEBUG': 10,
        'INFO': 20,
        'SUCCESS': 25,
        'WARNING': 30,
        'ERROR': 40,
        'CRITICAL': 50
    }
    
    # Color configuration
    COLORS = {
        'DEBUG': Fore.CYAN + Style.DIM,
        'INFO': Fore.BLUE,
        'SUCCESS': Fore.GREEN + Style.BRIGHT,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT
    } if COLORAMA_AVAILABLE else {}
    
    def __init__(self, name: str = "SCROLL", level: str = "INFO"):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            level: Minimum log level
        """
        self.name = name
        self.level = self.LEVELS.get(level.upper(), 20)
        self.handlers = []
        self.buffer = deque(maxlen=1000)  # In-memory buffer for UI
        
        # Set up console handler by default
        self.add_console_handler()
    
    def add_console_handler(self):
        """Add console output handler"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.handlers.append(console_handler)
    
    def add_file_handler(self, filepath: Path, max_size_mb: int = 10):
        """
        Add file output handler with rotation.
        
        Args:
            filepath: Path to log file
            max_size_mb: Maximum file size in MB before rotation
        """
        try:
            # Create directory if it doesn't exist
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Configure rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                filepath,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
            )
            self.handlers.append(file_handler)
        except Exception as e:
            self._raw_log("ERROR", f"Failed to create file handler: {e}")
    
    def _should_log(self, level: str) -> bool:
        """Check if message should be logged based on level"""
        return self.LEVELS.get(level.upper(), 0) >= self.level
    
    def _raw_log(self, level: str, message: str, **kwargs):
        """
        Internal logging method.
        
        Args:
            level: Log level
            message: Message to log
            **kwargs: Additional parameters
        """
        if not self._should_log(level):
            return
        
        # Format message
        timestamp = datetime.now().strftime('%H:%M:%S')
        color = self.COLORS.get(level, '')
        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
        
        formatted = f"{color}[{timestamp}] [{level:>8}] {message}{reset}"
        
        # Add to buffer for UI
        self.buffer.append({
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'color': color
        })
        
        # Send to all handlers
        for handler in self.handlers:
            try:
                if isinstance(handler, logging.StreamHandler):
                    handler.stream.write(formatted + '\n')
                else:
                    handler.emit(logging.LogRecord(
                        name=self.name,
                        level=self.LEVELS[level],
                        pathname=__file__,
                        lineno=0,
                        msg=message,
                        args=(),
                        exc_info=None
                    ))
            except Exception as e:
                # Fallback to stderr if handlers fail
                sys.stderr.write(f"Logger error: {e}\n")
    
    # Public logging methods
    def debug(self, message: str, **kwargs):
        self._raw_log("DEBUG", message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._raw_log("INFO", message, **kwargs)
    
    def success(self, message: str, **kwargs):
        self._raw_log("SUCCESS", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._raw_log("WARNING", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._raw_log("ERROR", message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._raw_log("CRITICAL", message, **kwargs)
    
    def get_recent_logs(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get recent log entries for UI display"""
        return list(self.buffer)[-count:]

# Create global logger instance
logger = ScrollLogger("SCROLL")

# ============================================================================
# USER INTERFACE SYSTEM
# ============================================================================

class UserInterface:
    """
    Advanced user interface system with menus, prompts, and visual elements.
    Handles all user interactions in a consistent and user-friendly manner.
    """
    
    def __init__(self):
        self.current_menu = None
        self.menu_history = []
        self.width = 80
        
    @staticmethod
    def clear_screen():
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def get_terminal_size() -> Tuple[int, int]:
        """Get terminal dimensions"""
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24
    
    def display_banner(self):
        """Display the SCROLL banner"""
        self.clear_screen()
        
        banner = f"""
{Fore.CYAN + Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗ ██████╗██████╗  ██████╗ ██╗     ██╗                              ║
║   ██╔════╝██╔════╝██╔══██╗██╔═══██╗██║     ██║                              ║
║   ███████╗██║     ██████╔╝██║   ██║██║     ██║                              ║
║   ╚════██║██║     ██╔══██╗██║   ██║██║     ██║                              ║
║   ███████║╚██████╗██║  ██║╚██████╔╝███████╗███████╗                         ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝                         ║
║                                                                              ║
║            Security Comprehensive Reconnaissance & Offensive Scanner         ║
║                            Version {APP_VERSION}                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def display_header(self, title: str, subtitle: str = ""):
        """Display section header"""
        print(f"\n{Fore.CYAN + Style.BRIGHT}{'═' * self.width}{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{title.center(self.width)}{Style.RESET_ALL}")
        if subtitle:
            print(f"{Fore.CYAN}{subtitle.center(self.width)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'═' * self.width}{Style.RESET_ALL}\n")
    
    def display_menu(self, title: str, options: List[Tuple[str, str, Any]], 
                    back_option: bool = True) -> Any:
        """
        Display interactive menu.
        
        Args:
            title: Menu title
            options: List of (key, description, value) tuples
            back_option: Whether to include back option
        
        Returns:
            Selected value or None if back selected
        """
        self.display_header(title)
        
        # Display options
        for key, description, _ in options:
            print(f"  {Fore.GREEN}[{key}]{Style.RESET_ALL} {description}")
        
        if back_option:
            print(f"\n  {Fore.YELLOW}[B]{Style.RESET_ALL} Back")
        
        print()
        
        # Get user input
        while True:
            choice = input(f"{Fore.CYAN}Select option: {Style.RESET_ALL}").strip().upper()
            
            if back_option and choice == 'B':
                return None
            
            for key, _, value in options:
                if choice == key.upper():
                    return value
            
            print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")
    
    def prompt_text(self, prompt: str, default: str = "", 
                   validator: Callable[[str], bool] = None) -> str:
        """
        Prompt for text input with validation.
        
        Args:
            prompt: Prompt text
            default: Default value
            validator: Validation function
        
        Returns:
            User input
        """
        while True:
            if default:
                full_prompt = f"{Fore.CYAN}{prompt} [{default}]: {Style.RESET_ALL}"
            else:
                full_prompt = f"{Fore.CYAN}{prompt}: {Style.RESET_ALL}"
            
            value = input(full_prompt).strip()
            
            if not value and default:
                return default
            
            if value:
                if validator and not validator(value):
                    print(f"{Fore.RED}Invalid input. Please try again.{Style.RESET_ALL}")
                    continue
                return value
            
            print(f"{Fore.YELLOW}Input cannot be empty.{Style.RESET_ALL}")
    
    def prompt_yes_no(self, question: str, default: bool = True) -> bool:
        """
        Prompt for yes/no confirmation.
        
        Args:
            question: Question to ask
            default: Default answer
        
        Returns:
            True for yes, False for no
        """
        default_text = "Y/n" if default else "y/N"
        while True:
            response = input(f"{Fore.CYAN}{question} [{default_text}]: {Style.RESET_ALL}").strip().lower()
            
            if not response:
                return default
            
            if response in ['y', 'yes', '1']:
                return True
            elif response in ['n', 'no', '0']:
                return False
            
            print(f"{Fore.RED}Please enter 'y' or 'n'.{Style.RESET_ALL}")
    
    def progress_bar(self, current: int, total: int, prefix: str = "", 
                    suffix: str = "", length: int = 50):
        """
        Display progress bar.
        
        Args:
            current: Current progress
            total: Total steps
            prefix: Text before bar
            suffix: Text after bar
            length: Bar length in characters
        """
        percent = current / total if total > 0 else 0
        filled = int(length * percent)
        bar = f"{Fore.GREEN}█{Style.RESET_ALL}" * filled + f"{Fore.WHITE}░{Style.RESET_ALL}" * (length - filled)
        
        sys.stdout.write(f"\r{prefix} |{bar}| {percent:.1%} {suffix}")
        sys.stdout.flush()
    
    def display_table(self, headers: List[str], rows: List[List[Any]], 
                     col_widths: List[int] = None):
        """
        Display data in formatted table.
        
        Args:
            headers: Column headers
            rows: Table rows
            col_widths: Column widths (auto-calculated if None)
        """
        if not rows:
            return
        
        # Calculate column widths if not provided
        if not col_widths:
            col_widths = [len(str(h)) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Display header
        header_line = " | ".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
        separator = "-+-".join("-" * w for w in col_widths)
        
        print(f"{Fore.CYAN + Style.BRIGHT}{header_line}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{separator}{Style.RESET_ALL}")
        
        # Display rows
        for row in rows:
            row_line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
            print(row_line)
    
    def display_finding(self, finding: Finding):
        """Display a security finding in detailed format"""
        self.display_header(f"Finding: {finding.title}", f"Severity: {finding.severity.name}")
        
        print(f"{Fore.CYAN}Description:{Style.RESET_ALL}")
        print(f"  {finding.description}\n")
        
        print(f"{Fore.CYAN}Location:{Style.RESET_ALL}")
        print(f"  {finding.location}\n")
        
        print(f"{Fore.CYAN}Impact:{Style.RESET_ALL}")
        print(f"  {finding.impact}\n")
        
        print(f"{Fore.CYAN}Remediation:{Style.RESET_ALL}")
        print(f"  {finding.remediation}\n")
        
        if finding.references:
            print(f"{Fore.CYAN}References:{Style.RESET_ALL}")
            for ref in finding.references:
                print(f"  • {ref}")
            print()

# ============================================================================
# TOOL MANAGEMENT SYSTEM
# ============================================================================

class ToolManager:
    """
    Manages security tools discovery, configuration, and execution.
    Provides unified interface for all security tools used by SCROLL.
    """
    
    # Registry of known tools with metadata
    TOOL_REGISTRY = {
        'nmap': ToolMetadata(
            name="nmap",
            version="7.93",
            author="Gordon Lyon",
            license="GPLv2",
            homepage="https://nmap.org",
            description="Network exploration and security auditing"
        ),
        'nikto': ToolMetadata(
            name="nikto",
            version="2.5.0",
            author="Chris Sullo",
            license="GPLv2",
            homepage="https://cirt.net/Nikto2",
            description="Web server vulnerability scanner"
        ),
        'whatweb': ToolMetadata(
            name="whatweb",
            version="0.5.5",
            author="Andrew Horton",
            license="GPLv2",
            homepage="https://morningstarsecurity.com/research/whatweb",
            description="Web technology identifier"
        ),
        'gobuster': ToolMetadata(
            name="gobuster",
            version="3.5.0",
            author="OJ Reeves",
            license="Apache 2.0",
            homepage="https://github.com/OJ/gobuster",
            description="Directory/file brute forcer"
        ),
        'sqlmap': ToolMetadata(
            name="sqlmap",
            version="1.7",
            author="Bernardo Damele",
            license="GPLv2",
            homepage="https://sqlmap.org",
            description="Automatic SQL injection tool"
        ),
        'sslscan': ToolMetadata(
            name="sslscan",
            version="2.0.15",
            author="rbsec",
            license="GPLv3",
            homepage="https://github.com/rbsec/sslscan",
            description="SSL/TLS configuration scanner"
        ),
        'nuclei': ToolMetadata(
            name="nuclei",
            version="2.9.11",
            author="ProjectDiscovery",
            license="MIT",
            homepage="https://github.com/projectdiscovery/nuclei",
            description="Vulnerability scanner based on templates"
        )
    }
    
    def __init__(self):
        self.tools = {}
        self.discovered_tools = {}
        self._load_tools()
    
    def _load_tools(self):
        """Load tool configurations from registry"""
        for name, metadata in self.TOOL_REGISTRY.items():
            # Check if tool is installed
            tool_path = shutil.which(name)
            metadata.installed = bool(tool_path)
            metadata.path = Path(tool_path) if tool_path else None
            
            # Create configuration based on metadata
            config = self._create_tool_configuration(name, metadata)
            
            self.tools[name] = {
                'metadata': metadata,
                'config': config
            }
    
    def _create_tool_configuration(self, name: str, metadata: ToolMetadata) -> ToolConfiguration:
        """Create tool configuration based on name and metadata"""
        # Base configurations for each tool
        configurations = {
            'nmap': ToolConfiguration(
                name="nmap",
                command_template="nmap {flags} {target} -oN {output}",
                arguments={
                    'flags': '-sS -sV -sC -T4',
                    'target': '',
                    'output': ''
                },
                timeout=0,  # No timeout
                retries=1,
                estimated_duration=300
            ),
            'nikto': ToolConfiguration(
                name="nikto",
                command_template="nikto -h {target} -Format txt -output {output}",
                arguments={
                    'target': '',
                    'output': ''
                },
                timeout=600,
                retries=2,
                estimated_duration=180
            ),
            'whatweb': ToolConfiguration(
                name="whatweb",
                command_template="whatweb -a 3 {target} -v --log-xml={output}",
                arguments={
                    'target': '',
                    'output': ''
                },
                timeout=120,
                retries=2,
                estimated_duration=60
            ),
            'gobuster': ToolConfiguration(
                name="gobuster",
                command_template="gobuster dir -u {target} -w {wordlist} -o {output}",
                arguments={
                    'target': '',
                    'wordlist': '',
                    'output': ''
                },
                timeout=0,  # No timeout
                retries=1,
                estimated_duration=900
            ),
            'sqlmap': ToolConfiguration(
                name="sqlmap",
                command_template="sqlmap -u {target} --batch --level=1 --output-dir={output_dir}",
                arguments={
                    'target': '',
                    'output_dir': ''
                },
                timeout=1200,
                retries=1,
                estimated_duration=600
            )
        }
        
        return configurations.get(name, ToolConfiguration(
            name=name,
            command_template=f"{name} {{target}}",
            timeout=300,
            retries=2,
            estimated_duration=300
        ))
    
    def discover_tools(self) -> Dict[str, bool]:
        """
        Discover installed security tools.
        
        Returns:
            Dictionary mapping tool names to installation status
        """
        discovered = {}
        
        for name, data in self.tools.items():
            metadata = data['metadata']
            if metadata.installed:
                discovered[name] = True
                logger.success(f"Found {name} v{metadata.version}")
            else:
                discovered[name] = False
                logger.warning(f"{name} not found")
        
        return discovered
    
    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """Get tool by name"""
        return self.tools.get(name)
    
    def get_installed_tools(self) -> List[str]:
        """Get list of installed tools"""
        return [name for name, data in self.tools.items() 
                if data['metadata'].installed]
    
    def execute_tool(self, tool_name: str, context: Dict[str, Any]) -> Tuple[bool, str, float]:
        """
        Execute a security tool.
        
        Args:
            tool_name: Name of tool to execute
            context: Context variables for command template
        
        Returns:
            Tuple of (success, output, execution_time)
        """
        tool_data = self.get_tool(tool_name)
        if not tool_data:
            return False, f"Tool not found: {tool_name}", 0.0
        
        if not tool_data['metadata'].installed:
            return False, f"Tool not installed: {tool_name}", 0.0
        
        config = tool_data['config']
        
        try:
            # Build command
            command = config.resolve_command(context)
            
            logger.info(f"Executing: {command}")
            
            # Execute with subprocess
            start_time = time.time()
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Collect output in real-time
            output_lines = []
            while True:
                line = process.stdout.readline()
                if line:
                    output_lines.append(line)
                    # Log long-running process status
                    elapsed = time.time() - start_time
                    if elapsed > 30 and elapsed % 30 < 1:
                        logger.debug(f"{tool_name} running for {elapsed:.0f}s...")
                elif process.poll() is not None:
                    break
            
            # Get remaining output
            remaining, _ = process.communicate()
            if remaining:
                output_lines.append(remaining)
            
            output = ''.join(output_lines)
            exit_code = process.returncode
            execution_time = time.time() - start_time
            
            if exit_code == 0:
                logger.success(f"{tool_name} completed in {execution_time:.1f}s")
                return True, output, execution_time
            else:
                logger.warning(f"{tool_name} failed with exit code {exit_code}")
                return False, output, execution_time
            
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return False, str(e), time.time() - start_time if 'start_time' in locals() else 0.0
    
    def get_recommended_tools(self, scan_mode: ScanMode) -> List[str]:
        """
        Get recommended tools for a scan mode.
        
        Args:
            scan_mode: Scan mode
        
        Returns:
            List of recommended tool names
        """
        # Tool recommendations by scan mode
        recommendations = {
            ScanMode.RECONNAISSANCE: ['whatweb', 'nmap'],
            ScanMode.STEALTH: ['whatweb', 'nmap', 'sslscan'],
            ScanMode.STANDARD: ['nmap', 'whatweb', 'nikto', 'sslscan'],
            ScanMode.AGGRESSIVE: ['nmap', 'nikto', 'gobuster', 'nuclei'],
            ScanMode.COMPREHENSIVE: ['nmap', 'nikto', 'whatweb', 'gobuster', 'sslscan', 'nuclei'],
            ScanMode.PENETRATION: ['nmap', 'nikto', 'gobuster', 'sqlmap', 'nuclei']
        }
        
        return recommendations.get(scan_mode, self.get_installed_tools())

# ============================================================================
# SCAN ENGINE
# ============================================================================

class ScanEngine:
    """
    Core scanning engine that orchestrates the entire security assessment.
    Manages phases, tool execution, and data collection.
    """
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.tool_manager = ToolManager()
        self.statistics = ScanStatistics(start_time=datetime.now())
        self.findings = []
        self.phase_results = {}
        self.is_running = False
        self.is_paused = False
        self.current_phase = None
        
        # Create output directories
        self._create_output_directories()
        
        # Initialize phase handlers
        self._init_phase_handlers()
    
    def _create_output_directories(self):
        """Create organized output directory structure"""
        directories = [
            'logs',
            'reports',
            'data',
            'tools',
            'screenshots',
            'evidence',
            'backups'
        ]
        
        for directory in directories:
            (self.config.output_directory / directory).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Output directory: {self.config.output_directory}")
    
    def _init_phase_handlers(self):
        """Initialize phase handler methods"""
        self.phase_handlers = {
            Phase.INITIALIZATION: self._phase_initialization,
            Phase.RECONNAISSANCE: self._phase_reconnaissance,
            Phase.NETWORK_DISCOVERY: self._phase_network_discovery,
            Phase.WEB_ASSESSMENT: self._phase_web_assessment,
            Phase.VULNERABILITY_SCAN: self._phase_vulnerability_scan,
            Phase.EXPLOIT_VERIFICATION: self._phase_exploit_verification,
            Phase.POST_EXPLOITATION: self._phase_post_exploitation,
            Phase.REPORTING: self._phase_reporting,
            Phase.CLEANUP: self._phase_cleanup
        }
    
    def run(self):
        """Execute the complete scan"""
        try:
            self.is_running = True
            
            # Record start time
            self.statistics.start_time = datetime.now()
            logger.info(f"Starting scan: {self.config.target.display_name}")
            
            # Execute phases in order
            for phase in Phase:
                if not self.is_running:
                    break
                
                if self.is_paused:
                    logger.info("Scan paused. Waiting to resume...")
                    while self.is_paused and self.is_running:
                        time.sleep(1)
                
                self._execute_phase(phase)
            
            # Complete statistics
            self.statistics.end_time = datetime.now()
            self.statistics.findings_count = len(self.findings)
            
            # Count findings by severity
            for finding in self.findings:
                self.statistics.findings_by_severity[finding.severity] = \
                    self.statistics.findings_by_severity.get(finding.severity, 0) + 1
            
            logger.success(f"Scan completed in {self.statistics.duration}")
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            self.stop()
        except Exception as e:
            logger.critical(f"Scan failed: {e}")
            self.stop()
            raise
    
    def _execute_phase(self, phase: Phase):
        """Execute a single scan phase"""
        self.current_phase = phase
        
        logger.info(f"Starting phase: {phase.name.replace('_', ' ').title()}")
        
        # Check if phase handler exists
        if phase in self.phase_handlers:
            try:
                # Execute phase
                result = self.phase_handlers[phase]()
                self.phase_results[phase] = result
                
                # Log phase completion
                if result.get('success', False):
                    logger.success(f"Phase completed: {phase.name}")
                else:
                    logger.warning(f"Phase completed with issues: {phase.name}")
                    
            except Exception as e:
                logger.error(f"Phase failed: {phase.name} - {e}")
                self.phase_results[phase] = {
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.now()
                }
        else:
            logger.warning(f"No handler for phase: {phase.name}")
    
    def pause(self):
        """Pause the scan"""
        self.is_paused = True
        logger.info("Scan paused")
    
    def resume(self):
        """Resume the scan"""
        self.is_paused = False
        logger.info("Scan resumed")
    
    def stop(self):
        """Stop the scan"""
        self.is_running = False
        logger.info("Scan stopped")
    
    # Phase implementation methods
    def _phase_initialization(self) -> Dict[str, Any]:
        """Initialization phase: Setup and validation"""
        result = {
            'success': True,
            'tools_checked': 0,
            'tools_available': 0,
            'warnings': []
        }
        
        # Check target accessibility
        logger.info("Validating target...")
        if not self.config.target.validate():
            raise ValueError("Invalid target configuration")
        
        # Check tool availability
        logger.info("Checking tool availability...")
        available_tools = self.tool_manager.discover_tools()
        
        result['tools_checked'] = len(available_tools)
        result['tools_available'] = sum(1 for v in available_tools.values() if v)
        
        if result['tools_available'] == 0:
            result['warnings'].append("No security tools found")
            logger.warning("No security tools found. Some scans may not work.")
        
        # Create session file
        session_file = self.config.output_directory / 'session.json'
        session_data = {
            'config': asdict(self.config),
            'start_time': self.statistics.start_time.isoformat(),
            'target': asdict(self.config.target)
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        logger.success("Initialization completed")
        return result
    
    def _phase_reconnaissance(self) -> Dict[str, Any]:
        """Reconnaissance phase: Information gathering"""
        result = {
            'success': True,
            'subdomains_found': 0,
            'technologies_identified': 0,
            'dns_records': [],
            'whois_data': None
        }
        
        # DNS reconnaissance
        if DNS_AVAILABLE:
            try:
                logger.info("Performing DNS reconnaissance...")
                domain = self.config.target.domain
                
                if domain:
                    resolver = dns.resolver.Resolver()
                    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
                    
                    for record_type in record_types:
                        try:
                            answers = resolver.resolve(domain, record_type)
                            result['dns_records'].extend([
                                {'type': record_type, 'value': str(rdata)}
                                for rdata in answers
                            ])
                        except:
                            pass
                    
                    logger.success(f"Found {len(result['dns_records'])} DNS records")
            except Exception as e:
                logger.warning(f"DNS reconnaissance failed: {e}")
        
        # Web technology identification
        if 'whatweb' in self.tool_manager.get_installed_tools():
            try:
                logger.info("Identifying web technologies...")
                
                output_file = self.config.output_directory / 'data' / 'technologies.xml'
                context = {
                    'target': self.config.target.url,
                    'output': str(output_file)
                }
                
                success, output, duration = self.tool_manager.execute_tool('whatweb', context)
                
                if success and output_file.exists():
                    result['technologies_identified'] = self._parse_technologies(output_file)
                    logger.success(f"Identified {result['technologies_identified']} technologies")
            except Exception as e:
                logger.warning(f"Technology identification failed: {e}")
        
        return result
    
    def _phase_network_discovery(self) -> Dict[str, Any]:
        """Network discovery phase: Port scanning and service detection"""
        result = {
            'success': True,
            'ports_open': 0,
            'services_identified': 0,
            'vulnerabilities_found': 0
        }
        
        # Nmap scan
        if 'nmap' in self.tool_manager.get_installed_tools():
            try:
                logger.info("Starting network discovery...")
                
                # Determine scan intensity
                intensity = self.config.intensity
                if intensity <= 3:
                    flags = '-sS -T2 --top-ports 100'
                elif intensity <= 6:
                    flags = '-sS -sV -T4 --top-ports 1000'
                else:
                    flags = '-sS -sV -sC -A -T4 -p-'
                
                output_file = self.config.output_directory / 'data' / 'nmap_scan.txt'
                context = {
                    'flags': flags,
                    'target': self.config.target.ip_address or self.config.target.domain,
                    'output': str(output_file)
                }
                
                logger.info("Running Nmap (this may take a while)...")
                success, output, duration = self.tool_manager.execute_tool('nmap', context)
                
                if success:
                    # Parse Nmap results
                    scan_results = self._parse_nmap_output(output)
                    result.update(scan_results)
                    
                    logger.success(f"Found {result['ports_open']} open ports")
                    
                    # Save detailed results
                    self._save_network_results(scan_results)
            except Exception as e:
                logger.error(f"Network discovery failed: {e}")
                result['success'] = False
        
        return result
    
    def _phase_web_assessment(self) -> Dict[str, Any]:
        """Web assessment phase: Directory enumeration and vulnerability scanning"""
        result = {
            'success': True,
            'directories_found': 0,
            'vulnerabilities_identified': 0,
            'security_headers': {},
            'ssl_issues': []
        }
        
        target_url = self.config.target.url
        if not target_url:
            logger.warning("No URL specified for web assessment")
            return result
        
        # Nikto scan
        if 'nikto' in self.tool_manager.get_installed_tools():
            try:
                logger.info("Running web vulnerability scan...")
                
                output_file = self.config.output_directory / 'data' / 'nikto_scan.txt'
                context = {
                    'target': target_url,
                    'output': str(output_file)
                }
                
                success, output, duration = self.tool_manager.execute_tool('nikto', context)
                
                if success:
                    vulnerabilities = self._parse_nikto_output(output)
                    result['vulnerabilities_identified'] = len(vulnerabilities)
                    
                    # Create findings from vulnerabilities
                    for vuln in vulnerabilities:
                        finding = Finding(
                            id=f"WEB-{hashlib.md5(vuln['description'].encode()).hexdigest()[:8]}",
                            title=vuln['title'],
                            description=vuln['description'],
                            severity=Severity.MEDIUM if 'OSVDB' in vuln.get('references', '') else Severity.LOW,
                            confidence=0.7,
                            location=target_url,
                            evidence=vuln.get('evidence', ''),
                            impact="Information disclosure or security misconfiguration",
                            remediation="Review and fix the identified issues",
                            references=vuln.get('references', [])
                        )
                        self.findings.append(finding)
                    
                    logger.success(f"Found {len(vulnerabilities)} potential vulnerabilities")
            except Exception as e:
                logger.warning(f"Nikto scan failed: {e}")
        
        # Directory enumeration
        if 'gobuster' in self.tool_manager.get_installed_tools() and self.config.enable_bruteforce:
            try:
                logger.info("Starting directory enumeration...")
                
                # Find wordlist
                wordlist = self._find_wordlist('directory')
                if not wordlist:
                    logger.warning("No directory wordlist found")
                    return result
                
                output_file = self.config.output_directory / 'data' / 'directory_scan.txt'
                context = {
                    'target': target_url,
                    'wordlist': wordlist,
                    'output': str(output_file)
                }
                
                success, output, duration = self.tool_manager.execute_tool('gobuster', context)
                
                if success:
                    directories = self._parse_directory_scan(output)
                    result['directories_found'] = len(directories)
                    
                    # Check for sensitive directories
                    sensitive_dirs = self._check_sensitive_directories(directories)
                    if sensitive_dirs:
                        finding = Finding(
                            id=f"DIR-{hashlib.md5(str(sensitive_dirs).encode()).hexdigest()[:8]}",
                            title="Sensitive Directories Exposed",
                            description=f"Found {len(sensitive_dirs)} sensitive directories accessible via web",
                            severity=Severity.MEDIUM,
                            confidence=0.9,
                            location=target_url,
                            evidence=str(sensitive_dirs),
                            impact="Potential information disclosure",
                            remediation="Restrict access to sensitive directories",
                            references=["OWASP: A5 Security Misconfiguration"]
                        )
                        self.findings.append(finding)
                    
                    logger.success(f"Found {len(directories)} directories")
            except Exception as e:
                logger.warning(f"Directory enumeration failed: {e}")
        
        # SSL/TLS assessment
        if 'sslscan' in self.tool_manager.get_installed_tools() and target_url.startswith('https://'):
            try:
                logger.info("Checking SSL/TLS configuration...")
                
                domain = self.config.target.domain
                if domain:
                    output_file = self.config.output_directory / 'data' / 'ssl_scan.txt'
                    context = {
                        'target': domain,
                        'output': str(output_file)
                    }
                    
                    success, output, duration = self.tool_manager.execute_tool('sslscan', context)
                    
                    if success:
                        ssl_issues = self._parse_sslscan_output(output)
                        result['ssl_issues'] = ssl_issues
                        
                        if ssl_issues:
                            finding = Finding(
                                id=f"SSL-{hashlib.md5(str(ssl_issues).encode()).hexdigest()[:8]}",
                                title="SSL/TLS Configuration Issues",
                                description=f"Found {len(ssl_issues)} SSL/TLS configuration issues",
                                severity=Severity.MEDIUM,
                                confidence=0.8,
                                location=target_url,
                                evidence=str(ssl_issues),
                                impact="Potential encryption weaknesses",
                                remediation="Update SSL/TLS configuration to follow best practices",
                                references=["Mozilla SSL Configuration Generator"]
                            )
                            self.findings.append(finding)
                        
                        logger.success(f"Found {len(ssl_issues)} SSL/TLS issues")
            except Exception as e:
                logger.warning(f"SSL scan failed: {e}")
        
        return result
    
    def _phase_vulnerability_scan(self) -> Dict[str, Any]:
        """Vulnerability scanning phase: Automated vulnerability detection"""
        result = {
            'success': True,
            'vulnerabilities_found': 0,
            'cvss_scores': [],
            'cwe_ids': []
        }
        
        # Nuclei scan (if available)
        if 'nuclei' in self.tool_manager.get_installed_tools():
            try:
                logger.info("Running template-based vulnerability scan...")
                
                output_file = self.config.output_directory / 'data' / 'nuclei_scan.txt'
                context = {
                    'target': self.config.target.url or self.config.target.domain,
                    'output': str(output_file)
                }
                
                success, output, duration = self.tool_manager.execute_tool('nuclei', context)
                
                if success:
                    vulnerabilities = self._parse_nuclei_output(output)
                    result['vulnerabilities_found'] = len(vulnerabilities)
                    
                    for vuln in vulnerabilities:
                        # Extract CVSS score if available
                        cvss_score = vuln.get('cvss_score')
                        if cvss_score:
                            result['cvss_scores'].append(float(cvss_score))
                        
                        # Extract CWE ID if available
                        cwe_id = vuln.get('cwe_id')
                        if cwe_id:
                            result['cwe_ids'].append(cwe_id)
                        
                        # Create finding
                        severity = self._cvss_to_severity(cvss_score) if cvss_score else Severity.MEDIUM
                        
                        finding = Finding(
                            id=f"VULN-{hashlib.md5(vuln['name'].encode()).hexdigest()[:8]}",
                            title=vuln['name'],
                            description=vuln.get('description', ''),
                            severity=severity,
                            confidence=0.8,
                            location=vuln.get('host', self.config.target.url),
                            evidence=vuln.get('matched_at', ''),
                            impact=vuln.get('impact', ''),
                            remediation=vuln.get('remediation', 'Apply security patches'),
                            references=vuln.get('references', []),
                            cwe_id=cwe_id,
                            cvss_score=cvss_score,
                            cvss_vector=vuln.get('cvss_vector')
                        )
                        self.findings.append(finding)
                    
                    logger.success(f"Found {len(vulnerabilities)} vulnerabilities")
            except Exception as e:
                logger.warning(f"Nuclei scan failed: {e}")
        
        return result
    
    def _phase_exploit_verification(self) -> Dict[str, Any]:
        """Exploit verification phase: Manual and automated exploit testing"""
        result = {
            'success': True,
            'exploits_tested': 0,
            'exploits_successful': 0,
            'proofs_of_concept': []
        }
        
        if not self.config.enable_exploitation:
            logger.info("Exploitation disabled in configuration")
            return result
        
        logger.warning("Exploitation phase requires careful consideration")
        logger.info("This phase is for authorized testing only")
        
        # Basic SQL injection testing
        if 'sqlmap' in self.tool_manager.get_installed_tools():
            try:
                logger.info("Testing for SQL injection vulnerabilities...")
                
                output_dir = self.config.output_directory / 'data' / 'sqlmap'
                output_dir.mkdir(parents=True, exist_ok=True)
                
                context = {
                    'target': self.config.target.url,
                    'output_dir': str(output_dir)
                }
                
                # Use conservative settings for safety
                success, output, duration = self.tool_manager.execute_tool('sqlmap', context)
                
                if success:
                    sqli_results = self._parse_sqlmap_output(output_dir)
                    result['exploits_tested'] += 1
                    
                    if sqli_results.get('vulnerable', False):
                        result['exploits_successful'] += 1
                        result['proofs_of_concept'].append({
                            'type': 'SQL Injection',
                            'location': sqli_results.get('location'),
                            'technique': sqli_results.get('technique')
                        })
                        
                        finding = Finding(
                            id=f"EXPLOIT-{hashlib.md5(str(sqli_results).encode()).hexdigest()[:8]}",
                            title="SQL Injection Vulnerability",
                            description="SQL injection vulnerability confirmed",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            location=sqli_results.get('location', self.config.target.url),
                            evidence=str(sqli_results),
                            impact="Potential database compromise",
                            remediation="Use parameterized queries and input validation",
                            references=["OWASP: SQL Injection"]
                        )
                        self.findings.append(finding)
            except Exception as e:
                logger.warning(f"SQL injection testing failed: {e}")
        
        return result
    
    def _phase_post_exploitation(self) -> Dict[str, Any]:
        """Post-exploitation phase: Data collection and analysis"""
        result = {
            'success': True,
            'data_collected': 0,
            'analysis_completed': False
        }
        
        logger.info("Performing post-exploitation analysis...")
        
        # Analyze collected data
        try:
            # Combine findings from all phases
            all_findings = self.findings.copy()
            
            # Perform risk assessment
            risk_assessment = self._assess_risk(all_findings)
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(all_findings, risk_assessment)
            
            # Save analysis results
            analysis_file = self.config.output_directory / 'reports' / 'analysis.json'
            analysis_data = {
                'risk_assessment': risk_assessment,
                'executive_summary': executive_summary,
                'total_findings': len(all_findings),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(analysis_file, 'w') as f:
                json.dump(analysis_data, f, indent=2)
            
            result['data_collected'] = len(all_findings)
            result['analysis_completed'] = True
            
            logger.success("Post-exploitation analysis completed")
            
        except Exception as e:
            logger.error(f"Post-exploitation analysis failed: {e}")
            result['success'] = False
        
        return result
    
    def _phase_reporting(self) -> Dict[str, Any]:
        """Reporting phase: Generate comprehensive reports"""
        result = {
            'success': True,
            'reports_generated': 0,
            'report_formats': []
        }
        
        logger.info("Generating reports...")
        
        try:
            report_generator = ReportGenerator(
                findings=self.findings,
                statistics=self.statistics,
                config=self.config,
                output_dir=self.config.output_directory / 'reports'
            )
            
            # Generate different report formats
            formats = [
                ('html', report_generator.generate_html_report),
                ('markdown', report_generator.generate_markdown_report),
                ('json', report_generator.generate_json_report),
                ('pdf', report_generator.generate_pdf_report),
                ('csv', report_generator.generate_csv_report)
            ]
            
            for format_name, generator_func in formats:
                try:
                    report_path = generator_func()
                    if report_path and report_path.exists():
                        result['reports_generated'] += 1
                        result['report_formats'].append(format_name)
                        logger.success(f"Generated {format_name.upper()} report")
                except Exception as e:
                    logger.warning(f"Failed to generate {format_name} report: {e}")
            
            # Generate executive dashboard
            try:
                dashboard_path = report_generator.generate_executive_dashboard()
                if dashboard_path:
                    logger.success(f"Generated executive dashboard: {dashboard_path}")
            except Exception as e:
                logger.warning(f"Failed to generate dashboard: {e}")
            
            logger.success(f"Generated {result['reports_generated']} reports")
            
        except Exception as e:
            logger.error(f"Reporting phase failed: {e}")
            result['success'] = False
        
        return result
    
    def _phase_cleanup(self) -> Dict[str, Any]:
        """Cleanup phase: Finalize and optimize output"""
        result = {
            'success': True,
            'files_cleaned': 0,
            'space_saved': 0
        }
        
        logger.info("Performing cleanup...")
        
        try:
            # Compress large files
            data_dir = self.config.output_directory / 'data'
            if data_dir.exists():
                for file in data_dir.glob('*.txt'):
                    if file.stat().st_size > 10 * 1024 * 1024:  # 10MB
                        # Compress with gzip
                        import gzip
                        with open(file, 'rb') as f_in:
                            with gzip.open(f'{file}.gz', 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        file.unlink()
                        result['files_cleaned'] += 1
                        result['space_saved'] += file.stat().st_size
            
            # Create final summary
            summary_file = self.config.output_directory / 'scan_summary.json'
            summary_data = {
                'scan_id': hashlib.md5(str(self.config).encode()).hexdigest()[:16],
                'config': asdict(self.config),
                'statistics': {
                    'duration': str(self.statistics.duration) if self.statistics.duration else None,
                    'tools_executed': self.statistics.tools_executed,
                    'findings_count': self.statistics.findings_count,
                    'success_rate': self.statistics.success_rate
                },
                'findings_summary': {
                    severity.name: count 
                    for severity, count in self.statistics.findings_by_severity.items()
                },
                'completion_time': datetime.now().isoformat(),
                'version': APP_VERSION
            }
            
            with open(summary_file, 'w') as f:
                json.dump(summary_data, f, indent=2)
            
            logger.success("Cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            result['success'] = False
        
        return result
    
    # Helper methods
    def _find_wordlist(self, category: str) -> Optional[str]:
        """Find wordlist file for given category"""
        wordlist_dir = self.config.wordlist_directory
        
        # Common wordlist locations
        locations = [
            wordlist_dir / f"{category}.txt",
            wordlist_dir / "common.txt",
            wordlist_dir / "directory-list-2.3-medium.txt",
            wordlist_dir / "big.txt"
        ]
        
        for location in locations:
            if location.exists():
                return str(location)
        
        return None
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap scan output"""
        result = {
            'ports_open': 0,
            'services': [],
            'os_guess': None,
            'vulnerabilities': []
        }
        
        # Simple parsing (in production, use nmap parser library)
        lines = output.split('\n')
        
        for line in lines:
            # Count open ports
            if '/tcp' in line and 'open' in line:
                result['ports_open'] += 1
                
                # Extract service info
                parts = line.split()
                if len(parts) >= 3:
                    service = {
                        'port': parts[0].split('/')[0],
                        'state': 'open',
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    result['services'].append(service)
            
            # OS detection
            elif 'OS details:' in line or 'OS guesses:' in line:
                result['os_guess'] = line.split(':', 1)[1].strip()
            
            # Script output (vulnerabilities)
            elif 'VULNERABLE:' in line:
                result['vulnerabilities'].append(line.split(':', 1)[1].strip())
        
        return result
    
    def _parse_nikto_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nikto scan output"""
        vulnerabilities = []
        
        lines = output.split('\n')
        current_vuln = {}
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('+'):
                # New vulnerability
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                
                parts = line[2:].split(':', 1)
                current_vuln = {
                    'title': parts[0].strip() if len(parts) > 0 else '',
                    'description': parts[1].strip() if len(parts) > 1 else '',
                    'evidence': '',
                    'references': []
                }
            elif line.startswith('|') and current_vuln:
                # Additional information
                key_value = line[2:].split(':', 1)
                if len(key_value) == 2:
                    key, value = key_value
                    key = key.strip().lower()
                    
                    if 'reference' in key:
                        current_vuln['references'].append(value.strip())
                    elif 'evidence' in key:
                        current_vuln['evidence'] = value.strip()
        
        # Add last vulnerability
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities
    
    def _parse_directory_scan(self, output: str) -> List[str]:
        """Parse directory enumeration output"""
        directories = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line and ('Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line):
                # Extract URL
                parts = line.split()
                if parts:
                    directories.append(parts[0])
        
        return directories
    
    def _check_sensitive_directories(self, directories: List[str]) -> List[str]:
        """Check for sensitive directories"""
        sensitive_keywords = [
            'admin', 'backup', 'config', 'database', 'sql', 'backup',
            '.git', '.env', 'wp-admin', 'phpinfo', 'test', 'debug',
            'upload', 'download', 'private', 'secret', 'password'
        ]
        
        sensitive = []
        for directory in directories:
            dir_lower = directory.lower()
            if any(keyword in dir_lower for keyword in sensitive_keywords):
                sensitive.append(directory)
        
        return sensitive
    
    def _parse_sslscan_output(self, output: str) -> List[str]:
        """Parse SSL/TLS scan results"""
        issues = []
        
        # Simple parsing for common issues
        if 'SSLv2' in output or 'SSLv3' in output:
            issues.append("Outdated SSL protocol enabled")
        
        if 'RC4' in output or 'DES' in output or '3DES' in output:
            issues.append("Weak cipher suites enabled")
        
        if 'self signed' in output.lower():
            issues.append("Self-signed certificate")
        
        if 'expired' in output.lower():
            issues.append("Expired certificate")
        
        if 'heartbleed' in output.lower():
            issues.append("Heartbleed vulnerability")
        
        return issues
    
    def _parse_nuclei_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nuclei scan output"""
        vulnerabilities = []
        
        try:
            # Nuclei outputs JSON lines
            for line in output.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        vuln = {
                            'name': data.get('template-id', 'Unknown'),
                            'description': data.get('info', {}).get('description', ''),
                            'severity': data.get('info', {}).get('severity', 'medium'),
                            'host': data.get('host', ''),
                            'matched_at': data.get('matched-at', ''),
                            'cvss_score': data.get('info', {}).get('classification', {}).get('cvss-score'),
                            'cvss_vector': data.get('info', {}).get('classification', {}).get('cvss-vector'),
                            'cwe_id': data.get('info', {}).get('classification', {}).get('cwe-id'),
                            'impact': data.get('info', {}).get('impact', ''),
                            'remediation': data.get('info', {}).get('remediation', ''),
                            'references': data.get('info', {}).get('reference', [])
                        }
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue
        except:
            pass
        
        return vulnerabilities
    
    def _parse_sqlmap_output(self, output_dir: Path) -> Dict[str, Any]:
        """Parse SQLMap results"""
        result = {
            'vulnerable': False,
            'location': '',
            'technique': ''
        }
        
        # Look for results files
        for file in output_dir.glob('*.txt'):
            with open(file, 'r') as f:
                content = f.read()
                
                if 'vulnerable' in content.lower():
                    result['vulnerable'] = True
                    
                    # Extract injection point
                    for line in content.split('\n'):
                        if 'Parameter:' in line:
                            result['location'] = line.split(':', 1)[1].strip()
                        elif 'Type:' in line:
                            result['technique'] = line.split(':', 1)[1].strip()
                    
                    break
        
        return result
    
    def _parse_technologies(self, xml_file: Path) -> int:
        """Parse WhatWeb XML output for technologies"""
        count = 0
        
        if BEAUTIFULSOUP_AVAILABLE and xml_file.exists():
            try:
                with open(xml_file, 'r') as f:
                    soup = BeautifulSoup(f.read(), 'xml')
                    plugins = soup.find_all('plugin')
                    count = len(plugins)
            except:
                pass
        
        return count
    
    def _save_network_results(self, results: Dict[str, Any]):
        """Save network discovery results"""
        output_file = self.config.output_directory / 'data' / 'network_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def _assess_risk(self, findings: List[Finding]) -> Dict[str, Any]:
        """Assess overall risk based on findings"""
        # Count findings by severity
        severity_counts = defaultdict(int)
        total_cvss = 0
        cvss_count = 0
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            
            if finding.cvss_score:
                total_cvss += finding.cvss_score
                cvss_count += 1
        
        # Calculate overall risk score
        risk_score = 0
        if findings:
            # Weighted average based on severity
            weights = {
                Severity.CRITICAL: 10,
                Severity.HIGH: 7,
                Severity.MEDIUM: 4,
                Severity.LOW: 2,
                Severity.INFO: 1
            }
            
            weighted_sum = sum(weights[sev] * count for sev, count in severity_counts.items())
            total_findings = sum(severity_counts.values())
            risk_score = min(100, weighted_sum * 10 / total_findings if total_findings > 0 else 0)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'severity_distribution': {k.name: v for k, v in severity_counts.items()},
            'average_cvss': round(total_cvss / cvss_count, 2) if cvss_count > 0 else None,
            'total_findings': len(findings)
        }
    
    def _generate_executive_summary(self, findings: List[Finding], 
                                  risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        # Get top critical/high findings
        critical_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        top_findings = critical_findings[:5] if critical_findings else findings[:3]
        
        summary = {
            'target': self.config.target.display_name,
            'scan_mode': self.config.mode.name,
            'risk_assessment': risk_assessment,
            'key_findings': [
                {
                    'title': f.title,
                    'severity': f.severity.name,
                    'description': f.description[:200] + '...' if len(f.description) > 200 else f.description
                }
                for f in top_findings
            ],
            'recommendations': [
                "Address critical vulnerabilities immediately",
                "Implement security monitoring",
                "Schedule regular security assessments",
                "Provide security awareness training"
            ],
            'generated': datetime.now().isoformat()
        }
        
        return summary
    
    def _cvss_to_severity(self, cvss_score: float) -> Severity:
        """Convert CVSS score to Severity enum"""
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        elif cvss_score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFO

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """
    Generates comprehensive reports in multiple formats.
    Creates professional, well-formatted reports suitable for different audiences.
    """
    
    def __init__(self, findings: List[Finding], statistics: ScanStatistics,
                 config: ScanConfiguration, output_dir: Path):
        self.findings = findings
        self.statistics = statistics
        self.config = config
        self.output_dir = output_dir
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_html_report(self) -> Optional[Path]:
        """Generate HTML report"""
        try:
            report_file = self.output_dir / 'report.html'
            
            # Group findings by severity
            findings_by_severity = defaultdict(list)
            for finding in self.findings:
                findings_by_severity[finding.severity].append(finding)
            
            # Sort findings by severity priority
            sorted_severities = sorted(
                findings_by_severity.keys(),
                key=lambda s: s.priority
            )
            
            html_content = self._generate_html_template(
                findings_by_severity,
                sorted_severities
            )
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return None
    
    def _generate_html_template(self, findings_by_severity: Dict[Severity, List[Finding]],
                              sorted_severities: List[Severity]) -> str:
        """Generate HTML report template"""
        
        # Statistics
        duration = self.statistics.duration
        duration_str = str(duration) if duration else "N/A"
        
        # Findings count by severity
        severity_counts = {
            severity.name: len(findings)
            for severity, findings in findings_by_severity.items()
        }
        
        # Generate HTML
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCROLL Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.98);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
        }}
        .header {{ 
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 30px;
            border-bottom: 3px solid #3498db;
        }}
        .header h1 {{ 
            color: #2c3e50;
            font-size: 2.8em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #3498db, #2c3e50);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header p {{ 
            color: #7f8c8d;
            font-size: 1.2em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-top: 5px solid #3498db;
        }}
        .stat-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.12);
        }}
        .stat-card.critical {{ border-top-color: #e74c3c; }}
        .stat-card.high {{ border-top-color: #e67e22; }}
        .stat-card.medium {{ border-top-color: #f1c40f; }}
        .stat-card.low {{ border-top-color: #27ae60; }}
        .stat-card.info {{ border-top-color: #3498db; }}
        .stat-card h3 {{ 
            font-size: 1em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #7f8c8d;
            margin-bottom: 10px;
        }}
        .stat-card .count {{ 
            font-size: 3em;
            font-weight: 800;
            margin: 15px 0;
        }}
        .stat-card.critical .count {{ color: #e74c3c; }}
        .stat-card.high .count {{ color: #e67e22; }}
        .stat-card.medium .count {{ color: #f1c40f; }}
        .stat-card.low .count {{ color: #27ae60; }}
        .stat-card.info .count {{ color: #3498db; }}
        .section {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.08);
        }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }}
        .finding {{
            border-left: 5px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            background: #f8f9fa;
            border-radius: 0 10px 10px 0;
            transition: all 0.3s ease;
        }}
        .finding:hover {{
            background: #edf2f7;
            transform: translateX(5px);
        }}
        .finding.critical {{ border-left-color: #e74c3c; background: #fff5f5; }}
        .finding.high {{ border-left-color: #e67e22; background: #fffaf0; }}
        .finding.medium {{ border-left-color: #f1c40f; background: #fffff0; }}
        .finding.low {{ border-left-color: #27ae60; background: #f0fff4; }}
        .finding.info {{ border-left-color: #3498db; background: #f0f8ff; }}
        .finding h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .finding.critical .severity {{ background: #e74c3c; color: white; }}
        .finding.high .severity {{ background: #e67e22; color: white; }}
        .finding.medium .severity {{ background: #f1c40f; color: #333; }}
        .finding.low .severity {{ background: #27ae60; color: white; }}
        .finding.info .severity {{ background: #3498db; color: white; }}
        .finding .details {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
        }}
        .finding .details p {{
            margin: 8px 0;
            color: #4a5568;
        }}
        .finding .details strong {{
            color: #2d3748;
        }}
        .risk-meter {{
            height: 25px;
            background: linear-gradient(to right, #27ae60, #f1c40f, #e67e22, #e74c3c);
            border-radius: 12px;
            margin: 20px 0;
            position: relative;
            overflow: hidden;
        }}
        .risk-indicator {{
            position: absolute;
            top: 0;
            bottom: 0;
            width: 6px;
            background: #2c3e50;
            transform: translateX(-50%);
            border-radius: 3px;
        }}
        .risk-labels {{
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.9em;
            color: #718096;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #ecf0f1;
            color: #718096;
            font-size: 0.9em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 20px; }}
            .header h1 {{ font-size: 2em; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 SCROLL Security Assessment Report</h1>
            <p>Target: {html.escape(self.config.target.display_name)} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        
        <!-- Statistics Grid -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="count">{severity_counts.get('CRITICAL', 0)}</div>
                <p>Immediate attention required</p>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="count">{severity_counts.get('HIGH', 0)}</div>
                <p>Address as soon as possible</p>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="count">{severity_counts.get('MEDIUM', 0)}</div>
                <p>Schedule for remediation</p>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="count">{severity_counts.get('LOW', 0)}</div>
                <p>Consider for future updates</p>
            </div>
            <div class="stat-card info">
                <h3>Info</h3>
                <div class="count">{severity_counts.get('INFO', 0)}</div>
                <p>Informational findings</p>
            </div>
        </div>
        
        <!-- Scan Summary -->
        <div class="section">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Target Information</h3>
                    <p><strong>URL:</strong> {html.escape(self.config.target.url or 'N/A')}</p>
                    <p><strong>Domain:</strong> {html.escape(self.config.target.domain or 'N/A')}</p>
                    <p><strong>IP:</strong> {html.escape(self.config.target.ip_address or 'N/A')}</p>
                </div>
                <div class="summary-card">
                    <h3>Scan Details</h3>
                    <p><strong>Mode:</strong> {self.config.mode.name}</p>
                    <p><strong>Duration:</strong> {duration_str}</p>
                    <p><strong>Tools Executed:</strong> {self.statistics.tools_executed}</p>
                </div>
                <div class="summary-card">
                    <h3>Risk Overview</h3>
                    <p><strong>Total Findings:</strong> {len(self.findings)}</p>
                    <p><strong>Success Rate:</strong> {self.statistics.success_rate:.1f}%</p>
                </div>
            </div>
        </div>
        
        <!-- Findings by Severity -->
        {"".join([
            self._generate_severity_section(severity, findings)
            for severity in sorted_severities
            if findings_by_severity[severity]
        ])}
        
        <!-- Risk Assessment -->
        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <div class="risk-meter">
                <div class="risk-indicator" style="left: 50%;"></div>
            </div>
            <div class="risk-labels">
                <span>Low</span>
                <span>Medium</span>
                <span>High</span>
                <span>Critical</span>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <h2>🚀 Recommendations</h2>
            <div class="finding info">
                <h3>Immediate Actions</h3>
                <div class="details">
                    <p>1. Address all critical findings within 24 hours</p>
                    <p>2. Implement emergency security patches</p>
                    <p>3. Disable vulnerable services temporarily</p>
                </div>
            </div>
            <div class="finding info">
                <h3>Short-term Actions (7 days)</h3>
                <div class="details">
                    <p>1. Fix high severity vulnerabilities</p>
                    <p>2. Implement security monitoring</p>
                    <p>3. Conduct security awareness training</p>
                </div>
            </div>
            <div class="finding info">
                <h3>Long-term Strategy</h3>
                <div class="details">
                    <p>1. Establish security development lifecycle</p>
                    <p>2. Implement continuous security testing</p>
                    <p>3. Schedule regular security assessments</p>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by {APP_NAME} v{APP_VERSION} - Professional Security Assessment Platform</p>
            <p>For authorized testing only. Unauthorized use is prohibited.</p>
            <p>Report ID: {hashlib.md5(str(datetime.now()).encode()).hexdigest()[:16]}</p>
        </div>
    </div>
    
    <script>
        // Create severity distribution chart
        const ctx = document.createElement('canvas');
        ctx.style.width = '100%';
        ctx.style.height = '300px';
        ctx.style.marginTop = '30px';
        document.querySelector('.section:nth-child(3)').appendChild(ctx);
        
        const severityData = {json.dumps(severity_counts)};
        
        new Chart(ctx, {{
            type: 'pie',
            data: {{
                labels: Object.keys(severityData),
                datasets: [{{
                    data: Object.values(severityData),
                    backgroundColor: [
                        '#e74c3c',
                        '#e67e22',
                        '#f1c40f',
                        '#27ae60',
                        '#3498db'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }},
                    title: {{
                        display: true,
                        text: 'Findings Distribution by Severity'
                    }}
                }}
            }}
        }});
        
        // Risk indicator positioning
        const totalFindings = {len(self.findings)};
        const criticalFindings = severityData.CRITICAL || 0;
        const riskPercentage = totalFindings > 0 ? (criticalFindings / totalFindings) * 100 : 0;
        const riskIndicator = document.querySelector('.risk-indicator');
        
        // Position based on risk
        let position = 25; // Default to low
        if (riskPercentage > 30) position = 75;
        else if (riskPercentage > 15) position = 50;
        else if (riskPercentage > 5) position = 25;
        
        riskIndicator.style.left = `${{position}}%`;
    </script>
</body>
</html>
"""
    
    def _generate_severity_section(self, severity: Severity, findings: List[Finding]) -> str:
        """Generate HTML section for a severity level"""
        severity_name = severity.name
        severity_class = severity.name.lower()
        
        findings_html = ""
        for finding in findings:
            findings_html += f"""
            <div class="finding {severity_class}">
                <h3>
                    <span class="severity">{severity_name}</span>
                    {html.escape(finding.title)}
                </h3>
                <p>{html.escape(finding.description)}</p>
                <div class="details">
                    <p><strong>Location:</strong> {html.escape(finding.location)}</p>
                    <p><strong>Impact:</strong> {html.escape(finding.impact)}</p>
                    <p><strong>Remediation:</strong> {html.escape(finding.remediation)}</p>
                    {f'<p><strong>CVSS Score:</strong> {finding.cvss_score}</p>' if finding.cvss_score else ''}
                    {f'<p><strong>CWE:</strong> {finding.cwe_id}</p>' if finding.cwe_id else ''}
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>{severity_name} Severity Findings ({len(findings)})</h2>
            {findings_html}
        </div>
        """
    
    def generate_markdown_report(self) -> Optional[Path]:
        """Generate Markdown report"""
        try:
            report_file = self.output_dir / 'report.md'
            
            with open(report_file, 'w', encoding='utf-8') as f:
                # Header
                f.write(f"# SCROLL Security Assessment Report\n\n")
                f.write(f"**Target:** {self.config.target.display_name}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Scan Mode:** {self.config.mode.name}\n\n")
                
                # Summary
                f.write("## Executive Summary\n\n")
                
                # Statistics
                duration = self.statistics.duration
                duration_str = str(duration) if duration else "N/A"
                
                f.write("### Scan Statistics\n")
                f.write(f"- Duration: {duration_str}\n")
                f.write(f"- Tools Executed: {self.statistics.tools_executed}\n")
                f.write(f"- Success Rate: {self.statistics.success_rate:.1f}%\n")
                f.write(f"- Total Findings: {len(self.findings)}\n\n")
                
                # Findings by severity
                severity_counts = defaultdict(int)
                for finding in self.findings:
                    severity_counts[finding.severity] += 1
                
                f.write("### Findings Summary\n")
                for severity in Severity:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        f.write(f"- **{severity.name}**: {count}\n")
                f.write("\n")
                
                # Detailed findings
                f.write("## Detailed Findings\n\n")
                
                for severity in Severity:
                    severity_findings = [f for f in self.findings if f.severity == severity]
                    if severity_findings:
                        f.write(f"### {severity.name} Severity\n\n")
                        
                        for i, finding in enumerate(severity_findings, 1):
                            f.write(f"#### {i}. {finding.title}\n")
                            f.write(f"- **Description**: {finding.description}\n")
                            f.write(f"- **Location**: {finding.location}\n")
                            f.write(f"- **Impact**: {finding.impact}\n")
                            f.write(f"- **Remediation**: {finding.remediation}\n")
                            if finding.cvss_score:
                                f.write(f"- **CVSS Score**: {finding.cvss_score}\n")
                            if finding.cwe_id:
                                f.write(f"- **CWE ID**: {finding.cwe_id}\n")
                            f.write("\n")
                
                # Recommendations
                f.write("## Recommendations\n\n")
                f.write("1. **Immediate Action** (Critical/High findings within 24h)\n")
                f.write("2. **Short-term Fixes** (Medium findings within 7 days)\n")
                f.write("3. **Long-term Improvements** (Low/Info findings in next sprint)\n")
                f.write("4. **Continuous Security Testing** implementation\n\n")
                
                # Footer
                f.write("---\n")
                f.write(f"*Generated by {APP_NAME} v{APP_VERSION}*\n")
                f.write("*For authorized testing only*\n")
            
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            return None
    
    def generate_json_report(self) -> Optional[Path]:
        """Generate JSON report"""
        try:
            report_file = self.output_dir / 'report.json'
            
            report_data = {
                'metadata': {
                    'tool': APP_NAME,
                    'version': APP_VERSION,
                    'generated': datetime.now().isoformat(),
                    'target': asdict(self.config.target)
                },
                'statistics': {
                    'duration': str(self.statistics.duration) if self.statistics.duration else None,
                    'tools_executed': self.statistics.tools_executed,
                    'tools_failed': self.statistics.tools_failed,
                    'success_rate': self.statistics.success_rate,
                    'findings_count': len(self.findings)
                },
                'findings': [finding.to_dict() for finding in self.findings],
                'scan_configuration': asdict(self.config)
            }
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return None
    
    def generate_pdf_report(self) -> Optional[Path]:
        """Generate PDF report"""
        try:
            # Check if we can generate PDF
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.lib import colors
                from reportlab.lib.units import inch
                PDF_AVAILABLE = True
            except ImportError:
                PDF_AVAILABLE = False
                logger.warning("ReportLab not installed. PDF generation disabled.")
                return None
            
            if not PDF_AVAILABLE:
                return None
            
            report_file = self.output_dir / 'report.pdf'
            
            # Create PDF
            doc = SimpleDocTemplate(
                str(report_file),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = styles['Heading1']
            title_style.alignment = 1  # Center
            story.append(Paragraph("SCROLL Security Assessment Report", title_style))
            story.append(Spacer(1, 12))
            
            # Subtitle
            subtitle_style = styles['Normal']
            subtitle_style.alignment = 1
            story.append(Paragraph(f"Target: {self.config.target.display_name}", subtitle_style))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", subtitle_style))
            story.append(Spacer(1, 24))
            
            # Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            # Statistics table
            data = [
                ['Metric', 'Value'],
                ['Duration', str(self.statistics.duration) if self.statistics.duration else 'N/A'],
                ['Tools Executed', str(self.statistics.tools_executed)],
                ['Success Rate', f"{self.statistics.success_rate:.1f}%"],
                ['Total Findings', str(len(self.findings))]
            ]
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 24))
            
            # Findings summary
            severity_counts = defaultdict(int)
            for finding in self.findings:
                severity_counts[finding.severity] += 1
            
            story.append(Paragraph("Findings Summary", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            for severity in Severity:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    story.append(Paragraph(f"{severity.name}: {count}", styles['Normal']))
            
            story.append(Spacer(1, 24))
            
            # Detailed findings
            story.append(Paragraph("Detailed Findings", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            for severity in Severity:
                severity_findings = [f for f in self.findings if f.severity == severity]
                if severity_findings:
                    story.append(Paragraph(f"{severity.name} Severity Findings", styles['Heading3']))
                    
                    for i, finding in enumerate(severity_findings[:10], 1):  # Limit to 10 per severity
                        story.append(Paragraph(f"{i}. {finding.title}", styles['Normal']))
                        story.append(Spacer(1, 6))
            
            # Build PDF
            doc.build(story)
            
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return None
    
    def generate_csv_report(self) -> Optional[Path]:
        """Generate CSV report"""
        try:
            report_file = self.output_dir / 'report.csv'
            
            with open(report_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'ID', 'Title', 'Description', 'Severity', 'Confidence',
                    'Location', 'Impact', 'Remediation', 'CVSS Score',
                    'CWE ID', 'References', 'Timestamp'
                ])
                
                # Write findings
                for finding in self.findings:
                    writer.writerow([
                        finding.id,
                        finding.title,
                        finding.description,
                        finding.severity.name,
                        finding.confidence,
                        finding.location,
                        finding.impact,
                        finding.remediation,
                        finding.cvss_score or '',
                        finding.cwe_id or '',
                        ';'.join(finding.references),
                        finding.timestamp.isoformat()
                    ])
            
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return None
    
    def generate_executive_dashboard(self) -> Optional[Path]:
        """Generate interactive executive dashboard"""
        try:
            dashboard_file = self.output_dir / 'dashboard.html'
            
            # This would be a more sophisticated dashboard
            # For now, we'll use the HTML report as dashboard
            html_report = self.generate_html_report()
            if html_report:
                shutil.copy(html_report, dashboard_file)
                return dashboard_file
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to generate dashboard: {e}")
            return None

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class ScrollApplication:
    """
    Main application class for SCROLL.
    Orchestrates the entire security assessment workflow.
    """
    
    def __init__(self):
        self.ui = UserInterface()
        self.config = None
        self.scan_engine = None
        self.running = False
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals"""
        logger.warning(f"Received signal {signum}. Shutting down...")
        self.stop()
    
    def run(self):
        """Main application entry point"""
        try:
            self.running = True
            
            # Check Python version
            self._check_python_version()
            
            # Check dependencies
            self._check_dependencies()
            
            # Display banner
            self.ui.display_banner()
            
            # Welcome message
            self._show_welcome_message()
            
            # Main menu
            while self.running:
                choice = self._show_main_menu()
                
                if choice == '1':
                    self._run_new_scan()
                elif choice == '2':
                    self._load_session()
                elif choice == '3':
                    self._show_settings()
                elif choice == '4':
                    self._show_about()
                elif choice == '5':
                    self._exit_application()
                else:
                    logger.error("Invalid selection")
        
        except KeyboardInterrupt:
            logger.warning("\n\nApplication interrupted by user")
            self.stop()
        except Exception as e:
            logger.critical(f"Application error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def _check_python_version(self):
        """Check Python version requirements"""
        current_version = sys.version_info
        if current_version < MIN_PYTHON_VERSION:
            logger.critical(f"Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}+ required")
            sys.exit(1)
        
        if current_version < RECOMMENDED_PYTHON_VERSION:
            logger.warning(f"Python {RECOMMENDED_PYTHON_VERSION[0]}.{RECOMMENDED_PYTHON_VERSION[1]}+ recommended")
    
    def _check_dependencies(self):
        """Check for required dependencies"""
        missing = []
        
        if not REQUESTS_AVAILABLE:
            missing.append("requests")
        
        if missing:
            logger.warning(f"Missing dependencies: {', '.join(missing)}")
            logger.info("Install with: pip install " + " ".join(missing))
    
    def _show_welcome_message(self):
        """Display welcome message"""
        self.ui.display_header("Welcome to SCROLL", "Ultimate Security Assessment Platform")
        
        print(f"{Fore.GREEN}🚀 Ready to perform professional security assessments{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Remember: Only test systems you own or have explicit permission to test{Style.RESET_ALL}")
        print()
    
    def _show_main_menu(self) -> str:
        """Display main menu"""
        options = [
            ("1", "New Security Assessment", "Perform a new scan"),
            ("2", "Load Session", "Resume a previous scan"),
            ("3", "Settings", "Configure SCROLL"),
            ("4", "About", "Show version and information"),
            ("5", "Exit", "Quit the application")
        ]
        
        print(f"{Fore.CYAN}Main Menu{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 40}{Style.RESET_ALL}")
        
        for key, title, description in options:
            print(f"  {Fore.GREEN}[{key}]{Style.RESET_ALL} {Fore.CYAN}{title:25}{Style.RESET_ALL} - {description}")
        
        print()
        
        while True:
            choice = input(f"{Fore.YELLOW}Select option (1-5): {Style.RESET_ALL}").strip()
            if choice in ['1', '2', '3', '4', '5']:
                return choice
            logger.error("Invalid selection. Please enter 1-5.")
    
    def _run_new_scan(self):
        """Run a new security assessment"""
        try:
            # Step 1: Select scan mode
            scan_mode = self._select_scan_mode()
            if not scan_mode:
                return
            
            # Step 2: Configure target
            target = self._configure_target()
            if not target:
                return
            
            # Step 3: Configure scan parameters
            config = self._configure_scan(scan_mode, target)
            if not config:
                return
            
            # Step 4: Ethical agreement
            if not self._ethical_agreement(target):
                return
            
            # Step 5: Final confirmation
            if not self._confirm_scan(config):
                return
            
            # Step 6: Run scan
            self._execute_scan(config)
            
        except Exception as e:
            logger.error(f"Scan setup failed: {e}")
    
    def _select_scan_mode(self) -> Optional[ScanMode]:
        """Select scan mode"""
        self.ui.display_header("Scan Mode Selection", "Choose the type of assessment")
        
        modes = [
            ("1", "RECONNAISSANCE", ScanMode.RECONNAISSANCE),
            ("2", "STEALTH", ScanMode.STEALTH),
            ("3", "STANDARD", ScanMode.STANDARD),
            ("4", "AGGRESSIVE", ScanMode.AGGRESSIVE),
            ("5", "COMPREHENSIVE", ScanMode.COMPREHENSIVE),
            ("6", "PENETRATION", ScanMode.PENETRATION),
            ("7", "CUSTOM", ScanMode.CUSTOM)
        ]
        
        for key, name, mode in modes:
            print(f"  {Fore.GREEN}[{key}]{Style.RESET_ALL} {Fore.CYAN}{name:20}{Style.RESET_ALL}")
            print(f"     {mode.description()}")
            print()
        
        while True:
            choice = input(f"{Fore.YELLOW}Select mode (1-7): {Style.RESET_ALL}").strip()
            
            if choice == '0':
                return None
            
            for key, name, mode in modes:
                if choice == key:
                    logger.info(f"Selected: {name}")
                    return mode
            
            logger.error("Invalid selection. Please enter 1-7 or 0 to cancel.")
    
    def _configure_target(self) -> Optional[ScanTarget]:
        """Configure target information"""
        self.ui.display_header("Target Configuration", "Specify the target to assess")
        
        target = ScanTarget()
        
        # Get target URL
        while True:
            url = input(f"{Fore.YELLOW}Target URL (http:// or https://): {Style.RESET_ALL}").strip()
            
            if not url:
                logger.error("URL is required")
                continue
            
            if url.lower() == 'back':
                return None
            
            # Validate URL
            try:
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    logger.error("Invalid URL format. Include http:// or https://")
                    continue
                
                target.url = url
                target.domain = parsed.netloc
                
                # Try to resolve IP
                try:
                    target.ip_address = socket.gethostbyname(parsed.netloc)
                    logger.success(f"Resolved IP: {target.ip_address}")
                except:
                    logger.warning("Could not resolve IP address")
                    target.ip_address = None
                
                break
            except Exception as e:
                logger.error(f"Invalid URL: {e}")
        
        # Get additional configuration
        ports_input = input(f"{Fore.YELLOW}Specific ports (comma-separated, blank for all): {Style.RESET_ALL}").strip()
        if ports_input:
            try:
                target.ports = [int(p.strip()) for p in ports_input.split(',')]
            except:
                logger.warning("Invalid port list. Using all ports.")
        
        scope_input = input(f"{Fore.YELLOW}Scope/exclusions file (optional): {Style.RESET_ALL}").strip()
        if scope_input and os.path.exists(scope_input):
            target.scope = scope_input
        
        return target
    
    def _configure_scan(self, scan_mode: ScanMode, target: ScanTarget) -> Optional[ScanConfiguration]:
        """Configure scan parameters"""
        self.ui.display_header("Scan Configuration", "Configure assessment parameters")
        
        # Output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = target.domain or 'unknown'
        default_output = DEFAULT_OUTPUT_DIR / f"SCROLL_{domain}_{timestamp}"
        
        output_dir = input(f"{Fore.YELLOW}Output directory [{default_output}]: {Style.RESET_ALL}").strip()
        if not output_dir:
            output_dir = default_output
        
        # Wordlist directory
        wordlist_dir = input(f"{Fore.YELLOW}Wordlist directory [{DEFAULT_WORDLIST_DIR}]: {Style.RESET_ALL}").strip()
        if not wordlist_dir:
            wordlist_dir = DEFAULT_WORDLIST_DIR
        
        # Intensity
        intensity = 5  # Default
        if scan_mode == ScanMode.RECONNAISSANCE:
            intensity = 2
        elif scan_mode == ScanMode.STEALTH:
            intensity = 3
        elif scan_mode == ScanMode.STANDARD:
            intensity = 5
        elif scan_mode == ScanMode.AGGRESSIVE:
            intensity = 7
        elif scan_mode == ScanMode.COMPREHENSIVE:
            intensity = 9
        elif scan_mode == ScanMode.PENETRATION:
            intensity = 10
        
        intensity_input = input(f"{Fore.YELLOW}Scan intensity (1-10) [{intensity}]: {Style.RESET_ALL}").strip()
        if intensity_input:
            try:
                intensity = max(1, min(10, int(intensity_input)))
            except:
                logger.warning(f"Invalid intensity. Using {intensity}")
        
        # Concurrent tools
        concurrent_tools = MAX_CONCURRENT_TOOLS
        concurrent_input = input(f"{Fore.YELLOW}Max concurrent tools [{concurrent_tools}]: {Style.RESET_ALL}").strip()
        if concurrent_input:
            try:
                concurrent_tools = max(1, min(10, int(concurrent_input)))
            except:
                logger.warning(f"Invalid value. Using {concurrent_tools}")
        
        # Features
        enable_bruteforce = scan_mode in [ScanMode.AGGRESSIVE, ScanMode.COMPREHENSIVE, ScanMode.PENETRATION]
        bruteforce_input = input(f"{Fore.YELLOW}Enable bruteforce? (Y/n) [{'Y' if enable_bruteforce else 'N'}]: {Style.RESET_ALL}").strip().lower()
        if bruteforce_input:
            enable_bruteforce = bruteforce_input in ['y', 'yes']
        
        enable_exploitation = scan_mode == ScanMode.PENETRATION
        exploitation_input = input(f"{Fore.YELLOW}Enable exploitation? (y/N) [{'Y' if enable_exploitation else 'N'}]: {Style.RESET_ALL}").strip().lower()
        if exploitation_input:
            enable_exploitation = exploitation_input in ['y', 'yes']
        
        # Create configuration
        config = ScanConfiguration(
            mode=scan_mode,
            target=target,
            output_directory=Path(output_dir),
            wordlist_directory=Path(wordlist_dir),
            intensity=intensity,
            max_concurrent_tools=concurrent_tools,
            enable_bruteforce=enable_bruteforce,
            enable_exploitation=enable_exploitation,
            save_session=True,
            generate_reports=True
        )
        
        # Validate configuration
        errors = config.validate()
        if errors:
            logger.error("Configuration errors:")
            for error in errors:
                logger.error(f"  - {error}")
            return None
        
        return config
    
    def _ethical_agreement(self, target: ScanTarget) -> bool:
        """Display and confirm ethical agreement"""
        self.ui.display_header("Ethical Agreement", "Legal and ethical compliance")
        
        print(f"{Fore.RED}IMPORTANT: YOU MUST HAVE EXPLICIT AUTHORIZATION{Style.RESET_ALL}")
        print()
        print(f"Target: {target.display_name}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        print()
        print("By proceeding, you confirm that:")
        print("1. You have written permission to test this target")
        print("2. You will stay within authorized scope")
        print("3. You will report findings responsibly")
        print("4. You understand unauthorized testing is illegal")
        print()
        
        confirm = input(f"{Fore.RED}Type 'AUTHORIZED' to confirm: {Style.RESET_ALL}").strip()
        
        if confirm != "AUTHORIZED":
            logger.error("Authorization not confirmed")
            return False
        
        # Get tester information
        print()
        print(f"{Fore.CYAN}Tester Information{Style.RESET_ALL}")
        name = input(f"{Fore.YELLOW}Your name: {Style.RESET_ALL}").strip()
        organization = input(f"{Fore.YELLOW}Organization: {Style.RESET_ALL}").strip()
        reference = input(f"{Fore.YELLOW}Authorization reference: {Style.RESET_ALL}").strip()
        
        if not name or not reference:
            logger.warning("Incomplete tester information")
        
        logger.success("Ethical agreement confirmed")
        return True
    
    def _confirm_scan(self, config: ScanConfiguration) -> bool:
        """Show final confirmation before scan"""
        self.ui.display_header("Ready to Scan", "Final confirmation")
        
        print(f"{Fore.CYAN}Scan Configuration:{Style.RESET_ALL}")
        print(f"  Target: {config.target.display_name}")
        print(f"  Mode: {config.mode.name}")
        print(f"  Intensity: {config.intensity}/10")
        print(f"  Output: {config.output_directory}")
        print(f"  Concurrent Tools: {config.max_concurrent_tools}")
        print(f"  Bruteforce: {'Enabled' if config.enable_bruteforce else 'Disabled'}")
        print(f"  Exploitation: {'Enabled' if config.enable_exploitation else 'Disabled'}")
        print()
        print(f"{Fore.YELLOW}Note:{Style.RESET_ALL} Tools will run to completion with no timeouts.")
        print(f"      Press Ctrl+C to pause or stop the scan.")
        print()
        
        confirm = input(f"{Fore.GREEN}Start scan? (Y/n): {Style.RESET_ALL}").strip().lower()
        
        return confirm in ['', 'y', 'yes']
    
    def _execute_scan(self, config: ScanConfiguration):
        """Execute the scan"""
        try:
            # Create scan engine
            self.scan_engine = ScanEngine(config)
            
            # Run scan
            logger.info("Starting security assessment...")
            self.scan_engine.run()
            
            # Show completion message
            self._show_scan_completion()
            
        except Exception as e:
            logger.critical(f"Scan execution failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _show_scan_completion(self):
        """Show scan completion summary"""
        if not self.scan_engine:
            return
        
        self.ui.display_header("Assessment Complete", "Results and next steps")
        
        stats = self.scan_engine.statistics
        findings = self.scan_engine.findings
        
        # Statistics
        print(f"{Fore.CYAN}📊 Scan Statistics:{Style.RESET_ALL}")
        print(f"  Duration: {stats.duration}")
        print(f"  Tools Executed: {stats.tools_executed}")
        print(f"  Success Rate: {stats.success_rate:.1f}%")
        print(f"  Total Findings: {len(findings)}")
        print()
        
        # Findings by severity
        print(f"{Fore.CYAN}📋 Findings Summary:{Style.RESET_ALL}")
        for severity in Severity:
            count = stats.findings_by_severity.get(severity, 0)
            if count > 0:
                print(f"  {severity.color}{severity.name}: {count}{Style.RESET_ALL}")
        print()
        
        # Output location
        output_dir = self.scan_engine.config.output_directory
        print(f"{Fore.CYAN}📁 Output Directory:{Style.RESET_ALL}")
        print(f"  {output_dir}")
        print()
        
        # Generated reports
        reports_dir = output_dir / 'reports'
        if reports_dir.exists():
            print(f"{Fore.CYAN}📄 Generated Reports:{Style.RESET_ALL}")
            for report in sorted(reports_dir.glob('*')):
                print(f"  • {report.name}")
            print()
        
        # Next steps
        print(f"{Fore.YELLOW}🚀 Next Steps:{Style.RESET_ALL}")
        print("  1. Review the HTML dashboard for overview")
        print("  2. Check executive summary for management")
        print("  3. Implement remediation plan")
        print("  4. Schedule follow-up assessment")
        print()
        
        # Dashboard path
        dashboard = reports_dir / 'dashboard.html'
        if dashboard.exists():
            print(f"{Fore.GREEN}💡 Open dashboard with:{Style.RESET_ALL}")
            print(f"  open '{dashboard}'")
            print()
    
    def _load_session(self):
        """Load a previous scan session"""
        logger.info("Session loading not implemented in this version")
        # TODO: Implement session loading
    
    def _show_settings(self):
        """Show application settings"""
        logger.info("Settings not implemented in this version")
        # TODO: Implement settings
    
    def _show_about(self):
        """Show about information"""
        self.ui.display_header("About SCROLL", "Ultimate Security Assessment Platform")
        
        print(f"{Fore.CYAN}Version:{Style.RESET_ALL} {APP_VERSION}")
        print(f"{Fore.CYAN}Author:{Style.RESET_ALL} {APP_AUTHOR}")
        print(f"{Fore.CYAN}License:{Style.RESET_ALL} {APP_LICENSE}")
        print(f"{Fore.CYAN}Description:{Style.RESET_ALL} {APP_DESCRIPTION}")
        print()
        print(f"{Fore.YELLOW}Key Features:{Style.RESET_ALL}")
        print("  • Zero-timeout tool execution")
        print("  • Interactive workflow with pause/resume")
        print("  • Multi-format professional reporting")
        print("  • Modular, extensible architecture")
        print("  • Comprehensive vulnerability assessment")
        print()
        print(f"{Fore.RED}Legal Notice:{Style.RESET_ALL}")
        print("  This tool is for authorized security testing only.")
        print("  Unauthorized use is illegal and unethical.")
        print()
        
        input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
    
    def _exit_application(self):
        """Exit the application"""
        self.running = False
        logger.info("Thank you for using SCROLL!")
        print()
    
    def stop(self):
        """Stop the application"""
        self.running = False
        
        if self.scan_engine:
            self.scan_engine.stop()

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Main entry point for SCROLL"""
    # Create application instance
    app = ScrollApplication()
    
    # Run application
    app.run()

if __name__ == "__main__":
    main()
