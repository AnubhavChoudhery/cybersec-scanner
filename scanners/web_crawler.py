"""
Web crawler for scanning localhost applications.

Crawls web pages and JavaScript files, matching against known secret patterns.
"""
import urllib.parse
from collections import deque

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip install requests")
    requests = None

from config import PROBE_PATHS, KNOWN_PATTERNS, SOURCE_MAP_RE, JS_URL_RE


class LocalCrawler:
    """
    HTTP crawler for localhost applications to discover security vulnerabilities.
    
    Crawls a local web application to:
    1. Discover exposed sensitive paths (.env, .git, config files)
    2. Extract and analyze JavaScript code for hardcoded secrets
    3. Fetch and analyze source maps for leaked credentials
    4. Check HTTP headers for security issues
    5. Extract string literals from responses
    
    Attributes:
        base (str): Base URL to crawl (e.g., "http://localhost:8000")
        session (requests.Session): HTTP session for making requests
        visited (set): Set of URLs already crawled (prevents loops)
        queue (deque): URLs waiting to be crawled
        findings (list): All security findings discovered
        js_store (dict): Cache of JavaScript file contents
        
    Configuration:
        timeout (int): Request timeout in seconds (default: 6)
        same_host_only (bool): Only crawl same hostname (default: True)
        max_pages (int): Maximum pages to crawl (default: 300)
        
    Limitations:
        - No JavaScript execution (misses dynamically loaded content)
        - Basic link extraction (may miss some modern routing)
        - No authentication support (can't scan protected areas)
        - Sequential crawling (no parallelization)
    """
    
    def __init__(self, base, timeout=6, same_host_only=True, max_pages=300):
        """
        Initialize the crawler with target configuration.
        
        Args:
            base (str): Base URL to crawl (e.g., "http://localhost:8000")
            timeout (int): HTTP request timeout in seconds
            same_host_only (bool): Restrict crawling to same hostname
            max_pages (int): Maximum number of pages to crawl
        """
        self.base = base.rstrip("/")
        self.parsed_base = urllib.parse.urlparse(self.base)
        
        if requests is None:
            raise ImportError("requests library is required for web crawling")
        
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "LocalSecurityAudit/1.0"})
        self.timeout = timeout
        self.same_host_only = same_host_only
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.base + "/"])
        self.findings = []
        self.js_store = {}

    def is_same_host(self, url):
        """
        Check if a URL belongs to the same host as the base URL.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if same host or localhost variant, False otherwise
            
        Notes:
            Treats localhost, 127.0.0.1, and the base hostname as equivalent.
            Relative URLs (no netloc) are considered same-host.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                return True  # Relative URL
            host = parsed.hostname
            return host in (self.parsed_base.hostname, "localhost", "127.0.0.1")
        except Exception:
            return True  # On parse error, allow it

    def probe_common_paths(self):
        """
        Probe common sensitive paths that often contain secrets or configuration.
        
        Checks a predefined list of paths commonly left exposed by developers:
        - Environment files (.env, .env.local)
        - Git metadata (.git/config, .git/HEAD)
        - Backup files (config.php.bak)
        - Server status pages
        - CI/CD configuration files
        
        Any 200 OK responses with non-empty content are flagged as findings.
        This is typically run before the main crawl for quick wins.
        """
        for p in PROBE_PATHS:
            url = urllib.parse.urljoin(self.base + "/", p.lstrip("/"))
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200 and r.text.strip():
                    self.findings.append({
                        "type": "exposed_path",
                        "url": url,
                        "status": r.status_code,
                        "snippet": r.text[:800]  # First 800 chars for context
                    })
            except Exception:
                pass  # Expected for most paths (404s)

    def fetch(self, url):
        """
        Fetch a URL with the configured timeout and session.
        
        Args:
            url (str): URL to fetch
            
        Returns:
            requests.Response or None: Response object on success, None on failure
        """
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r
        except Exception:
            return None

    def analyze_text_for_patterns(self, text, url):
        """
        Analyze text content for known secret patterns.
        
        Args:
            text: Response body or content to analyze
            url: Source URL for reporting
        """
        for name, pat in KNOWN_PATTERNS.items():
            try:
                match = pat.search(text)
                if match:
                    self.findings.append({
                        "type": "response_pattern",
                        "url": url,
                        "pattern": name,
                        "snippet": match.group(0)[:400]
                    })
            except Exception:
                continue

    def analyze_response(self, url, response):
        """
        Analyze HTTP response for security issues using pattern matching.
        
        Args:
            url: URL that was fetched
            response: Response object to analyze
        """
        text = response.text if response.text else ""
        
        # Pattern matching on response body
        self.analyze_text_for_patterns(text, url)
        
        # Check HTTP headers for exposed secrets
        for k, v in response.headers.items():
            for name, pat in KNOWN_PATTERNS.items():
                if pat.search(str(v)):
                    self.findings.append({
                        "type": "header_pattern",
                        "url": url,
                        "header": k,
                        "pattern": name,
                        "value": v
                    })
        
        # Look for source map references and analyze them
        for m in SOURCE_MAP_RE.finditer(text):
            rel = m.group("url")
            map_url = urllib.parse.urljoin(url, rel)
            
            try:
                mr = self.fetch(map_url)
                if mr and mr.status_code == 200:
                    try:
                        jsmap = mr.json()
                        sources = jsmap.get("sourcesContent", []) or []
                        
                        # Pattern match on source map content
                        for i, src in enumerate(sources):
                            for name, pat in KNOWN_PATTERNS.items():
                                try:
                                    match = pat.search(src)
                                    if match:
                                        self.findings.append({
                                            "type": "sourcemap_pattern",
                                            "map": map_url,
                                            "source_index": i,
                                            "pattern": name,
                                            "snippet": match.group(0)[:400]
                                        })
                                except Exception:
                                    continue
                    except Exception:
                        continue
            except Exception:
                continue

    def crawl(self):
        """
        Main crawl loop - processes URLs from queue until max_pages or queue empty.
        
        For each URL:
        1. Fetch the page
        2. Analyze response for security issues
        3. Extract links and add to queue
        4. Extract and analyze JavaScript files
        
        Respects:
        - max_pages limit
        - same_host_only setting
        - visited set (no duplicates)
        
        Side Effects:
            Populates self.findings with all discovered issues
        """
        pages = 0
        
        while self.queue and pages < self.max_pages:
            url = self.queue.popleft()
            
            # Skip if already visited
            if url in self.visited:
                continue
            
            # Skip if different host (when same_host_only enabled)
            if self.same_host_only and not self.is_same_host(url):
                continue
            
            self.visited.add(url)
            pages += 1
            
            # Fetch the page
            r = self.fetch(url)
            if not r:
                continue
            
            # Record status
            self.findings.append({"type": "status", "url": url, "status": r.status_code})
            
            # Analyze response for secrets
            self.analyze_response(url, r)
            
            # Extract links and JavaScript files
            for m in JS_URL_RE.finditer(r.text or ""):
                link = urllib.parse.urljoin(url, m.group(1))
                
                if link not in self.visited:
                    # Handle JavaScript and source map files specially
                    if link.endswith(".js") or link.endswith(".map"):
                        rr = self.fetch(link)
                        if rr and rr.status_code == 200:
                            self.js_store[link] = rr.text
                            
                            # Pattern match on JavaScript content
                            for name, pat in KNOWN_PATTERNS.items():
                                try:
                                    match = pat.search(rr.text)
                                    if match:
                                        self.findings.append({
                                            "type": "js_pattern",
                                            "url": link,
                                            "pattern": name,
                                            "snippet": match.group(0)[:400]
                                        })
                                except Exception:
                                    continue
                    else:
                        # Regular page - add to crawl queue
                        self.queue.append(link)
