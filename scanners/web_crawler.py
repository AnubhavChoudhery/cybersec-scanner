"""
Web crawler for scanning localhost applications.

Crawls web pages and JavaScript files, matching against known secret patterns.
"""
import urllib.parse
from collections import deque
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, wait
import os
import re
import logging

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip install requests")
    requests = None

from config import PROBE_PATHS, KNOWN_PATTERNS, SOURCE_MAP_RE, JS_URL_RE


def _scan_patterns_worker(text, patterns_serialized):
    """
    Worker function run in a separate process to apply regex patterns to text.

    Args:
        text (str): content to scan
        patterns_serialized (list): list of tuples (name, pattern_str, flags)

    Returns:
        list of tuples (name, matched_text)
    """
    out = []
    try:
        for name, pat_str, flags in patterns_serialized:
            try:
                pat = re.compile(pat_str, flags)
            except Exception:
                # fallback: compile without flags
                try:
                    pat = re.compile(pat_str)
                except Exception:
                    continue
            try:
                m = pat.search(text)
                if m:
                    out.append((name, m.group(0)))
            except Exception:
                continue
    except Exception:
        pass
    return out


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
    
    def __init__(self, base, timeout=6, same_host_only=True, max_pages=300, workers=8, ignore_headers=None, max_js_size=500_000):
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
            raise ImportError(
                "requests library is required for web crawling\n"
                "Install with: pip install requests"
            )
        
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "LocalSecurityAudit/1.0"})
        self.timeout = timeout
        self.same_host_only = same_host_only
        self.max_pages = max_pages
        self.workers = max(1, int(workers))
        # headers to ignore during header scanning (case-insensitive)
        if ignore_headers is None:
            self.ignore_headers = {"etag", "server", "date", "content-length"}
        else:
            self.ignore_headers = {h.lower() for h in ignore_headers}
        # max JS size (bytes) to scan; skip very large bundles by default (None=no limit)
        self.max_js_size = int(max_js_size) if max_js_size is not None else None

        # Thread-safe state
        self._lock = threading.Lock()
        self.visited = set()
        self.queue = deque([self.base + "/"])
        self.findings = []
        self.js_store = {}

        # Known session/XSRF token cookie names to skip pattern matching (case-insensitive)
        self.skip_cookie_names = {
            "_streamlit_xsrf", "sessionid", "session", "csrf_token", "xsrf-token",
            "ajs_anonymous_id", "ajs_user_id", "_ga", "_gid", "_fbp"
        }

        # Track probe responses for catch-all detection
        self.probe_responses = {}

        # Pre-serialize patterns for process-pool scanning (pattern string + flags)
        self.patterns_serialized = [(name, pat.pattern, pat.flags) for name, pat in KNOWN_PATTERNS.items()]

        # Process pool for CPU-bound regex scanning
        try:
            cpus = max(1, (os.cpu_count() or 2) - 1)
        except Exception:
            cpus = 1
        self.process_pool = ProcessPoolExecutor(max_workers=cpus)

        # logger for this crawler
        self.logger = logging.getLogger(__name__)
        self.logger.debug(
            "Initialized LocalCrawler(base=%s, timeout=%s, same_host_only=%s, max_pages=%s, workers=%s)",
            self.base, self.timeout, self.same_host_only, self.max_pages, self.workers
        )

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
        self.logger.info("Probing common sensitive paths (%d paths)", len(PROBE_PATHS))
        probe_findings = []
        for p in PROBE_PATHS:
            url = urllib.parse.urljoin(self.base + "/", p.lstrip("/"))
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200 and r.text.strip():
                    self.probe_responses[url] = r.text
                    self.logger.info("Exposed path found: %s (status=%s)", url, r.status_code)
                    probe_findings.append({
                        "type": "exposed_path",
                        "url": url,
                        "status": r.status_code,
                        "snippet": "[REDACTED]",
                        "original_length": len(r.text[:800]),
                        "severity": "MEDIUM"
                    })
            except Exception:
                self.logger.debug("Probe failed for %s (expected for many)", url, exc_info=True)
                pass  # Expected for most paths (404s)
        
        # Detect catch-all responses: if all probes return identical content, it's likely a framework default
        if probe_findings and len(probe_findings) >= 3:
            first_response = list(self.probe_responses.values())[0]
            all_identical = all(resp == first_response for resp in self.probe_responses.values())
            if all_identical:
                self.logger.info("Catch-all response detected - all %d probes returned identical content (likely framework default 404)", len(probe_findings))
                # Mark all probe findings as false positives
                for finding in probe_findings:
                    finding["type"] = "false_positive_catchall"
        
        self.findings.extend(probe_findings)

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
            self.logger.debug("Fetched %s -> %s", url, getattr(r, 'status_code', None))
            return r
        except Exception:
            self.logger.debug("Fetch failed: %s", url, exc_info=True)
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
                    self.logger.info("Pattern match in response: %s @ %s", name, url)
                    self.findings.append({
                        "type": "response_pattern",
                        "url": url,
                        "pattern": name,
                        "snippet": "[REDACTED]",
                        "original_length": len(match.group(0)[:400]),
                        "severity": "HIGH"
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
        
        # Check HTTP headers for exposed secrets, skipping noisy headers
        for k, v in response.headers.items():
            if k.lower() in self.ignore_headers:
                continue
            try:
                # run lightweight pattern checks in-process for headers
                sval = str(v)
                for name, pat in KNOWN_PATTERNS.items():
                    if pat.search(sval):
                        self.logger.info("Header pattern match: %s header=%s @ %s", name, k, url)
                        self.findings.append({
                            "type": "header_pattern",
                            "url": url,
                            "header": k,
                            "pattern": name,
                            "value": "[REDACTED]",
                            "original_length": len(v),
                            "severity": "HIGH"
                        })
            except Exception:
                continue
        
        # Check cookies for suspicious patterns, but skip known session/XSRF tokens
        if "set-cookie" in response.headers:
            for cookie_header in response.headers.getlist("set-cookie") if hasattr(response.headers, "getlist") else [response.headers.get("set-cookie", "")]:
                # Extract cookie name (format: name=value; ...)
                try:
                    cookie_name = cookie_header.split("=")[0].strip().lower()
                    if cookie_name not in self.skip_cookie_names:
                        # Pattern match on cookie value
                        for name, pat in KNOWN_PATTERNS.items():
                            if pat.search(cookie_header):
                                self.logger.info("Cookie pattern match: %s in %s @ %s", name, cookie_name, url)
                                self.findings.append({
                                    "type": "cookie_pattern",
                                    "url": url,
                                    "cookie": cookie_name,
                                    "pattern": name,
                                    "snippet": "[REDACTED]",
                                    "original_length": len(cookie_header[:400]),
                                    "severity": "HIGH"
                                })
                    else:
                        self.logger.debug("Skipping known session/XSRF token: %s", cookie_name)
                except Exception:
                    continue
        
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
                            try:
                                # Offload heavy pattern scanning to process pool
                                fut = self.process_pool.submit(_scan_patterns_worker, src, self.patterns_serialized)
                                matches = fut.result()
                                for name, matched in matches:
                                    self.logger.info("Sourcemap pattern match: %s in %s (source_index=%d)", name, map_url, i)
                                    self.findings.append({
                                        "type": "sourcemap_pattern",
                                        "map": map_url,
                                        "source_index": i,
                                        "pattern": name,
                                        "snippet": "[REDACTED]",
                                        "original_length": len(matched[:400]),
                                        "severity": "HIGH"
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

        # Worker to fetch and analyze a single URL. Returns new links found.
        def _process(url):
            new_links = []
            try:
                r = self.fetch(url)
                if not r:
                    return new_links

                # record status and analyze response
                with self._lock:
                    self.findings.append({"type": "status", "url": url, "status": r.status_code})
                self.analyze_response(url, r)

                text = r.text or ""
                # discover JS/source links and regular links
                for m in JS_URL_RE.finditer(text):
                    link = urllib.parse.urljoin(url, m.group(1))
                    if link.endswith(".js") or link.endswith(".map"):
                        # Avoid refetching the same JS/map if another worker already fetched it
                        with self._lock:
                            cached = self.js_store.get(link)
                        if cached is not None:
                            rr_text = cached
                            self.logger.debug("Using cached JS/map %s", link)
                        else:
                            rr = self.fetch(link)
                            if not rr or rr.status_code != 200:
                                continue
                            rr_text = rr.text
                            with self._lock:
                                self.js_store[link] = rr_text

                        # Log processing start with size to indicate progress
                        try:
                            size = len(rr_text.encode('utf-8'))
                        except Exception:
                            size = len(rr_text)
                        self.logger.info("Processing JS/map: %s (%d bytes)", link, size)

                        # Skip very large JS bundles to avoid long-running scans (if limit set)
                        if self.max_js_size is not None and size > self.max_js_size:
                            self.logger.info("Skipping JS/map %s because size %d > max_js_size %d", link, size, self.max_js_size)
                            continue

                        # Offload JS pattern matching to the process pool
                        try:
                            fut = self.process_pool.submit(_scan_patterns_worker, rr_text, self.patterns_serialized)
                            matches = fut.result()
                            for name, matched in matches:
                                with self._lock:
                                    self.findings.append({
                                        "type": "js_pattern",
                                        "url": link,
                                        "pattern": name,
                                        "snippet": "[REDACTED]",
                                        "original_length": len(matched[:400]),
                                        "severity": "HIGH"
                                    })
                                self.logger.info("JS pattern match: %s @ %s", name, link)
                        except Exception:
                            self.logger.debug("JS process-pool scanning failed for %s", link, exc_info=True)
                    else:
                        new_links.append(link)
            except Exception:
                pass
            return new_links

        futures = set()
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            # seed initial tasks up to worker count
            while True:
                with self._lock:
                    if not self.queue or pages >= self.max_pages:
                        break
                    # find next candidate URL
                    try:
                        url = self.queue.popleft()
                    except IndexError:
                        break
                    if url in self.visited:
                        continue
                    if self.same_host_only and not self.is_same_host(url):
                        continue
                    self.visited.add(url)
                    pages += 1
                futures.add(ex.submit(_process, url))

            # Process completed tasks and keep seeding until limits reached
            while futures:
                done, _ = wait(futures, return_when='FIRST_COMPLETED')
                for f in done:
                    futures.remove(f)
                    try:
                        new_links = f.result() or []
                    except Exception:
                        new_links = []
                    with self._lock:
                        for nl in new_links:
                            if self.same_host_only and not self.is_same_host(nl):
                                continue
                            if nl not in self.visited and nl not in self.queue and pages < self.max_pages:
                                self.queue.append(nl)

                    # fill up worker slots
                    with self._lock:
                        while self.queue and pages < self.max_pages and len(futures) < self.workers:
                            try:
                                nxt = self.queue.popleft()
                            except IndexError:
                                break
                            if nxt in self.visited:
                                continue
                            if self.same_host_only and not self.is_same_host(nxt):
                                continue
                            self.visited.add(nxt)
                            pages += 1
                            futures.add(ex.submit(_process, nxt))

            # drain any remaining futures (safety)
            for f in as_completed(futures):
                try:
                    new_links = f.result() or []
                except Exception:
                    new_links = []
                with self._lock:
                    for nl in new_links:
                        if self.same_host_only and not self.is_same_host(nl):
                            continue
                        if nl not in self.visited and nl not in self.queue and pages < self.max_pages:
                            self.queue.append(nl)
        # Shutdown process pool used for CPU-bound regex scanning
        try:
            self.process_pool.shutdown(wait=True)
        except Exception:
            pass


def process_crawler_findings(crawler_findings):
    """
    Process crawler findings and filter out non-issues.
    
    Args:
        crawler_findings (list): Raw findings from LocalCrawler
        
    Returns:
        list: Filtered findings (excludes successful status codes)
    """
    real_issues = [
        f for f in crawler_findings 
        if f.get("type") != "status" or f.get("status", 200) >= 400
    ]
    
    return [
        {
            "type": "crawler_issue",
            "url": f.get("url"),
            "description": f.get("description"),
            "details": f
        }
        for f in real_issues
    ]
