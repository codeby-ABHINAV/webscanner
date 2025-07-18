# zera.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

xss_results = []
sqli_results = []
open_redirect_results = []
security_headers_results = []

OPEN_REDIRECT_TEST_URL = "http://evil.com"
SECURITY_HEADERS = [
    "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy"
]

def crawl_site(url):
    visited = set()
    to_visit = [url]
    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)
        try:
            response = requests.get(current_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_link = urljoin(current_url, link['href'])
                if full_link.startswith(url):
                    to_visit.append(full_link)
        except:
            continue
    return visited

def test_open_redirect(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    for param in params:
        if param.lower() in ["redirect", "url", "next", "dest"]:
            injected_params = params.copy()
            injected_params[param] = [OPEN_REDIRECT_TEST_URL]
            injected_query = "&".join(f"{k}={v[0]}" for k,v in injected_params.items())
            test_url = parsed_url._replace(query=injected_query).geturl()
            try:
                res = requests.get(test_url, allow_redirects=False, timeout=5)
                if res.status_code in [301, 302, 303, 307, 308]:
                    location = res.headers.get("Location", "")
                    if OPEN_REDIRECT_TEST_URL in location:
                        open_redirect_results.append(test_url)
            except:
                continue

def check_security_headers(url):
    try:
        res = requests.get(url, timeout=5)
        missing = [h for h in SECURITY_HEADERS if h not in res.headers]
        if missing:
            security_headers_results.append((url, missing))
    except:
        pass

def test_vulnerabilities(urls):
    xss_payload = "<script>alert('XSS')</script>"
    sqli_payload = "' OR '1'='1"
    for url in urls:
        if "=" in url:
            test_xss = url.replace("=", "=" + xss_payload)
            test_sql = url.replace("=", "=" + sqli_payload)
            try:
                xss_res = requests.get(test_xss)
                if xss_payload in xss_res.text:
                    xss_results.append(test_xss)
                sql_res = requests.get(test_sql)
                if "sql" in sql_res.text.lower() or "error" in sql_res.text.lower():
                    sqli_results.append(test_sql)
            except:
                continue
            test_open_redirect(url)
        check_security_headers(url)

def scan_forms(url):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_url = urljoin(url, action)
            data = {i.get("name"): xss_payload for i in inputs if i.get("name")}
            if method == "post":
                response = requests.post(form_url, data=data)
            else:
                response = requests.get(form_url, params=data)
            if xss_payload in response.text:
                xss_results.append(form_url)
            elif "sql" in response.text.lower() or "error" in response.text.lower():
                sqli_results.append(form_url)
    except:
        pass

def run_full_scan(target_url):
    global xss_results, sqli_results, open_redirect_results, security_headers_results
    xss_results.clear()
    sqli_results.clear()
    open_redirect_results.clear()
    security_headers_results.clear()

    scanned_links = crawl_site(target_url)
    test_vulnerabilities(scanned_links)
    for link in scanned_links:
        scan_forms(link)

    return {
        "xss": xss_results,
        "sqli": sqli_results,
        "open_redirect": open_redirect_results,
        "missing_headers": security_headers_results
    }

