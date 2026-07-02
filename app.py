import difflib
import json
import os
import re
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from openpyxl import load_workbook

load_dotenv()

app = Flask(__name__, template_folder='templates')

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
GEMINI_USE_API = os.getenv('GEMINI_USE_API', 'false').strip().lower() in ('1', 'true', 'yes')


def load_vulnerability_catalog():
    catalog_path = os.path.join(os.path.dirname(__file__), 'Web App Vulnerabilities.xlsx')
    if not os.path.exists(catalog_path):
        app.logger.warning('Vulnerability catalog file not found: %s', catalog_path)
        return []

    try:
        workbook = load_workbook(filename=catalog_path, read_only=True, data_only=True)
        sheet = workbook.active
        headers = [str(cell).strip() if cell else '' for cell in next(sheet.iter_rows(min_row=1, max_row=1, values_only=True))]
        header_index = {name.lower(): idx for idx, name in enumerate(headers) if name}

        def get_value(row, key):
            idx = header_index.get(key)
            if idx is None or idx >= len(row):
                return ''
            value = row[idx]
            return str(value).strip() if value is not None else ''

        catalog = []
        for row in sheet.iter_rows(min_row=2, values_only=True):
            if not any(row):
                continue

            catalog.append({
                'id': get_value(row, '#') or get_value(row, 'id'),
                'severity': get_value(row, 'severity'),
                'vulnerabilityName': get_value(row, 'vulnerability name'),
                'details': get_value(row, 'vulnerability details'),
                'impact': get_value(row, 'impact'),
                'remediations': get_value(row, 'remediations'),
                'referenceLink': get_value(row, 'reference link'),
                'issueName': get_value(row, 'issue name'),
            })

        return catalog
    except Exception as exc:
        app.logger.warning('Unable to load vulnerability catalog: %s', exc)
        return []


VULNERABILITY_CATALOG = load_vulnerability_catalog()
CATALOG_NAMES = [item['vulnerabilityName'] for item in VULNERABILITY_CATALOG if item.get('vulnerabilityName')]


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


def fetch_url_content(url: str):
    """Fetch URL content with retries and graceful timeout handling.
    Returns: (page_content, response_headers, error_message)
    If connection fails, page_content and headers may be None but error_message explains why.
    """
    headers = {'User-Agent': 'AI-Security-Scanner/1.0'}
    last_error = None

    # Try with shorter timeout first, then fallback
    for timeout in [8, 12]:
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            page_content = response.text[:16000]
            return page_content, dict(response.headers), None
        except requests.exceptions.Timeout:
            last_error = f'Connection timed out after {timeout}s. The target server may be down, blocking requests, or very slow.'
            app.logger.warning('Timeout fetching %s (timeout=%s)', url, timeout)
            continue
        except requests.exceptions.ConnectionError as exc:
            last_error = f'Connection failed: {str(exc)}. The server may be offline, blocking our scanner, or the URL may be incorrect.'
            app.logger.warning('Connection error fetching %s: %s', url, exc)
            break
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response else 'unknown'
            last_error = f'HTTP {status} error. The server responded with an error status code.'
            app.logger.warning('HTTP error fetching %s: %s', url, exc)
            # For 403/401, we still got headers — return them for analysis
            if exc.response and exc.response.status_code in (401, 403, 404, 500, 502, 503):
                return exc.response.text[:8000], dict(exc.response.headers), None
            break
        except Exception as exc:
            last_error = f'Unexpected error: {str(exc)}'
            app.logger.warning('Unexpected error fetching %s: %s', url, exc)
            break

    return None, None, last_error


def build_catalog_context() -> str:
    lines = []
    for item in VULNERABILITY_CATALOG:
        lines.append(f"- {item.get('vulnerabilityName', 'Unknown Vulnerability')}")
        if item.get('severity'):
            lines.append(f"  Severity: {item['severity']}")
        if item.get('details'):
            lines.append(f"  Details: {item['details'][:300]}")
        if item.get('referenceLink'):
            lines.append(f"  Reference: {item['referenceLink']}")
        if item.get('issueName'):
            lines.append(f"  Issue Name: {item['issueName']}")
        lines.append('')
    return '\n'.join(lines)


def build_gemini_prompt(url: str, headers: dict, page_content: str) -> str:
    catalog_context = build_catalog_context()
    return (
        'You are a security vulnerability analyzer. Here is a catalog of known vulnerabilities found in similar applications. '
        'Analyze the provided URL\'s content and headers, and identify which of these vulnerability patterns are present. '
        'ONLY report issues that have evidence in the content. Do NOT invent issues not in the catalog.\n\n'
        'Catalog:\n'
        f'{catalog_context}\n'
        f'URL: {url}\n\n'
        'Response Headers:\n'
        f'{json.dumps(headers, indent=2)}\n\n'
        'Page Content (truncated):\n'
        f'{page_content[:5000]}\n\n'
        'Identify potential security issues and return ONLY a JSON array in this exact format:\n'
        '[\n'
        '  {\n'
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "vulnerabilityName": "Exact name from the catalog or closest match",\n'
        '    "referenceLink": "URL from the catalog or OWASP link",\n'
        '    "issueName": "Brief description of what was found",\n'
        '    "thinking": "Step-by-step reasoning with evidence from the content"\n'
        '  }\n'
        ']\n\n'
        'Return results in the exact JSON structure above and do not provide any other text outside the JSON array.\n'
    )


def extract_text_from_gemini_response(response):
    if hasattr(response, 'text') and response.text is not None:
        return response.text
    if hasattr(response, 'output'):
        output = getattr(response, 'output')
        if isinstance(output, list) and output:
            first = output[0]
            if hasattr(first, 'content'):
                content = getattr(first, 'content')
                if isinstance(content, list) and content:
                    return getattr(content[0], 'text', str(content[0]))
            return getattr(first, 'text', str(first))
    if isinstance(response, dict):
        if 'text' in response:
            return response['text']
        if 'content' in response:
            return response['content']
        return json.dumps(response)
    return str(response)


def extract_token_counts(response, prompt: str, text: str):
    input_tokens = None
    output_tokens = None

    if hasattr(response, 'metadata'):
        metadata = getattr(response, 'metadata') or {}
    elif isinstance(response, dict):
        metadata = response.get('metadata', {}) or {}
    else:
        metadata = {}

    if isinstance(metadata, dict):
        input_tokens = metadata.get('input_tokens') or metadata.get('input_token_count') or metadata.get('inputTokenCount')
        output_tokens = metadata.get('output_tokens') or metadata.get('output_token_count') or metadata.get('outputTokenCount')
        token_usage = metadata.get('token_usage') or metadata.get('tokenUsage')
        if token_usage and isinstance(token_usage, dict):
            input_tokens = input_tokens or token_usage.get('input') or token_usage.get('input_tokens')
            output_tokens = output_tokens or token_usage.get('output') or token_usage.get('output_tokens')

    if input_tokens is None or output_tokens is None:
        input_tokens = max(1, len(prompt) // 4)
        output_tokens = max(1, len(text) // 4)
    try:
        return int(input_tokens), int(output_tokens)
    except Exception:
        return max(1, int(input_tokens or 1)), max(1, int(output_tokens or 1))


def format_token_annotation(input_tokens: int, output_tokens: int) -> str:
    return f'input={input_tokens} output={output_tokens}'


def extract_results_from_text(text: str):
    if not text:
        raise ValueError('Empty Gemini response')

    json_match = re.search(r'```json\s*(\[.*?\])\s*```', text, re.DOTALL | re.IGNORECASE)
    if json_match:
        payload = json_match.group(1)
    else:
        array_match = re.search(r'(\[\s*\{.*?\}\s*\])', text, re.DOTALL)
        payload = array_match.group(1) if array_match else text

    return json.loads(payload)


def normalize_results(results, token_annotation='input=0 output=0'):
    normalized = []
    for item in (results or []):
        severity = str(item.get('severity', 'LOW')).strip().upper()
        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            severity = 'LOW'

        normalized.append({
            'severity': severity,
            'vulnerabilityName': str(item.get('vulnerabilityName', 'Unknown Vulnerability')).strip(),
            'referenceLink': str(item.get('referenceLink', 'https://owasp.org')).strip(),
            'issueName': str(item.get('issueName', 'No issue description provided')).strip(),
            'thinking': str(item.get('thinking', '')),
            'analysisTime': str(item.get('analysisTime', '')),
            'tokens': str(item.get('tokens', token_annotation)).strip(),
            'confidence': str(item.get('confidence', '')),
        })
    return normalized


def call_gemini_api(prompt: str):
    try:
        from google import genai
    except ImportError as exc:
        raise RuntimeError(
            'Gemini integration requires the google GenAI package. Install with: pip install -r requirements.txt'
        ) from exc

    try:
        app.logger.info('Initializing Gemini client...')
        client = genai.Client(api_key=GEMINI_API_KEY)

        app.logger.info(f'Sending prompt to Gemini API ({GEMINI_MODEL})...')
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)

        if not response:
            raise ValueError('Gemini API returned empty response')

        app.logger.info('Gemini API response received successfully')
        text = extract_text_from_gemini_response(response)

        if not text:
            raise ValueError('Failed to extract text from Gemini response')

        app.logger.info(f'Extracted {len(text)} characters from response')
        input_tokens, output_tokens = extract_token_counts(response, prompt, text)
        return text, input_tokens, output_tokens
    except Exception as exc:
        app.logger.error(f'Gemini API call failed: {type(exc).__name__}: {exc}', exc_info=True)
        raise


def find_catalog_entry_by_name(name: str):
    if not name:
        return None

    normalized_query = name.strip().lower()
    for item in VULNERABILITY_CATALOG:
        if item.get('vulnerabilityName', '').strip().lower() == normalized_query:
            return item

    if not CATALOG_NAMES:
        return None

    matches = difflib.get_close_matches(name, CATALOG_NAMES, n=1, cutoff=0.4)
    if matches:
        target = matches[0]
        return next((item for item in VULNERABILITY_CATALOG if item.get('vulnerabilityName') == target), None)

    return None


def build_static_result(name: str, issue_name: str, thinking: str, reference: str = None, severity: str = None):
    entry = find_catalog_entry_by_name(name)
    return {
        'severity': (severity or entry.get('severity', 'LOW')).strip().upper() if entry else (severity or 'LOW').strip().upper(),
        'vulnerabilityName': entry.get('vulnerabilityName') if entry else name,
        'referenceLink': reference or (entry.get('referenceLink') if entry else 'https://owasp.org'),
        'issueName': issue_name,
        'thinking': thinking,
        'analysisTime': '0.0s',
        'tokens': format_token_annotation(0, 0),
    }


def static_analysis_findings(url: str, headers: dict, page_content: str):
    findings = []

    if not headers:
        headers = {}
    if not page_content:
        page_content = ''

    lower_headers = {k.lower(): v for k, v in (headers or {}).items()}
    required_headers = [
        'x-frame-options',
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'referrer-policy',
    ]
    missing_headers = [h for h in required_headers if h not in lower_headers]
    if missing_headers:
        findings.append(build_static_result(
            'Missing Security Headers',
            f'Missing required security headers: {", ".join(missing_headers)}',
            'The response headers were inspected and one or more security headers are absent. '
            'This increases risk of clickjacking, MIME type confusion, and referrer leakage.',
        ))

    server_header = lower_headers.get('server')
    powered_by_header = lower_headers.get('x-powered-by')
    if server_header or powered_by_header:
        header_values = []
        if server_header:
            header_values.append(f'Server: {server_header}')
        if powered_by_header:
            header_values.append(f'X-Powered-By: {powered_by_header}')
        findings.append(build_static_result(
            'Information Disclosure',
            'Server version or platform disclosure found in response headers: ' + '; '.join(header_values),
            'The server response exposes implementation details that can help an attacker identify known vulnerabilities.',
        ))

    cors_origin = lower_headers.get('access-control-allow-origin', '')
    if cors_origin and cors_origin.strip() in ('*', 'null'):
        findings.append(build_static_result(
            'CORS Misconfiguration',
            f'Access-Control-Allow-Origin is set to {cors_origin!r}.',
            'A permissive CORS policy allows any origin to access resources, which may expose sensitive data in browser-based requests.',
        ))

    try:
        sensitive_pattern = re.search(r'\b(password|api_key|secret|token|encryptionkey)\b', page_content or '', re.IGNORECASE)
        if sensitive_pattern:
            findings.append(build_static_result(
                'Information Disclosure',
                f'Potential sensitive data exposure found by matching {sensitive_pattern.group(0)} in page content.',
                'The page content contains terms commonly associated with credentials or secrets, which may indicate accidental disclosure.',
            ))
    except Exception as e:
        app.logger.warning(f'Sensitive pattern search failed: {e}')

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme == 'http':
            findings.append(build_static_result(
                'Missing HTTPS Redirect',
                'The target URL uses http:// instead of https://.',
                'The connection is not encrypted by default, which can expose data in transit and make the application vulnerable to man-in-the-middle attacks.',
            ))
    except Exception as e:
        app.logger.warning(f'URL parsing failed: {e}')

    return findings


def analyze_unreachable_url(url: str, error_msg: str):
    """When a URL cannot be fetched, still perform analysis on what we know."""
    findings = []

    # Check if it's HTTP
    try:
        parsed = urlparse(url)
        if parsed.scheme == 'http':
            findings.append(build_static_result(
                'Missing HTTPS Redirect',
                'The target URL uses http:// instead of https://.',
                'The connection is not encrypted by default. Additionally, the server could not be reached, which may indicate it is down or blocking requests.',
            ))
    except Exception:
        pass

    # Add a note about connectivity
    findings.append(build_static_result(
        'Information Disclosure',
        f'Target server could not be reached: {error_msg}',
        'The scanner was unable to establish a connection to the target. This could mean the server is offline, blocking automated requests, or the URL is incorrect. '
        'No content or headers could be analyzed. Consider testing with a different URL or checking if the target requires authentication.',
        severity='LOW',
    ))

    return findings


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()

        if not url or not is_valid_url(url):
            return jsonify({'error': 'Please provide a valid http or https URL.', 'results': []}), 400

        page_content, headers, fetch_error = fetch_url_content(url)

        # If fetch failed completely, still try to analyze what we can from the URL itself
        if fetch_error and (page_content is None or headers is None):
            app.logger.warning('Fetch failed for %s: %s', url, fetch_error)
            fallback_results = analyze_unreachable_url(url, fetch_error)
            return jsonify({
                'results': fallback_results,
                'url': url,
                'warning': f'Could not fetch target content: {fetch_error}. Analysis is limited to URL-level checks only.',
            })

        try:
            static_results = static_analysis_findings(url, headers or {}, page_content or '')
            app.logger.info(f'Static analysis found {len(static_results)} issues')
        except Exception as exc:
            app.logger.error(f'Static analysis error: {exc}', exc_info=True)
            static_results = []

        ai_results = []

        if GEMINI_USE_API and GEMINI_API_KEY and page_content:
            prompt = build_gemini_prompt(url, headers or {}, page_content)
            try:
                app.logger.info('Calling Gemini API...')
                raw_text, input_tokens, output_tokens = call_gemini_api(prompt)
                app.logger.info(f'Gemini response received: {len(raw_text)} chars')
                extracted = extract_results_from_text(raw_text)
                app.logger.info(f'Extracted {len(extracted)} AI results')
                ai_results = normalize_results(
                    extracted,
                    format_token_annotation(input_tokens, output_tokens),
                )
            except Exception as exc:
                app.logger.error(f'Gemini API error: {exc}', exc_info=True)
        elif GEMINI_USE_API and not GEMINI_API_KEY:
            app.logger.warning('GEMINI_USE_API is enabled but GEMINI_API_KEY is not set. Skipping AI request.')

        combined = []
        seen = set()
        for result in static_results + ai_results:
            key = result.get('vulnerabilityName', '').strip().lower()
            if not key:
                continue
            if key not in seen:
                combined.append(result)
                seen.add(key)

        if not combined:
            return jsonify({
                'results': [],
                'url': url,
                'message': 'No vulnerabilities detected in the accessible content. Note: This tool can only analyze publicly visible content and headers. Active vulnerabilities (SQL injection, broken access control, IDOR, etc.) require authenticated penetration testing and cannot be detected through static analysis.',
            })

        return jsonify({'results': combined, 'url': url})

    except Exception as exc:
        app.logger.error(f'Unexpected error in /scan: {exc}', exc_info=True)
        return jsonify({'error': f'Internal server error: {str(exc)}', 'results': []}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', 'false').strip().lower() in ('1', 'true', 'yes')
    app.run(debug=debug, host='0.0.0.0', port=port)