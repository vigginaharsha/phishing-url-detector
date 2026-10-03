"""
URL Feature Extraction Engine for Phishing Detection.

This module parses URL strings safely without initiating any web requests,
extracting numerical lexical features for machine learning models and generating
human-readable security indicators.
"""

import re
from urllib.parse import urlparse, parse_qs

# Configurable list of keywords commonly used in phishing campaigns
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'secure',
    'update', 'password', 'banking', 'payment', 'confirm', 'security',
    'authentication', 'wallet', 'bonus', 'free', 'admin', 'service',
    'support', 'billing', 'webmail', 'paypal', 'apple', 'google',
    'microsoft', 'amazon', 'netflix', 'recover', 'claim', 'urgent'
]

# Configurable list of popular URL shortener domains
SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
    'buff.ly', 'ow.ly', 'rb.gy', 'cutt.ly', 'rebrand.ly'
]

# Regular expressions for IPv4 and IPv6 detection
IPV4_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
IPV6_PATTERN = re.compile(r'^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$')


def parse_url_safely(url_string: str):
    """
    Ensures the URL string has a scheme for proper parsing without executing/requesting it.
    """
    url_str = url_string.strip()
    if not url_str.startswith(('http://', 'https://', 'ftp://')):
        # Prepend scheme for urlparse if missing
        parsed = urlparse('http://' + url_str)
    else:
        parsed = urlparse(url_str)
    return parsed, url_str


def is_ip_address(domain: str) -> bool:
    """
    Checks if domain/host is a raw IPv4 or IPv6 address.
    """
    # Remove port if present
    host = domain.split(':')[0].strip('[]')
    if IPV4_PATTERN.match(host) or IPV6_PATTERN.match(host):
        return True
    return False


def extract_features(url_string: str) -> dict:
    """
    Extracts numerical lexical features from a URL string for Machine Learning training & prediction.
    
    Returns a dictionary of named numeric features.
    """
    parsed, full_url = parse_url_safely(url_string)
    
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    fragment = parsed.fragment.lower()
    url_lower = full_url.lower()

    # Domain details
    domain_clean = domain.split(':')[0]  # Remove port
    domain_parts = [part for part in domain_clean.split('.') if part]
    
    # Subdomain count calculation (e.g. sub.domain.co.uk -> subdomains count)
    num_subdomains = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0

    # Counts
    url_length = len(full_url)
    domain_length = len(domain_clean)
    num_dots = full_url.count('.')
    num_hyphens = full_url.count('-')
    num_underscores = full_url.count('_')
    num_slashes = full_url.count('/')
    num_question_marks = full_url.count('?')
    num_equal_signs = full_url.count('=')
    num_ampersands = full_url.count('&')
    
    # Character type counts
    num_digits = sum(c.isdigit() for c in full_url)
    num_letters = sum(c.isalpha() for c in full_url)
    num_special_chars = url_length - (num_digits + num_letters)

    # Boolean / Binary indicators
    has_ip = 1 if is_ip_address(domain_clean) else 0
    has_at_symbol = 1 if '@' in full_url else 0
    has_https = 1 if parsed.scheme.lower() == 'https' else 0
    has_http = 1 if parsed.scheme.lower() == 'http' else 0

    # Suspicious keywords count in URL path, query, or domain
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # URL Shortener check
    is_url_shortener = 1 if any(shortener in domain_clean for shortener in SHORTENER_DOMAINS) else 0

    # Query parameters
    query_params = parse_qs(query)
    query_param_count = len(query_params)
    has_fragment = 1 if fragment else 0
    has_percent_encoding = 1 if '%' in full_url else 0

    # Domain anomaly checks
    suspicious_domain_structure = 1 if (
        domain_clean.count('-') > 1 or 
        (len(domain_parts) > 0 and domain_parts[0].isdigit()) or 
        num_subdomains >= 2
    ) else 0

    has_punycode = 1 if 'xn--' in domain_clean else 0

    # Ratios
    digit_ratio = num_digits / url_length if url_length > 0 else 0.0
    special_char_ratio = num_special_chars / url_length if url_length > 0 else 0.0

    return {
        'url_length': url_length,
        'domain_length': domain_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_question_marks': num_question_marks,
        'num_equal_signs': num_equal_signs,
        'num_ampersands': num_ampersands,
        'num_digits': num_digits,
        'num_letters': num_letters,
        'num_special_chars': num_special_chars,
        'num_subdomains': num_subdomains,
        'has_ip': has_ip,
        'has_at_symbol': has_at_symbol,
        'has_https': has_https,
        'has_http': has_http,
        'suspicious_keyword_count': suspicious_keyword_count,
        'is_url_shortener': is_url_shortener,
        'query_param_count': query_param_count,
        'has_fragment': has_fragment,
        'has_percent_encoding': has_percent_encoding,
        'suspicious_domain_structure': suspicious_domain_structure,
        'has_punycode': has_punycode,
        'digit_ratio': round(digit_ratio, 4),
        'special_char_ratio': round(special_char_ratio, 4)
    }


def extract_indicators(url_string: str, features: dict = None) -> list:
    """
    Generates user-friendly explanations (positive and risk indicators)
    based on lexical feature analysis.
    """
    if features is None:
        features = extract_features(url_string)
        
    indicators = []

    # 1. IP Address Check
    if features['has_ip'] == 1:
        indicators.append({
            'status': 'danger',
            'icon': '⚠',
            'title': 'IP Address Hostname',
            'description': 'URL uses a raw IP address instead of a domain name (common phishing tactic).'
        })
    else:
        indicators.append({
            'status': 'safe',
            'icon': '✓',
            'title': 'Standard Domain',
            'description': 'URL uses a standard domain name instead of a numeric IP.'
        })

    # 2. Suspicious Keywords
    parsed, full_url = parse_url_safely(url_string)
    url_lower = full_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        indicators.append({
            'status': 'warning' if len(matched_keywords) == 1 else 'danger',
            'icon': '⚠',
            'title': 'Suspicious Keyword(s)',
            'description': f"Detected potential sensitive targets: {', '.join(matched_keywords[:3])}."
        })

    # 3. @ Symbol
    if features['has_at_symbol'] == 1:
        indicators.append({
            'status': 'danger',
            'icon': '⚠',
            'title': '@ Symbol Present',
            'description': 'The "@" symbol causes browsers to ignore text preceding it, hiding the actual target destination.'
        })

    # 4. Subdomains
    if features['num_subdomains'] >= 2:
        indicators.append({
            'status': 'danger' if features['num_subdomains'] >= 3 else 'warning',
            'icon': '⚠',
            'title': 'Excessive Subdomains',
            'description': f"Contains {features['num_subdomains']} subdomains, which may impersonate legitimate brands."
        })

    # 5. URL Shorteners
    if features['is_url_shortener'] == 1:
        indicators.append({
            'status': 'warning',
            'icon': '⚠',
            'title': 'URL Shortening Service',
            'description': 'URL uses a shortening service that masks the ultimate landing page destination.'
        })

    # 6. URL Length
    if features['url_length'] > 75:
        indicators.append({
            'status': 'warning' if features['url_length'] < 100 else 'danger',
            'icon': '⚠',
            'title': 'Long URL Length',
            'description': f"URL length is {features['url_length']} characters (unusually long URLs often obfuscate malicious parameters)."
        })
    elif features['url_length'] < 55:
        indicators.append({
            'status': 'safe',
            'icon': '✓',
            'title': 'Concise URL',
            'description': 'URL length is within standard concise limits.'
        })

    # 7. Protocol (HTTPS / HTTP)
    if features['has_https'] == 1:
        indicators.append({
            'status': 'safe',
            'icon': '✓',
            'title': 'HTTPS Enabled',
            'description': 'Uses encrypted HTTPS protocol (Note: HTTPS encrypts traffic but does not guarantee domain legitimacy).'
        })
    else:
        indicators.append({
            'status': 'warning',
            'icon': '⚠',
            'title': 'Unencrypted Protocol (HTTP)',
            'description': 'URL uses unencrypted HTTP communication.'
        })

    # 8. Punycode / IDN
    if features['has_punycode'] == 1:
        indicators.append({
            'status': 'danger',
            'icon': '⚠',
            'title': 'Punycode / Homograph Indicator',
            'description': 'Contains "xn--" prefix used in Internationalized Domain Name (IDN) homograph spoofing.'
        })

    # 9. Special Characters
    if features['special_char_ratio'] > 0.15:
        indicators.append({
            'status': 'warning',
            'icon': '⚠',
            'title': 'High Special Character Density',
            'description': f"Special characters represent {int(features['special_char_ratio']*100)}% of the URL."
        })

    return indicators
