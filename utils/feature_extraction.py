"""
feature_extraction.py
=====================
Extracts ALL 87 features from a URL — in the EXACT same order
the Gradient Boosting model was trained on from the Kaggle dataset.

Column order from training dataset (87 features, after dropping 'url' and 'status'):
['length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash',
 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host',
 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
 'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service',
 'path_extension', 'nb_redirection', 'nb_external_redirection',
 'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host',
 'shortest_word_path', 'longest_words_raw', 'longest_word_host',
 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path',
 'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
 'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
 'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
 'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon',
 'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia',
 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
 'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
 'whois_registered_domain', 'domain_registration_length', 'domain_age',
 'web_traffic', 'dns_record', 'google_index', 'page_rank']

NOTE: Features that require live page fetching (hyperlinks, CSS, iframes etc.)
are set to their dataset median/neutral value when only a URL is provided.
URL-structural features are computed exactly.
"""

import re
import math
from urllib.parse import urlparse

# ── Known brand names used in dataset ──────────────────────────
BRANDS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
    'ebay', 'instagram', 'twitter', 'linkedin', 'netflix', 'youtube',
    'yahoo', 'dropbox', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'hsbc', 'outlook', 'office365', 'gmail', 'whatsapp',
    'telegram', 'snapchat', 'tiktok', 'adobe', 'salesforce', 'shopify',
]

# ── Suspicious TLDs commonly used in phishing ──────────────────
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw',
    '.click', '.link', '.loan', '.work', '.party', '.review',
    '.country', '.stream', '.download', '.racing', '.online',
    '.science', '.win', '.bid', '.trade', '.webcam',
]

# ── Phishing hint keywords ──────────────────────────────────────
PHISH_HINTS = [
    'login', 'logon', 'signin', 'sign-in', 'verify', 'verification',
    'account', 'update', 'banking', 'secure', 'security', 'confirm',
    'password', 'passwd', 'credential', 'wallet', 'alert', 'suspended',
    'unusual', 'unauthorized', 'validate', 'authentication', 'recover',
]

# ── URL shorteners ──────────────────────────────────────────────
SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
    'short.link', 'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd',
    'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'su.pr', 'twit.ac',
]

# ── Common TLDs for tld_in_path / tld_in_subdomain check ───────
COMMON_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.info',
    '.biz', '.me', '.uk', '.us', '.de', '.fr', '.ru', '.cn',
]

# ── File extensions that appear in phishing paths ──────────────
PHISH_EXTENSIONS = ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp']


def _safe_divide(a, b, default=0.0):
    return round(a / b, 4) if b != 0 else default


def _word_stats(text):
    """Split text into words and return (count, shortest, longest, avg)."""
    if not text:
        return 0, 0, 0, 0.0
    words = re.split(r'[.\-_/=?&@%+\s]', text)
    words = [w for w in words if w]
    if not words:
        return 0, 0, 0, 0.0
    lengths = [len(w) for w in words]
    return len(words), min(lengths), max(lengths), round(sum(lengths) / len(lengths), 2)


def extract_features(url: str) -> list:
    """
    Given a URL string, returns a list of 87 numeric feature values
    in the exact column order the model was trained on.
    """
    # ── Parse URL ───────────────────────────────────────────────
    raw_url = url.strip()
    if not re.match(r'^https?://', raw_url, re.I):
        raw_url = 'http://' + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception:
        parsed = urlparse('http://invalid.com')

    full_url   = raw_url.lower()
    scheme     = parsed.scheme.lower()
    hostname   = parsed.netloc.lower().split(':')[0]   # strip port
    path       = parsed.path.lower()
    query      = parsed.query.lower()
    fragment   = parsed.fragment.lower()
    port_str   = parsed.port

    # Clean hostname for word analysis
    domain_clean = hostname.replace('www.', '')
    parts = domain_clean.split('.')
    tld   = ('.' + parts[-1]) if parts else ''

    # ── 1. length_url ────────────────────────────────────────────
    length_url = len(raw_url)

    # ── 2. length_hostname ──────────────────────────────────────
    length_hostname = len(hostname)

    # ── 3. ip ── 1 if IP address used instead of domain ─────────
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ip = 1 if ip_pattern.match(hostname) else 0

    # ── 4-20. Character counts ───────────────────────────────────
    nb_dots        = full_url.count('.')
    nb_hyphens     = full_url.count('-')
    nb_at          = full_url.count('@')
    nb_qm          = full_url.count('?')
    nb_and         = full_url.count('&')
    nb_or          = full_url.count('|')
    nb_eq          = full_url.count('=')
    nb_underscore  = full_url.count('_')
    nb_tilde       = full_url.count('~')
    nb_percent     = full_url.count('%')
    nb_slash       = full_url.count('/')
    nb_star        = full_url.count('*')
    nb_colon       = full_url.count(':')
    nb_comma       = full_url.count(',')
    nb_semicolumn  = full_url.count(';')
    nb_dollar      = full_url.count('$')
    nb_space       = full_url.count(' ') + full_url.count('%20')

    # ── 21. nb_www ── number of "www" occurrences ───────────────
    nb_www = full_url.count('www')

    # ── 22. nb_com ── number of ".com" occurrences ──────────────
    nb_com = full_url.count('.com')

    # ── 23. nb_dslash ── double slashes after scheme ────────────
    after_scheme = full_url[full_url.find('//')+2:]
    nb_dslash = after_scheme.count('//')

    # ── 24. http_in_path ── "http" appears in path ──────────────
    http_in_path = 1 if 'http' in path else 0

    # ── 25. https_token ── "https" as a token in domain/path ────
    https_token = 1 if 'https' in hostname or 'https' in path else 0

    # ── 26. ratio_digits_url ────────────────────────────────────
    digits_url = sum(c.isdigit() for c in raw_url)
    ratio_digits_url = _safe_divide(digits_url, length_url)

    # ── 27. ratio_digits_host ───────────────────────────────────
    digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_host = _safe_divide(digits_host, length_hostname)

    # ── 28. punycode ── xn-- encoding = IDN homograph attack ────
    punycode = 1 if 'xn--' in hostname else 0

    # ── 29. port ── non-standard port used ──────────────────────
    standard_ports = {80, 443, 8080, 8443}
    port = 0
    if port_str and int(port_str) not in standard_ports:
        port = 1

    # ── 30. tld_in_path ─────────────────────────────────────────
    tld_in_path = 1 if any(t in path for t in COMMON_TLDS) else 0

    # ── 31. tld_in_subdomain ────────────────────────────────────
    subdomain_part = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    tld_in_subdomain = 1 if any(t.strip('.') in subdomain_part for t in COMMON_TLDS) else 0

    # ── 32. abnormal_subdomain ──────────────────────────────────
    # Flag if subdomain starts with 'srv','www2','host' pattern etc.
    abnormal_subdomain = 0
    if subdomain_part:
        if re.match(r'^(srv|www\d+|host\d+|static\d+|cdn\d+|mail\d+)', subdomain_part):
            abnormal_subdomain = 1

    # ── 33. nb_subdomains ───────────────────────────────────────
    nb_subdomains = max(0, len(parts) - 2)

    # ── 34. prefix_suffix ── dash in domain ─────────────────────
    prefix_suffix = 1 if '-' in domain_clean else 0

    # ── 35. random_domain ── high consonant ratio = random look ─
    consonants = sum(1 for c in domain_clean if c.isalpha() and c not in 'aeiou')
    alpha_count = sum(1 for c in domain_clean if c.isalpha())
    consonant_ratio = _safe_divide(consonants, alpha_count)
    random_domain = 1 if consonant_ratio > 0.6 and length_hostname > 10 else 0

    # ── 36. shortening_service ──────────────────────────────────
    shortening_service = 1 if any(s in full_url for s in SHORTENERS) else 0

    # ── 37. path_extension ── executable/script extension ───────
    path_extension = 0
    if any(path.endswith(ext) for ext in PHISH_EXTENSIONS):
        path_extension = 1

    # ── 38-39. nb_redirection / nb_external_redirection ─────────
    # Count // occurrences in path (redirect indicators)
    nb_redirection = path.count('//')
    nb_external_redirection = nb_redirection  # approximation without live fetch

    # ── 40-49. Word-based features ───────────────────────────────
    raw_text    = domain_clean + ' ' + path + ' ' + query
    host_text   = domain_clean
    path_text   = path

    wc_raw,  sw_raw,  lw_raw,  aw_raw  = _word_stats(raw_text)
    wc_host, sw_host, lw_host, aw_host = _word_stats(host_text)
    wc_path, sw_path, lw_path, aw_path = _word_stats(path_text)

    length_words_raw   = wc_raw
    char_repeat        = max((full_url.count(c) for c in set(full_url) if c.isalpha()), default=0)
    shortest_words_raw = sw_raw
    shortest_word_host = sw_host
    shortest_word_path = sw_path
    longest_words_raw  = lw_raw
    longest_word_host  = lw_host
    longest_word_path  = lw_path
    avg_words_raw      = aw_raw
    avg_word_host      = aw_host
    avg_word_path      = aw_path

    # ── 50. phish_hints ── count of phishing keywords ───────────
    phish_hints = sum(1 for kw in PHISH_HINTS if kw in full_url)

    # ── 51-54. Brand features ────────────────────────────────────
    brand_in_domain    = any(b in domain_clean.split('.')[0] for b in BRANDS)
    brand_in_sub       = any(b in subdomain_part for b in BRANDS) if subdomain_part else False
    brand_in_path_flag = any(b in path for b in BRANDS)

    domain_in_brand  = 1 if brand_in_domain else 0
    brand_in_subdomain = 1 if brand_in_sub else 0
    brand_in_path    = 1 if brand_in_path_flag else 0

    # ── 55. suspecious_tld ──────────────────────────────────────
    suspecious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # ── 56. statistical_report ── known in phishing DBs (approximated) ──
    # We approximate using strong structural signals
    statistical_report = 1 if (ip == 1 or shortening_service == 1 or punycode == 1) else 0

    # ────────────────────────────────────────────────────────────
    # Features 57-87: Page-content features
    # These require fetching the actual page (hyperlinks, CSS, iframes, etc.)
    # When only a URL is given, we use dataset-representative neutral values.
    # The structural features above carry the most predictive weight anyway
    # (google_index and page_rank are the top features but are set conservatively).
    # ────────────────────────────────────────────────────────────

    # Neutral/median values from dataset analysis
    nb_hyperlinks           = 30
    ratio_intHyperlinks     = 0.5
    ratio_extHyperlinks     = 0.1
    ratio_nullHyperlinks    = 0.0
    nb_extCSS               = 2
    ratio_intRedirection    = 0.0
    ratio_extRedirection    = 0.0
    ratio_intErrors         = 0.0
    ratio_extErrors         = 0.0
    login_form              = 1 if phish_hints > 0 else 0
    external_favicon        = 0
    links_in_tags           = 0.8
    submit_email            = 0
    ratio_intMedia          = 0.5
    ratio_extMedia          = 0.1
    sfh                     = 0         # server form handler
    iframe                  = 0
    popup_window            = 0
    safe_anchor             = 0.5
    onmouseover             = 0
    right_clic              = 0
    empty_title             = 0

    # domain_in_title: if brand matches domain, probably legit
    domain_in_title         = 1 if domain_in_brand == 0 else 0
    domain_with_copyright   = 1 if domain_in_brand == 0 else 0

    # WHOIS / registration (approximate from structural signals)
    # Phishing domains tend to be newly registered
    whois_registered_domain   = 0 if (suspecious_tld or random_domain) else 1
    domain_registration_length = 0 if (suspecious_tld or random_domain) else 1
    domain_age                = 0 if (ip or shortening_service or suspecious_tld) else 1

    # Traffic / index signals
    # Known brands likely indexed; suspicious domains likely not
    is_known_brand = any(b in hostname for b in BRANDS[:10])
    web_traffic    = 1 if is_known_brand else 0
    dns_record     = 0 if ip == 1 else 1
    google_index   = 1 if is_known_brand else (0 if (ip or suspecious_tld or random_domain) else 1)
    page_rank      = 1 if is_known_brand else (0 if (ip or suspecious_tld or shortening_service) else 0)

    # ── Assemble in exact training column order ─────────────────
    features = [
        length_url, length_hostname, ip, nb_dots, nb_hyphens, nb_at,
        nb_qm, nb_and, nb_or, nb_eq, nb_underscore, nb_tilde,
        nb_percent, nb_slash, nb_star, nb_colon, nb_comma,
        nb_semicolumn, nb_dollar, nb_space, nb_www, nb_com, nb_dslash,
        http_in_path, https_token, ratio_digits_url, ratio_digits_host,
        punycode, port, tld_in_path, tld_in_subdomain, abnormal_subdomain,
        nb_subdomains, prefix_suffix, random_domain, shortening_service,
        path_extension, nb_redirection, nb_external_redirection,
        length_words_raw, char_repeat, shortest_words_raw, shortest_word_host,
        shortest_word_path, longest_words_raw, longest_word_host,
        longest_word_path, avg_words_raw, avg_word_host, avg_word_path,
        phish_hints, domain_in_brand, brand_in_subdomain, brand_in_path,
        suspecious_tld, statistical_report, nb_hyperlinks,
        ratio_intHyperlinks, ratio_extHyperlinks, ratio_nullHyperlinks,
        nb_extCSS, ratio_intRedirection, ratio_extRedirection,
        ratio_intErrors, ratio_extErrors, login_form, external_favicon,
        links_in_tags, submit_email, ratio_intMedia, ratio_extMedia,
        sfh, iframe, popup_window, safe_anchor, onmouseover,
        right_clic, empty_title, domain_in_title, domain_with_copyright,
        whois_registered_domain, domain_registration_length, domain_age,
        web_traffic, dns_record, google_index, page_rank,
    ]

    # Return features + a readable dict for the UI breakdown
    feature_names = [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
        'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
        'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
        'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash',
        'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host',
        'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
        'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service',
        'path_extension', 'nb_redirection', 'nb_external_redirection',
        'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host',
        'shortest_word_path', 'longest_words_raw', 'longest_word_host',
        'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path',
        'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
        'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
        'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
        'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
        'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon',
        'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia',
        'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
        'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
        'whois_registered_domain', 'domain_registration_length', 'domain_age',
        'web_traffic', 'dns_record', 'google_index', 'page_rank',
    ]

    feature_dict = dict(zip(feature_names, features))
    return features, feature_dict
