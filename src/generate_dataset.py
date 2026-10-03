"""
Dataset Generator for Phishing URL Detection.

Creates a balanced dataset of realistic legitimate and phishing URLs for machine learning model training.
All generated URLs are safe strings created for research purposes.
"""

import os
import random
import pandas as pd

LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'reddit.com', 'microsoft.com', 'github.com', 'apple.com', 'twitter.com',
    'linkedin.com', 'netflix.com', 'stackoverlow.com', 'medium.com', 'nytimes.com',
    'coursera.org', 'mit.edu', 'stanford.edu', 'mozilla.org', 'w3schools.com',
    'python.org', 'tensorflow.org', 'scikit-learn.org', 'huggingface.co', 'kaggle.com',
    'cloudflare.com', 'github.io', 'pypi.org', 'docker.com', 'ubuntu.com',
    'adobe.com', 'zoom.us', 'quora.com', 'spotify.com', 'bbc.com',
    'cnn.com', 'dropbox.com', 'salesforce.com', 'atlassian.com', 'notion.so'
]

LEGITIMATE_PATHS = [
    '', '/', '/search?q=machine+learning', '/docs/latest/index.html', '/about-us',
    '/contact', '/blog/2026/02/updates', '/profile/settings', '/projects/phishing-detector',
    '/products/category/item?id=4920', '/api/v1/health', '/en-us/download',
    '/help/article/10492', '/terms-of-service', '/privacy-policy', '/news/technology'
]

PHISHING_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'chase',
    'wellsfargo', 'bankofamerica', 'secure-bank', 'instagram', 'facebook',
    'binance', 'coinbase', 'metamask', 'outlook', 'yahoo', 'support-apple'
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify-account', 'update-password', 'secure-auth',
    'confirm-identity', 'billing-update', 'account-suspended', 'urgent-action',
    'claim-reward', 'bonus-payout', 'verify-wallet', 'security-center'
]

TLDS = ['.com', '.net', '.org', '.info', '.xyz', '.online', '.site', '.club', '.top', '.ru', '.cn']


def generate_legitimate_urls(count: int = 1500) -> list:
    urls = []
    for _ in range(count):
        domain = random.choice(LEGITIMATE_DOMAINS)
        path = random.choice(LEGITIMATE_PATHS)
        protocol = 'https://' if random.random() > 0.1 else 'http://'
        subdomain = ''
        if random.random() < 0.2:
            subdomain = random.choice(['www.', 'blog.', 'docs.', 'api.', 'dev.'])
        
        url = f"{protocol}{subdomain}{domain}{path}"
        urls.append((url, 0))
    return urls


def generate_phishing_urls(count: int = 1500) -> list:
    urls = []
    for _ in range(count):
        strategy = random.choice(['ip', 'brand_subdomain', 'typo_keyword', 'shortener', 'excessive_dashes', 'at_redirect'])
        
        if strategy == 'ip':
            ip_str = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            kw = random.choice(PHISHING_KEYWORDS)
            url = f"http://{ip_str}/{kw}/login.php?id={random.randint(1000, 9999)}"

        elif strategy == 'brand_subdomain':
            brand = random.choice(PHISHING_BRANDS)
            kw = random.choice(PHISHING_KEYWORDS)
            fake_domain = f"{brand}-{kw}"
            tld = random.choice(TLDS)
            sub1 = random.choice(['secure', 'account', 'auth', 'login', 'service'])
            sub2 = random.choice(['verify', 'portal', 'update', 'my'])
            url = f"https://{sub1}.{sub2}.{fake_domain}{tld}/index.html?ref={random.randint(100, 999)}"

        elif strategy == 'typo_keyword':
            brand = random.choice(PHISHING_BRANDS)
            kw = random.choice(PHISHING_KEYWORDS)
            tld = random.choice(['.xyz', '.info', '.site', '.online', '.top'])
            # Typosquatting e.g. paypa1-security-update.xyz
            typo_brand = brand.replace('l', '1').replace('o', '0').replace('e', '3')
            url = f"http://{typo_brand}-{kw}{tld}/webmail/login?user_token={random.randint(10000, 99999)}"

        elif strategy == 'shortener':
            shortener = random.choice(['bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly'])
            token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=7))
            url = f"http://{shortener}/{token}?verify={random.choice(PHISHING_BRANDS)}"

        elif strategy == 'excessive_dashes':
            brand = random.choice(PHISHING_BRANDS)
            url = f"https://www-{brand}-security-account-verification-portal-service.com/login"

        elif strategy == 'at_redirect':
            legit = random.choice(LEGITIMATE_DOMAINS)
            brand = random.choice(PHISHING_BRANDS)
            url = f"http://{legit}@{brand}-verify-update.info/login.php"

        urls.append((url, 1))
    return urls


def create_dataset(output_path: str = 'data/raw/phishing_dataset.csv', samples_per_class: int = 1500):
    """
    Generates and saves dataset CSV.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    legit_data = generate_legitimate_urls(samples_per_class)
    phish_data = generate_phishing_urls(samples_per_class)
    
    combined = legit_data + phish_data
    random.shuffle(combined)
    
    df = pd.DataFrame(combined, columns=['url', 'label'])
    df.to_csv(output_path, index=False)
    print(f"[+] Dataset successfully created at '{output_path}' with {len(df)} rows.")
    print(f"    - Safe URLs (0): {sum(df['label'] == 0)}")
    print(f"    - Phishing URLs (1): {sum(df['label'] == 1)}")
    return df


if __name__ == '__main__':
    create_dataset()
