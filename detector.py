import requests
from bs4 import BeautifulSoup
import whois
import datetime
from urllib.parse import urlparse
import re
import ipaddress

# Constants
BAD_WORDS = [
    "login", "signin", "verify", "account", "password", "secure", "update",
    "bank", "paypal", "alert", "confirm", "ebay", "security", "limited"
]

SHORT_SITES = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']

# Scoring values
AGE_SCORE = 30
SHORT_LINK_SCORE = 15
TITLE_BAD_SCORE = 20
BODY_BAD_SCORE = 20
FORM_COUNT_SCORE = 15
AT_SIGN_SCORE = 10
DOTS_SCORE = 10
LONG_LINK_SCORE = 10
NO_HTTPS_SCORE = 15
FORM_OUTSIDE_SCORE = 20
IP_SCORE = 20

def get_website_name(link):
    """
    Extracts and returns the domain name from a URL without 'www.' prefix.
    """
    parts = urlparse(link)
    return parts.netloc.replace("www.", "")

def is_short_link(link):
    """
    Checks if the URL is from a known link shortener.
    """
    site = urlparse(link).netloc
    return site in SHORT_SITES

def website_age(name):
    """
    Returns the age of the website in months based on WHOIS creation date.
    Returns None if unable to determine.
    """
    try:
        info = whois.whois(name)
        made_on = info.creation_date
        if isinstance(made_on, list):
            made_on = made_on[0]
        if made_on:
            now = datetime.datetime.now()
            age = now - made_on
            return age.days // 30  # convert days to months
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        return None

def get_html(link):
    """
    Downloads and returns the HTML content of the given URL.
    Returns None on failure.
    """
    try:
        reply = requests.get(link, timeout=10)
        reply.raise_for_status()
        return reply.text
    except requests.exceptions.RequestException as e:
        print(f"Failed to get HTML: {e}")
        return None

def look_inside_page(html):
    """
    Parses HTML to get the page title and all forms on the page.
    Returns a tuple (title, list_of_forms).
    """
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string if soup.title else "No Title"
    forms = soup.find_all("form")
    return title, forms

def find_bad_words(html, title):
    """
    Checks if any bad phishing-related words appear in the title or body.
    Returns two booleans: (title_bad, body_bad).
    """
    title_bad = any(word in title.lower() for word in BAD_WORDS)
    body_bad = any(word in html.lower() for word in BAD_WORDS)
    return title_bad, body_bad

def has_at_sign(link):
    """
    Returns True if '@' character is found in the URL.
    """
    return '@' in link

def dot_count(link):
    """
    Returns the number of dots in the domain name.
    """
    return urlparse(link).netloc.count('.')

def is_link_very_long(link):
    """
    Returns True if the URL length exceeds 75 characters.
    """
    return len(link) > 75

def uses_lock(link):
    """
    Returns True if the URL uses HTTPS.
    """
    return link.startswith("https://")

def forms_send_outside(forms, my_site):
    """
    Checks if any form on the page sends data to an external site.
    Returns True if any form action attribute points outside my_site.
    """
    for f in forms:
        action = f.get('action')
        if action and my_site not in action:
            return True
    return False

def has_ip(link):
    """
    Checks if the domain is an IP address instead of a domain name.
    """
    netloc = urlparse(link).netloc.split(':')[0]  # remove port if any
    try:
        ipaddress.ip_address(netloc)
        return True
    except ValueError:
        return False

def get_score(info):
    """
    Calculates and returns a phishing suspicion score based on checks.
    Higher score means higher chance of phishing.
    """
    score = 0
    if info.get("age") is not None and info.get("age") < 6:
        score += AGE_SCORE
    if info.get("short", False):
        score += SHORT_LINK_SCORE
    if info.get("title_bad", False):
        score += TITLE_BAD_SCORE
    if info.get("body_bad", False):
        score += BODY_BAD_SCORE
    if info.get("form_count", 0) > 0:
        score += FORM_COUNT_SCORE
    if info.get("at", False):
        score += AT_SIGN_SCORE
    if info.get("dots", 0) > 3:
        score += DOTS_SCORE
    if info.get("long", False):
        score += LONG_LINK_SCORE
    if not info.get("https", True):
        score += NO_HTTPS_SCORE
    if info.get("form_outside", False):
        score += FORM_OUTSIDE_SCORE
    if info.get("ip", False):
        score += IP_SCORE
    return score
