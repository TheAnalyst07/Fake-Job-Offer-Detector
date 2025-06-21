import re
import tldextract
from textblob import TextBlob
import whois
import requests
import spacy

nlp = spacy.load("en_core_web_sm")

def detect_spam_words(text):
    spam_keywords = ["urgent", "deposit", "refundable", "click here", "limited time", "account", "verify", "payment", "transfer"]
    return [word for word in spam_keywords if word.lower() in text.lower()]

def detect_suspicious_domain(email):
    ext = tldextract.extract(email)
    suspicious_tlds = ['xyz', 'top', 'online', 'click', 'work', 'buzz']
    return ext.suffix if ext.suffix in suspicious_tlds else None

def detect_shortened_urls(text):
    url_pattern = r'https?://(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|rebrand\.ly|is\.gd|shorte\.st|cutt\.ly)/\S+'
    return re.findall(url_pattern, text)

def grammar_and_spelling_check(text):
    blob = TextBlob(text)
    return str(blob.correct())

def check_domain_age(email):
    ext = tldextract.extract(email)
    domain = ext.domain + '.' + ext.suffix
    try:
        w = whois.whois(domain)
        return w.creation_date
    except:
        return None

def check_url_virustotal(url):
    api_key = '642ab41fa7b1f2a9e2f0794ccd95da0da16b1bfff67d5ccc3b70faff23923c6f_KEY'  # Replace with your VirusTotal API Key
    params = {'apikey': api_key, 'resource': url}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        result = response.json()
        if result.get('positives', 0) > 0:
            return True
    except:
        pass
    return False

def extract_entities(text):
    doc = nlp(text)
    return [(ent.text, ent.label_) for ent in doc.ents if ent.label_ == "ORG"]

def detect_salary_outlier(text):
    matches = re.findall(r'\b\d{5,}\b', text)
    amounts = [int(num) for num in matches]
    return [amt for amt in amounts if amt > 1000000]

def detect_suspicious_attachments(text):
    suspicious_ext = ['.exe', '.zip', '.bat']
    return [ext for ext in suspicious_ext if ext in text.lower()]
