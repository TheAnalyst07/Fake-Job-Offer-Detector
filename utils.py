import re
import whois
import tldextract
import nltk
import spacy
from textblob import TextBlob
from datetime import datetime
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from spacy.cli import download

# Ensure NLTK data is downloaded
nltk.download('punkt')
nltk.download('stopwords')

# Ensure spaCy model is loaded
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")


# 1. Check for suspicious keywords
def check_suspicious_keywords(text):
    keywords = ['deposit', 'payment', 'processing fee', 'urgent', 'refundable', 'security amount']
    found = [word for word in keywords if word in text.lower()]
    return found


# 2. Check domain age
def check_domain_age(email):
    domain = tldextract.extract(email).registered_domain
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days // 365
            return age
        else:
            return None
    except:
        return None


# 3. Check suspicious domain extensions
def check_domain_extension(email):
    suspicious_ext = ['.online', '.xyz', '.top', '.club', '.site', '.tech']
    ext = '.' + tldextract.extract(email).suffix
    return ext in suspicious_ext, ext


# 4. Check for spelling/grammar errors
def check_spelling_grammar(text):
    blob = TextBlob(text)
    errors = [word for word in blob.words if word.lower() not in set(stopwords.words('english')) and blob.correct() != blob]
    return errors


# 5. Check for shortened URLs
def check_shortened_urls(text):
    pattern = r"(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|buff\.ly)"
    return re.findall(pattern, text)


# 6. Named Entity Recognition (NER) — Detect Company/Org names
def perform_ner(text):
    doc = nlp(text)
    entities = [ent.text for ent in doc.ents if ent.label_ in ['ORG', 'PERSON', 'GPE']]
    return entities


# Final decision logic
def final_verdict(results):
    flags = 0

    if results['suspicious_keywords']:
        flags += 1
    if results['domain_age'] is not None and results['domain_age'] < 1:
        flags += 1
    if results['suspicious_extension'][0]:
        flags += 1
    if results['shortened_urls']:
        flags += 1

    if flags >= 2:
        return "Highly Suspicious / Possibly Fake"
    elif flags == 1:
        return "Suspicious - Needs Review"
    else:
        return "Looks Safe"


# Main analysis function
def analyze_email(sender, content):
    results = {}
    results['suspicious_keywords'] = check_suspicious_keywords(content)
    results['domain_age'] = check_domain_age(sender)
    results['suspicious_extension'] = check_domain_extension(sender)
    results['spelling_errors'] = check_spelling_grammar(content)
    results['shortened_urls'] = check_shortened_urls(content)
    results['named_entities'] = perform_ner(content)
    results['final_verdict'] = final_verdict(results)
    return results
