from utils import detect_spam_words, detect_suspicious_domain, detect_shortened_urls, grammar_and_spelling_check

def main():
    print("===== FAKE JOB OFFER EMAIL DETECTOR =====")
    email_text = input("\nPaste the email text here:\n")
    sender_email = input("\nEnter the sender's email address:\n")

    score = 0

    # Spam Word Check
    spam_words = detect_spam_words(email_text)
    if spam_words:
        print("\n⚠️ Spam words detected:", spam_words)
        score += 2
    else:
        print("\nNo spam words detected.")

    # Domain Check
    domain = detect_suspicious_domain(sender_email)
    if domain:
        print("\n⚠️ Suspicious domain detected: ." + domain)
        score += 2
    else:
        print("\nDomain looks normal.")

    # Shortened URL Check
    urls = detect_shortened_urls(email_text)
    if urls:
        print("\n⚠️ Shortened URLs detected:", urls)
        score += 1
    else:
        print("\nNo suspicious URLs found.")

    # Grammar Check
    print("\nSpelling/Grammar Suggestions:\n")
    print(grammar_and_spelling_check(email_text))

    # Final Verdict
    print("\n===== FINAL VERDICT =====")
    if score >= 4:
        print("🚫 Verdict: Likely FAKE email!")
    elif score >= 2:
        print("⚠️ Verdict: Suspicious email!")
    else:
        print("✅ Verdict: Looks Safe!")

if __name__ == "__main__":
    main()
