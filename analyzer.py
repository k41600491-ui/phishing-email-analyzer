import email

with open("sample_phish.eml", "r", encoding="utf-8") as f:
    msg = email.message_from_file(f)

    print("From:", msg["From"])
    print("Reply-To:", msg["Reply-To"])
    print("Subject:", msg["Subject"])
    print("Date:", msg["Date"])
    from email.utils import parseaddr
    from_name, from_addr = parseaddr(msg["From"])
    reply_name, reply_addr = parseaddr(msg["Reply-To"])
    from_domain = from_addr.split("@")[-1].lower()
    reply_domain = reply_addr.split("@")[-1].lower()

    print("\n-- Domain check ---")
    print("From Domain:", from_domain)
    print("Reply-To Domain:", reply_domain)
    if reply_domain and reply_domain != from_domain:
       print ("[!] MISMATCH: Reply-To domain differs from From domain - classic spoofing sign") 
    else:
        print("Domains match, or no Reply-To set")
    auth_results = msg["Authentication-Results"] or ""
    print("\n-- Authentication check ---")
    print("Raw header:", auth_results)
    spf_fail = "spf=fail" in auth_results.lower()
    dkim_fail = "dkim=fail" in auth_results.lower()
    dmarc_fail = "dmarc=fail" in auth_results.lower()

    fail_count = sum([spf_fail, dkim_fail, dmarc_fail])

    print("SPF fail:", spf_fail)
    print("DKIM fail:", dkim_fail)
    print("DMARC fail:", dmarc_fail)

    if fail_count >= 2:
        print("[!] Multiple authentication checks failed - strong phishing indicator")
    elif fail_count == 1:
            print("[!] One authentication check failed - worth a closer look")
    else:
            print("Authentication checks passed")
import re

body =msg.get_payload()

print("\n--- URL extraction ---")
urls = re.findall(r'href="(https?://[^"]+)"', body)
for url in urls:
    print("Found URL:", url)
suspicious_words = ["urgent", "verify", "suspended", "immediately", "24 hours", "limited", "act now"]
body_lower = body.lower()
found_words = [word for word in suspicious_words if word in body_lower]

print("\n--- urgency keyword check ---")
print("Suspicious words found:", found_words)

