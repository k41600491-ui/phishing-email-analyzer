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
        