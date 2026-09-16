import email

with open("sample_phish.eml", "r", encoding="utf-8") as f:
    msg = email.message_from_file(f)

    print("From:", msg["From"])
    print("Reply-To:", msg["Reply-To"])
    print("Subject:", msg["Subject"])
    print("Date:", msg["Date"])