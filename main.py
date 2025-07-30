import sys
from detector import (
    get_website_name, is_short_link, website_age, get_html, look_inside_page,
    find_bad_words, has_at_sign, dot_count, is_link_very_long,
    uses_lock, forms_send_outside, has_ip, get_score
)
from report import save_report_txt, save_report_json, append_report_csv

def banner():
    print("\n" + "="*40)
    print("    🔍 PHISHING DETECTION TOOL  🔒")
    print("="*40 + "\n")

def get_result(score):
    if score >= 70:
        return "⚠️ PHISHING — This site is highly suspicious!"
    elif score >= 40:
        return "⚠️ SUSPICIOUS — Be cautious. Some red flags found."
    return "✅ SAFE — No major phishing indicators found."

def get_url():
    url = input("🌐 Enter the URL to analyze: ").strip()
    if not url:
        print("[!] You didn't type anything. Please try again.\n")
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def analyze_url(url):
    print("\n🔎 Starting analysis...\n")
    domain = get_website_name(url)
    print(f"📌 Domain Name: {domain}")

    age = website_age(domain)
    print(f"📅 Domain Age: {age} month(s)" if age else "📅 Domain Age: N/A")

    short = is_short_link(url)
    print(f"🔗 Is Shortened Link: {'Yes' if short else 'No'}")

    html = get_html(url)
    if not html:
        print("[!] Failed to fetch the page. Cannot analyze further.\n")
        return None

    title, forms = look_inside_page(html)
    print(f"📝 Page Title: {title}")
    print(f"🧾 Number of Forms: {len(forms)}")

    sus_title, sus_body = find_bad_words(html, title)
    if sus_title: print("🚨 Suspicious words found in title!")
    if sus_body: print("🚨 Suspicious content found in body!")

    at_symbol = has_at_sign(url)
    dots = dot_count(url)
    long_url = is_link_very_long(url)
    https = uses_lock(url)
    ext_form = forms_send_outside(forms, domain)
    ip_found = has_ip(url)

    print("\n🌐 URL Structure Checks:")
    print(f"   • Contains '@' symbol: {'Yes' if at_symbol else 'No'}")
    print(f"   • Number of '.' in URL: {dots}")
    print(f"   • URL Length > 75 chars: {'Yes' if long_url else 'No'}")
    print(f"   • Uses HTTPS (Secure): {'Yes 🔒' if https else 'No ❌'}")
    print(f"   • Form sends data outside domain: {'Yes' if ext_form else 'No'}")
    print(f"   • IP Address used in URL: {'Yes' if ip_found else 'No'}")

    data = {
        "age": age if age else 0,
        "short": short,
        "title_bad": sus_title,
        "body_bad": sus_body,
        "form_count": len(forms),
        "at": at_symbol,
        "dots": dots,
        "long": long_url,
        "https": https,
        "form_outside": ext_form,
        "ip": ip_found
    }

    return data

def main():
    print("\nWelcome to your Cybersecurity Sidekick 🛡️\n")

    while True:
        banner()
        print("Menu:")
        print("1️⃣  Analyze a Website URL")
        print("2️⃣  Exit\n")

        choice = input("👉 Enter your choice: ").strip()

        if choice == '1':
            url = get_url()
            if not url:
                continue

            data = analyze_url(url)
            if not data:
                continue

            score = get_score(data)
            result = get_result(score)

68            print("\n" + "="*40)
            print(f"🧠 Phishing Score: {score} / 100")
            print(f"📊 Result: {result}")
            print("="*40 + "\n")

            try:
                save_report_txt(data, url, score, result)
                save_report_json(data, url, score, result)
                append_report_csv(data, url, score, result)
                print("💾 Report saved in TXT, JSON, and CSV formats.\n")
            except Exception as e:
                print(f"[!] Error saving report: {e}\n")

        elif choice == '2':
            print("👋 Goodbye! Stay safe online.")
            sys.exit()

        else:
            print("[!] Invalid input. Please enter 1 or 2 only.\n")

if __name__ == "__main__":
    main()
