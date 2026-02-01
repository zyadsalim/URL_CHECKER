#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URL Security Checker (Cybersecurity Project)
--------------------------------------------
أداة لفحص الروابط مع رسائل ملونة لواجهة CLI احترافية
"""

import requests
import time
import argparse
from urllib.parse import urlparse
from colorama import Fore, Style, init

# تفعيل دعم الألوان
init(autoreset=True)

def banner():
    """طباعة شكل ترحيبي عند فتح الأداة"""
    print(Fore.CYAN + r"""
========================================
   ____  _   _ _      ____              
  |  _ \| | | | |    / ___|  ___  _ __  
  | |_) | | | | |   | |  _  / _ \| '_ \ 
  |  __/| |_| | |___| |_| | (_) | | | |
  |_|    \___/|_____|____|\___/|_| |_|
----------------------------------------
   URL Security Checker - Cybersecurity
          Developer:ABO_SALIM
========================================
    """ + Style.RESET_ALL)

def quick_check(url: str) -> str:
    """
    Perform a security check on the given URL.
    Returns: str (report)
    """
    output = []
    output.append(Fore.YELLOW + "[*] Please wait, checking the URL...\n" + Style.RESET_ALL)
    time.sleep(1)

    # إضافة https إذا لم يكن موجود
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # تحليل الرابط
    parsed = urlparse(url)
    domain = parsed.netloc
    protocol = parsed.scheme

    if not domain:
        return Fore.RED + "[X] Invalid input, not a valid URL!" + Style.RESET_ALL

    # التحقق من أن الموقع يعمل فعلاً
    try:
        response = requests.head(url, allow_redirects=True, timeout=15)
        if response.status_code >= 400:
            return Fore.RED + f"[X] URL not reachable (Status: {response.status_code})" + Style.RESET_ALL
    except requests.exceptions.Timeout:
        return Fore.RED + "[X] Connection timed out!" + Style.RESET_ALL
    except requests.exceptions.SSLError:
        return Fore.RED + "[X] SSL Certificate error!" + Style.RESET_ALL
    except requests.exceptions.RequestException as e:
        return Fore.RED + f"[X] Request error: {e}" + Style.RESET_ALL

    # إذا وصلنا هنا، الرابط صالح ويعمل
    output.append(Fore.GREEN + "[+] Basic Information" + Style.RESET_ALL)
    output.append("----------------------------------------")
    output.append(f"URL      : {url}")
    output.append(f"Domain   : {domain}")
    output.append(f"Protocol : {protocol}\n")

    # كلمات مشبوهة
    suspicious_words = ['login','verify','bank','paypal','secure',
                        'account','update','confirm','password']
    found = [w for w in suspicious_words if w in url.lower()]

    output.append(Fore.GREEN + "[+] Suspicious Words Check" + Style.RESET_ALL)
    output.append("----------------------------------------")
    if found:
        output.append(Fore.RED + f"[!] Found suspicious words: {', '.join(found)}" + Style.RESET_ALL)
    else:
        output.append(Fore.GREEN + "[OK] No suspicious words detected" + Style.RESET_ALL)
    output.append("")

    # روابط مختصرة
    short_services = ['bit.ly','tinyurl.com','goo.gl','t.co']
    short_detected = any(s in domain for s in short_services)

    output.append(Fore.GREEN + "[+] Short URL Check" + Style.RESET_ALL)
    output.append("----------------------------------------")
    if short_detected:
        output.append(Fore.RED + "[!] Shortened URL detected" + Style.RESET_ALL)
    else:
        output.append(Fore.GREEN + "[OK] Not a shortened URL" + Style.RESET_ALL)
    output.append("")

    # حساب درجة الأمان
    score = 100
    if protocol != "https": score -= 30
    if len(url) > 100: score -= 15
    if found: score -= 10
    if short_detected: score -= 20

    if score >= 80:
        level = Fore.GREEN + "Safe" + Style.RESET_ALL
        recommendation = "You can use this link."
    elif score >= 60:
        level = Fore.YELLOW + "Moderate" + Style.RESET_ALL
        recommendation = "Use with caution."
    elif score >= 40:
        level = Fore.RED + "Risky" + Style.RESET_ALL
        recommendation = "Better not to use."
    else:
        level = Fore.RED + "Dangerous" + Style.RESET_ALL
        recommendation = "Avoid completely."

    output.append(Fore.GREEN + "[+] Final Report" + Style.RESET_ALL)
    output.append("----------------------------------------")
    output.append(f"Score         : {score}/100")
    output.append(f"Security Level: {level}")
    output.append(f"Recommendation: {recommendation}")
    output.append(Fore.CYAN + "========================================\n" + Style.RESET_ALL)

    # ملخص العمليات
    output.append(Fore.YELLOW + "[*] Operations performed:" + Style.RESET_ALL)
    output.append(" - Verified URL format and domain")
    output.append(" - Checked if website is reachable")
    output.append(" - Parsed domain and protocol")
    output.append(" - Searched for suspicious words")
    output.append(" - Checked if URL is shortened")
    output.append(" - Calculated security score and recommendation")
    output.append(Fore.GREEN + "\n[OK] URL check completed!\n" + Style.RESET_ALL)

    return "\n".join(output)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Classic-style URL Security Checker")
    parser.add_argument("url", help="Enter the URL to check")
    parser.add_argument("-o", "--output", help="Save report to file", default=None)
    args = parser.parse_args()

    report = quick_check(args.url)
    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(Fore.GREEN + f"[+] Report saved to {args.output}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()