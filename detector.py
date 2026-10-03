import os
import re
import json
import logging
import urllib.request
from urllib.parse import urlparse
from urlextract import URLExtract
from bs4 import BeautifulSoup

class PhishingDetector:
    def __init__(self):
        self.url_extractor = URLExtract()
        
        # Simple heuristic keywords commonly found in phishing attempts
        self.suspicious_keywords = [
            r"\burgent\b", r"\bverify your account\b", r"\bsuspended\b",
            r"\bpassword reset\b", r"\bunauthorized access\b", r"\bupdate your billing\b",
            r"\baction required\b", r"\bvalidate\b", r"\bimmediate action\b"
        ]

        # Dangerous attachment extensions
        self.dangerous_extensions = ('.exe', '.bat', '.vbs', '.js', '.scr', '.jar', '.cmd', '.iso', '.cab')

        # Get API key
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            logging.info("Gemini AI integration enabled (REST API mode).")
        else:
            logging.info("Running in Heuristics-only mode (No GEMINI_API_KEY found).")

    def _ai_analysis(self, sender: str, subject: str, text: str, urls: list) -> tuple[bool, list]:
        """Uses Gemini AI to analyze the email for social engineering and phishing."""
        if not self.api_key:
            return False, []

        prompt = f"""
        You are an expert cybersecurity phishing detector. 
        Analyze the following email and determine if it is a phishing attempt or social engineering attack.
        Be careful of false positives for legitimate automated emails (like real password resets).
        
        Sender: {sender}
        Subject: {subject}
        Extracted URLs: {urls}
        
        Email Content:
        {text[:3000]}
        
        Reply ONLY with a JSON object in this exact format:
        {{"is_phishing": true/false, "reasons": ["reason 1", "reason 2"]}}
        """
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                result_raw = json.loads(response.read().decode('utf-8'))
                
                # Check if candidates exist and have content
                if not result_raw.get('candidates') or not result_raw['candidates'][0].get('content'):
                    logging.warning(f"AI response blocked or empty. Raw API response: {result_raw}")
                    return False, ["AI Analysis blocked (likely safety filter)"]
                
                # Extract text from the Gemini REST response format
                text_resp = result_raw['candidates'][0]['content']['parts'][0]['text']
                result = json.loads(text_resp)
                return result.get("is_phishing", False), result.get("reasons", [])
        except Exception as e:
            logging.error(f"AI Analysis failed: {e}")
            return False, [f"AI Analysis error: {e}"]

    def analyze(self, sender: str, reply_to: str, subject: str, body_text: str, body_html: str, attachments: list = None, auth_headers: str = ""):
        """
        Analyzes the email contents and returns a tuple: (is_phishing: bool, reasons: list)
        """
        reasons = []
        score = 0
        attachments = attachments or []

        # Safely handle None values
        subject = subject or ""
        body_text = body_text or ""
        body_html = body_html or ""
        auth_headers = auth_headers.lower()

        # 1. Check for mismatched Sender and Reply-To
        if reply_to and sender != reply_to:
            reasons.append(f"Mismatched Sender ({sender}) and Reply-To ({reply_to})")
            score += 2

        # 2. Check for suspicious keywords in subject or body
        text_to_search = f"{subject} {body_text} {body_html}".lower()
        for keyword in self.suspicious_keywords:
            if re.search(keyword, text_to_search):
                reasons.append(f"Found suspicious keyword: '{keyword}'")
                score += 1

        # 3. Analyze URLs and check for Link Deception
        urls = []
        if body_text:
            urls.extend(self.url_extractor.find_urls(body_text))
        if body_html:
            soup = BeautifulSoup(body_html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                urls.append(href)
                
                # Link Deception Check
                link_text = a.get_text(strip=True).lower()
                # If the visible text looks like a URL (contains a dot, no spaces)
                if '.' in link_text and ' ' not in link_text:
                    try:
                        href_domain = urlparse(href if href.startswith('http') else 'http://' + href).netloc.split(':')[0]
                        text_domain = urlparse(link_text if link_text.startswith('http') else 'http://' + link_text).netloc.split(':')[0]
                        
                        # If both resolved domains and they don't match (one isn't a substring of the other)
                        if text_domain and href_domain and text_domain not in href_domain and href_domain not in text_domain:
                            reasons.append(f"Link Deception: Text says '{text_domain}' but link silently redirects to '{href_domain}'")
                            score += 4
                    except Exception:
                        pass

        for url in set(urls):
            try:
                # Ensure the url has a scheme so urlparse parses the netloc correctly
                if not url.startswith(('http://', 'https://')):
                    parsed = urlparse('http://' + url)
                else:
                    parsed = urlparse(url)
                
                # Check for IP address instead of domain in URL (ignoring ports)
                netloc_no_port = parsed.netloc.split(':')[0]
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc_no_port):
                    reasons.append(f"URL uses IP address instead of domain: {url}")
                    score += 3
                # Check for excessively long subdomains
                elif netloc_no_port.count('.') > 3:
                    reasons.append(f"URL has excessive subdomains: {url}")
                    score += 2
            except Exception:
                pass

        # 4. Analyze Attachments
        for filename in attachments:
            filename_lower = filename.lower()
            # Check for double extensions (e.g., invoice.pdf.exe)
            parts = filename_lower.split('.')
            if len(parts) >= 3 and parts[-1] in ('exe', 'scr', 'vbs', 'bat', 'cmd', 'js'):
                reasons.append(f"Suspicious double extension on attachment: {filename}")
                score += 4
            # Check for explicitly dangerous executable extensions
            elif filename_lower.endswith(self.dangerous_extensions):
                reasons.append(f"Dangerous attachment type: {filename}")
                score += 4

        # 5. Check Sender Authentication (SPF/DKIM/DMARC)
        if 'spf=fail' in auth_headers or 'spf=softfail' in auth_headers:
            reasons.append("Sender authentication failed (SPF FAIL). The sender is likely spoofed.")
            score += 4
        if 'dkim=fail' in auth_headers:
            reasons.append("Sender authentication failed (DKIM FAIL). The sender is likely spoofed.")
            score += 4
        if 'dmarc=fail' in auth_headers:
            reasons.append("Sender authentication failed (DMARC FAIL). The sender is likely spoofed.")
            score += 4

        is_phishing_heuristic = score >= 3

        # 6. AI Analysis (if enabled)
        if self.api_key:
            # Get the best available text for the AI
            clean_text = body_text
            if not clean_text and body_html:
                clean_text = BeautifulSoup(body_html, 'html.parser').get_text(separator=' ', strip=True)
            
            # Feed attachment info to the AI context as well
            if attachments:
                clean_text += f"\n\n[Attached Files: {', '.join(attachments)}]"
                
            ai_is_phishing, ai_reasons = self._ai_analysis(sender, subject, clean_text, list(set(urls)))
            
            # If AI says it's phishing, we trust it. 
            # If heuristics say phishing but AI says safe, we trust AI (reduces false positives).
            if ai_is_phishing:
                return True, reasons + ai_reasons
            else:
                # AI overrides heuristics and clears it
                if is_phishing_heuristic:
                    logging.info(f"AI overruled heuristics. Marked safe. Heuristic reasons were: {reasons}")
                return False, []

        return is_phishing_heuristic, reasons
