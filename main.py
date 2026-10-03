import os
import time
import logging
from dotenv import load_dotenv
from imap_tools import MailBox, A
from detector import PhishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    load_dotenv()
    
    server = os.getenv('IMAP_SERVER', 'imap.gmail.com')
    account = os.getenv('EMAIL_ACCOUNT')
    password = os.getenv('EMAIL_PASSWORD')
    interval_str = os.getenv('CHECK_INTERVAL_SECONDS', '300')
    quarantine_folder = os.getenv('QUARANTINE_FOLDER', 'Quarantine')

    if not all([server, account, password]):
        logging.error("Missing IMAP credentials! Please copy .env.example to .env and fill in your details.")
        return

    try:
        interval = int(interval_str)
    except ValueError:
        logging.error("CHECK_INTERVAL_SECONDS must be an integer.")
        return

    detector = PhishingDetector()
    
    logging.info(f"Starting continuous phishing detector for {account}")
    logging.info(f"Checking IMAP server '{server}' every {interval} seconds...")

    while True:
        try:
            with MailBox(server).login(account, password) as mailbox:
                # Attempt to create the quarantine folder if it doesn't exist
                if not mailbox.folder.exists(quarantine_folder):
                    logging.warning(f"Quarantine folder '{quarantine_folder}' does not exist. Attempting to create it.")
                    mailbox.folder.create(quarantine_folder)

                # Fetch UNSEEN emails
                # mark_seen=False ensures we don't automatically mark them as read just by looking at them
                unseen_emails = list(mailbox.fetch(A(seen=False), mark_seen=False))
                
                for msg in unseen_emails:
                    try:
                        logging.info(f"Analyzing email: '{msg.subject}' from {msg.from_}")
                        
                        reply_to = msg.reply_to[0] if msg.reply_to else ""
                        
                        # Extract attachment names
                        attachment_names = [att.filename for att in msg.attachments if att.filename]
                        
                        # Extract Authentication headers (SPF, DKIM, DMARC)
                        auth_results = msg.headers.get('authentication-results', ())
                        auth_str = " ".join(auth_results) if isinstance(auth_results, tuple) else str(auth_results)
                        
                        is_phishing, reasons = detector.analyze(
                            sender=msg.from_,
                            reply_to=reply_to,
                            subject=msg.subject,
                            body_text=msg.text,
                            body_html=msg.html,
                            attachments=attachment_names,
                            auth_headers=auth_str
                        )

                        if is_phishing:
                            logging.warning(f"[PHISHING DETECTED] Subject: '{msg.subject}'")
                            for reason in reasons:
                                logging.warning(f"  -> Reason: {reason}")
                            
                            logging.info(f"Moving to {quarantine_folder} folder...")
                            mailbox.move(msg.uid, quarantine_folder)
                        else:
                            logging.info(f"[SAFE] Subject: '{msg.subject}'")
                            # Mark safe emails as seen so we don't process them again
                            mailbox.flag(msg.uid, '\\Seen', True)
                    except Exception as msg_e:
                        logging.error(f"Error processing message UID {msg.uid}: {msg_e}")
                        # Flag as seen to prevent infinite retry loop on this specific 'poison' message
                        try:
                            mailbox.flag(msg.uid, '\\Seen', True)
                        except:
                            pass

        except Exception as e:
            logging.error(f"Error checking email: {e}")
        
        logging.info(f"Sleeping for {interval} seconds before the next check...")
        time.sleep(interval)

if __name__ == "__main__":
    main()
