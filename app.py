import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import imaplib
import email
from email.header import decode_header
import time
import threading
import pickle
import numpy as np
import os
import sys
import re
import requests
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from plyer import notification

class PhishingEmailDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DetectAlone - Email Security Monitor")
        self.root.geometry("800x750")
        self.root.configure(bg="#525252")
        self.root.resizable(False, False)
        
        # Set window icon (replace with your actual icon path)
        try:
            self.root.iconbitmap("favicon (1).ico")
        except:
            pass

        # Modern dark color scheme
        self.colors = {
            "primary": "#286BB8",  # Purple accent
            "primary_variant": "#3700B3",
            "secondary": "#03DAC6",  # Teal accent
            "background": "#121212",
            "surface": "#1E1E1E",
            "error": "#CF6679",
            "on_primary": "#000000",
            "on_secondary": "#000000",
            "on_background": "#FFFFFF",
            "on_surface": "#FFFFFF",
            "on_error": "#000000",
            "text_primary": "white",
            "text_secondary": "#B3B3B3",
            "card": "#2A2A2A"
        }

        # Modern fonts
        self.fonts = {
            "header": ("Segoe UI", 24, "bold"),
            "subheader": ("Segoe UI", 14),
            "label": ("Segoe UI Semibold", 11),
            "entry": ("Segoe UI", 11),
            "button": ("Segoe UI Semibold", 12),
            "status": ("Segoe UI", 10),
            "small": ("Segoe UI", 9)
        }

        # Create main container with subtle shadow effect
        self.main_container = tk.Frame(root, bg=self.colors["background"], padx=0, pady=0)
        self.main_container.pack(expand=True, fill="both", padx=20, pady=20)

        # Main frame with dark surface
        self.main_frame = tk.Frame(self.main_container, bg=self.colors["surface"], padx=40, pady=40)
        self.main_frame.pack(expand=True, fill="both")

        # Header section
        self.create_header()
        
        # Form section
        self.create_form()
        
        # Status section
        self.create_status()

        # Load model and tokenizer
        self.load_models()

        # Initialize variables
        self.imap = None
        self.running = False
        self.checked_uids = set()
        self.highest_uid = 0
        self.google_safe_browsing_api_key = "AIzaSyCgx2iyBf9rnTwZlNVTQ55yxC0tAwTtQvA"  # Placeholder for API key

    def create_header(self):
        """Create the modern header section with logo and title"""
        header_frame = tk.Frame(self.main_frame, bg=self.colors["surface"])
        header_frame.pack(fill="x", pady=(0, 30))

        # Logo and title container
        title_container = tk.Frame(header_frame, bg=self.colors["surface"])
        title_container.pack(fill="x", expand=True)
        title_container.pack_configure(anchor="center")

        # Modern logo with accent color
        self.logo = tk.Label(title_container, text="👑", font=("Segoe UI", 40), 
                           bg=self.colors["surface"], fg=self.colors["error"])
        self.logo.pack(side="left", padx=(5, 5))

        # Title and subtitle with better spacing
        title_text_container = tk.Frame(title_container, bg=self.colors["surface"])
        title_text_container.pack(side="left")

        tk.Label(title_text_container, text="DetectAlone", font=self.fonts["header"], 
                bg=self.colors["surface"], fg=self.colors["text_primary"]).pack(pady=(10, 0))

        tk.Label(title_text_container, text="Real-time Phishing Email Detection", font=self.fonts["subheader"], 
                bg=self.colors["surface"], fg=self.colors["text_secondary"]).pack()

    def create_form(self):
        """Create the modern form section with email and password fields"""
        form_frame = tk.Frame(self.main_frame, bg=self.colors["surface"])
        form_frame.pack(fill="x", pady=(0, 30))

        # Card-like container for form elements
        form_card = tk.Frame(form_frame, bg=self.colors["card"], padx=25, pady=25)
        form_card.pack(fill="x")

        # Email field with modern styling
        email_frame = tk.Frame(form_card, bg=self.colors["card"])
        email_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(email_frame, text="EMAIL ADDRESS", font=self.fonts["label"], 
                bg=self.colors["card"], fg=self.colors["text_secondary"]).pack(anchor="w")
        
        self.email_entry = tk.Entry(email_frame, font=self.fonts["entry"], 
                                  bg=self.colors["card"], fg=self.colors["text_primary"],
                                  relief="flat", highlightthickness=1, 
                                  highlightcolor=self.colors["primary"],
                                  highlightbackground="#444", 
                                  insertbackground=self.colors["primary"])
        self.email_entry.pack(fill="x", ipady=8)
        self.email_entry.insert(0, "your.email@example.com")
        self.email_entry.bind("<FocusIn>", lambda e: self._clear_placeholder(e, "your.email@example.com"))
        self.email_entry.bind("<FocusOut>", lambda e: self._add_placeholder(e, "your.email@example.com"))

        # Password field with modern styling
        password_frame = tk.Frame(form_card, bg=self.colors["card"])
        password_frame.pack(fill="x", pady=(0, 30))
        
        tk.Label(password_frame, text="PASSWORD", font=self.fonts["label"], 
                bg=self.colors["card"], fg=self.colors["text_secondary"]).pack(anchor="w")
        
        self.password_entry = tk.Entry(password_frame, font=self.fonts["entry"], 
                                      bg=self.colors["card"], fg=self.colors["text_primary"], show="*",
                                      relief="flat", highlightthickness=1, 
                                      highlightcolor=self.colors["primary"],
                                      highlightbackground="#444", 
                                      insertbackground=self.colors["primary"])
        self.password_entry.pack(fill="x", ipady=8)
        self.password_entry.insert(0, "password")
        self.password_entry.bind("<FocusIn>", lambda e: self._clear_placeholder(e, "password", is_password=True))
        self.password_entry.bind("<FocusOut>", lambda e: self._add_placeholder(e, "password", is_password=True))

        # Modern buttons with better spacing
        button_frame = tk.Frame(form_card, bg=self.colors["card"])
        button_frame.pack(fill="x", pady=(10, 0))

        self.start_button = tk.Button(button_frame, text="START MONITORING", 
                                    command=self.start_detection, 
                                    bg=self.colors["primary"], 
                                    fg=self.colors["on_primary"], 
                                    activebackground="#9a67ea",
                                    font=self.fonts["button"], 
                                    relief="flat", 
                                    padx=25, pady=10,
                                    bd=0)
        self.start_button.pack(side="left", padx=(0, 15))
        
        self.stop_button = tk.Button(button_frame, text="STOP MONITORING", 
                                   command=self.stop_detection, 
                                   bg="#A13535", 
                                   fg=self.colors["text_primary"], 
                                   activebackground="#9b3838",
                                   font=self.fonts["button"], 
                                   relief="flat", 
                                   padx=25, pady=10,
                                   bd=0,
                                   state="disabled")
        self.stop_button.pack(side="right")

        # Add hover effects
        self.add_button_hover_effect(self.start_button, self.colors["primary"], "#9a67ea")
        self.add_button_hover_effect(self.stop_button, "#7E3131", "#7c2e2e")

    def create_status(self):
        """Create the modern status indicator section"""
        status_frame = tk.Frame(self.main_frame, bg=self.colors["surface"])
        status_frame.pack(fill="x")

        # Status card
        status_card = tk.Frame(status_frame, bg=self.colors["card"], padx=20, pady=20)
        status_card.pack(fill="x")

        # Status indicator with modern look
        indicator_frame = tk.Frame(status_card, bg=self.colors["card"])
        indicator_frame.pack(anchor="w")

        self.indicator = tk.Canvas(indicator_frame, width=16, height=16, bg=self.colors["card"], 
                                  highlightthickness=0, bd=0)
        self.indicator.pack(side="left", padx=(0, 12))
        self.indicator_oval = self.indicator.create_oval(2, 2, 14, 14, fill=self.colors["text_secondary"], outline="")

        # Status text with secondary color
        self.status_label = tk.Label(status_card, text="Ready to monitor your inbox", 
                                   font=self.fonts["status"], bg=self.colors["card"], 
                                   fg=self.colors["text_secondary"], anchor="w")
        self.status_label.pack(fill="x")

        # Configure style for progress bar with blue background
        style = ttk.Style()
        style.theme_use('default')
        style.configure("blue.Horizontal.TProgressbar", troughcolor=self.colors["surface"], background=self.colors["primary"])

        # Add progress bar as status bar with custom style
        self.status_progress = ttk.Progressbar(status_card, mode='indeterminate', length=200, style="blue.Horizontal.TProgressbar")
        self.status_progress.pack(pady=(10, 0), fill="x")

        # Add a subtle separator
        separator = tk.Frame(status_frame, height=1, bg="#333")
        separator.pack(fill="x", pady=(15, 0))

        # Additional info text
        info_text = tk.Label(status_frame, 
                            text="DetectAlone will monitor your inbox in real-time and alert you about potential phishing attempts.",
                            font=self.fonts["small"], 
                            bg=self.colors["surface"], 
                            fg=self.colors["text_secondary"],
                            wraplength=600,
                            justify="left")
        info_text.pack(pady=(15, 0), anchor="w")

    def add_button_hover_effect(self, button, normal_color, hover_color):
        """Add hover effect to buttons"""
        def on_enter(e):
            button['background'] = hover_color
        
        def on_leave(e):
            button['background'] = normal_color
        
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

    def load_models(self):
        """Load the ML model and tokenizer"""
        # Determine base path for model and tokenizer
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        try:
            # Load model and tokenizer
            model_path = os.path.join(base_path, "my_model_phishing.h5")
            tokenizer_path = os.path.join(base_path, "tokenizer (1).pkl")
            self.model = load_model(model_path)
            with open(tokenizer_path, "rb") as f:
                self.tokenizer = pickle.load(f)
            
            # Update status to show models loaded
            self.status_label.config(text="Ready to monitor your inbox (AI models loaded)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load AI models: {str(e)}")
            self.status_label.config(text="Error loading AI models", fg=self.colors["error"])

    def _clear_placeholder(self, event, placeholder, is_password=False):
        """Clear placeholder text when field is focused"""
        widget = event.widget
        if widget.get() == placeholder:
            widget.delete(0, tk.END)
            if is_password:
                widget.config(show="*")
            widget.config(fg=self.colors["text_primary"])

    def _add_placeholder(self, event, placeholder, is_password=False):
        """Add placeholder text when field loses focus and is empty"""
        widget = event.widget
        if not widget.get():
            widget.insert(0, placeholder)
            if is_password:
                widget.config(show="")
            widget.config(fg=self.colors["text_secondary"])

    def start_detection(self):
        """Start the email monitoring process"""
        email_user = self.email_entry.get().strip()
        email_pass = self.password_entry.get().strip()
        
        if email_user == "your.email@example.com" or not email_user or email_pass == "password" or not email_pass:
            messagebox.showerror("Input Error", "Please enter both email and app password.")
            return

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text="Connecting to Gmail server...", fg=self.colors["secondary"])
        self.indicator.itemconfig(self.indicator_oval, fill=self.colors["secondary"])

        # Start the progress bar animation
        self.status_progress.start(5)

        # Animate the status indicator
        self.animate_indicator()

        # Start the email checking thread
        threading.Thread(target=self.check_email_loop, args=(email_user, email_pass), daemon=True).start()

    def stop_detection(self):
        """Stop the email monitoring process"""
        self.running = False
        self.status_label.config(text="Monitoring stopped", fg=self.colors["text_secondary"])
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.indicator.itemconfig(self.indicator_oval, fill=self.colors["text_secondary"])

        # Stop the progress bar animation
        self.status_progress.stop()
        self.status_progress['value'] = 0

    def animate_indicator(self):
        """Animate the status indicator with a wave effect"""
        if not self.running:
            self.indicator.itemconfig(self.indicator_oval, fill=self.colors["text_secondary"])
            return

        if not hasattr(self, '_wave_direction'):
            self._wave_direction = 1  # 1 for down, -1 for up
            self._wave_position = 0

        max_wave_offset = 6  # max vertical movement in pixels
        step = 1  # pixels per animation frame

        # Update wave position
        self._wave_position += self._wave_direction * step
        if self._wave_position >= max_wave_offset:
            self._wave_direction = -1
        elif self._wave_position <= 0:
            self._wave_direction = 1

        # Move oval vertically to create wave effect
        x1, y1, x2, y2 = 2, 2 + self._wave_position, 14, 14 + self._wave_position
        self.indicator.coords(self.indicator_oval, x1, y1, x2, y2)

        # Keep the color constant or optionally animate color here
        self.indicator.itemconfig(self.indicator_oval, fill=self.colors["primary"])

        self.root.after(100, self.animate_indicator)

    def connect_imap(self, email_user, email_pass):
        """Connect to IMAP server"""
        try:
            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            imap.login(email_user, email_pass)
            imap.select("inbox")
            return imap
        except Exception as e:
            self.status_label.config(text=f"Connection failed: {e}", fg=self.colors["error"])
            messagebox.showerror("Connection Error", f"Failed to connect to Gmail IMAP: {e}")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.indicator.itemconfig(self.indicator_oval, fill=self.colors["error"])
            return None

    def check_email_loop(self, email_user, email_pass):
        """Main loop for checking emails"""
        self.imap = self.connect_imap(email_user, email_pass)
        if not self.imap:
            return
            
        self.running = True
        self.status_label.config(text="Monitoring inbox for phishing emails...", fg=self.colors["secondary"])
        self.indicator.itemconfig(self.indicator_oval, fill=self.colors["primary"])

        # Get highest UID at start to ignore previous emails
        try:
            status, data = self.imap.uid('search', None, "ALL")
            if status == "OK":
                uids = data[0].split()
                if uids:
                    self.highest_uid = int(uids[-1])
                else:
                    self.highest_uid = 0
            else:
                self.highest_uid = 0
        except Exception as e:
            print(f"Error getting highest UID: {e}")
            self.highest_uid = 0

        while self.running:
            try:
                self.imap.select("inbox")
                # Search for unseen emails with UID greater than highest_uid
                criteria = f'(UID {self.highest_uid + 1}:*)'
                status, messages = self.imap.uid('search', None, criteria)
                if status != "OK":
                    self.status_label.config(text="Failed to search inbox", fg=self.colors["error"])
                    time.sleep(10)
                    continue

                mail_uids = messages[0].split()
                new_mail_uids = [uid for uid in mail_uids if int(uid) > self.highest_uid]

                for uid in new_mail_uids:
                    status, msg_data = self.imap.uid('fetch', uid, "(RFC822)")
                    if status != "OK":
                        continue
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            email_content = self.get_email_content(msg)
                            is_phishing = self.predict_phishing(email_content)

                            # Extract subject
                            subject = None
                            raw_subject = msg.get("Subject", "")
                            if raw_subject:
                                decoded_subject = email.header.decode_header(raw_subject)
                                subject_parts = []
                                for part, encoding in decoded_subject:
                                    if isinstance(part, bytes):
                                        try:
                                            part = part.decode(encoding or "utf-8", errors="ignore")
                                        except:
                                            part = part.decode("utf-8", errors="ignore")
                                    subject_parts.append(part)
                                subject = "".join(subject_parts)

                            # Extract sender
                            sender = msg.get("From", None)

                            # Extract URLs from email content
                            urls = self.extract_urls(email_content)
                            # Check URLs with Google Safe Browsing API
                            malicious_link_found = False
                            if urls:
                                malicious_link_found = self.check_urls_with_google_safe_browsing(urls)

                            self.show_notification(is_phishing, subject=subject, sender=sender, malicious_link_found=malicious_link_found)
                    self.highest_uid = max(self.highest_uid, int(uid))

                time.sleep(10)
            except Exception as e:
                import traceback
                tb_str = traceback.format_exc()
                self.status_label.config(text=f"Error during checking: {e}", fg=self.colors["error"])
                print(f"Exception in check_email_loop:\n{tb_str}")
                time.sleep(10)

    def get_email_content(self, msg):
        """Extract email content from message"""
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        part_content = part.get_payload(decode=True).decode()
                        parts.append(part_content)
                    except:
                        pass
        else:
            try:
                parts.append(msg.get_payload(decode=True).decode())
            except:
                pass
        return "\n".join(parts)

    def predict_phishing(self, text):
        """Predict if email is phishing using the ML model"""
        sequences = self.tokenizer.texts_to_sequences([text])
        padded = pad_sequences(sequences, maxlen=100)
        pred = self.model.predict(padded)
        return pred[0][0] > 0.5

    def show_notification(self, is_phishing, subject=None, sender=None, malicious_link_found=False):
        """Show custom tkinter notification based on prediction and malicious link detection"""
        if is_phishing or malicious_link_found:
            # Create a custom notification window
            notif_win = tk.Toplevel(self.root)
            notif_win.title("Phishing Email Detected")
            notif_win.configure(bg=self.colors["surface"])
            notif_win.resizable(False, False)
            notif_win.geometry("520x280")

            # Card frame for content with padding and border radius simulation
            card_frame = tk.Frame(notif_win, bg=self.colors["card"], bd=2, relief="ridge")
            card_frame.pack(expand=True, fill="both", padx=15, pady=15)

            # Icon and title container
            header_frame = tk.Frame(card_frame, bg=self.colors["card"])
            header_frame.pack(fill="x", pady=(0, 10))

            icon_label = tk.Label(header_frame, text="⚠️", font=("Segoe UI Emoji", 30), bg=self.colors["card"], fg=self.colors["error"])
            icon_label.pack(side="left", padx=(0, 10))

            title_label = tk.Label(header_frame, text="Phishing Email Detected", font=("Segoe UI", 20, "bold"), bg=self.colors["card"], fg=self.colors["error"])
            title_label.pack(side="left", anchor="center")

            # Message label with subject and sender
            msg = f"Subject: {subject}\nSender: {sender}"
            if malicious_link_found:
                msg += "\n\n🚫 Do NOT click any links in that email."

            message_label = tk.Label(card_frame, text=msg, font=("Segoe UI", 12), bg=self.colors["card"], fg=self.colors["text_primary"], justify="left", wraplength=460)
            message_label.pack(pady=(10, 20), padx=10, fill="both")

            # Learn More button with hover effect
            def on_learn_more():
                learn_more_win = tk.Toplevel(notif_win)
                learn_more_win.title("Learn More")
                learn_more_win.geometry("520x420")
                learn_more_win.configure(bg=self.colors["surface"])
                learn_more_win.resizable(False, False)

                # Create a Text widget with scrollbar for better content fitting and readability
                text_frame = tk.Frame(learn_more_win, bg=self.colors["surface"])
                text_frame.pack(expand=True, fill="both", padx=15, pady=15)

                scrollbar = tk.Scrollbar(text_frame)
                scrollbar.pack(side="right", fill="y")

                learn_more_text_widget = tk.Text(
                    text_frame,
                    wrap="word",
                    yscrollcommand=scrollbar.set,
                    font=self.fonts["label"],
                    bg=self.colors["card"],
                    fg=self.colors["text_primary"],
                    relief="flat",
                    padx=10,
                    pady=10,
                    borderwidth=0,
                    highlightthickness=0
                )
                learn_more_text_widget.pack(expand=True, fill="both")
                scrollbar.config(command=learn_more_text_widget.yview)

                # Clear existing content
                learn_more_text_widget.delete("1.0", tk.END)

                # Insert styled content
                learn_more_text_widget.tag_configure("title", font=("Segoe UI", 14, "bold"), foreground="#FF4500")
                learn_more_text_widget.tag_configure("number", font=("Segoe UI", 12, "bold"), foreground="#1E90FF")
                learn_more_text_widget.tag_configure("bold", font=("Segoe UI", 12, "bold"))
                learn_more_text_widget.tag_configure("normal", font=("Segoe UI", 12), foreground=self.colors["text_primary"])
                learn_more_text_widget.tag_configure("spacer", font=("Segoe UI", 6))

                learn_more_text_widget.insert(tk.END, "✅ What to Do When You Receive a Phishing Email\n\n", "title")

                learn_more_text_widget.delete("1.0", tk.END)

                learn_more_text_widget.insert(tk.END, "What to Do After Receiving a Phishing Email\n\n", "title")

                learn_more_text_widget.insert(tk.END, "1 Do Not Open or Interact\n\n", "number")
                learn_more_text_widget.insert(tk.END, "❗ Avoid clicking links, downloading attachments, or replying.\n\n", "normal")

                learn_more_text_widget.insert(tk.END, "2 Report the Email\n\n", "number")
                learn_more_text_widget.insert(tk.END, "📤 Forward it to your organization’s IT/security team or use the official reporting email:\n\n", "normal")
                learn_more_text_widget.insert(tk.END, "Gmail: reportphishing@google.com\n\n", "bold")

                learn_more_text_widget.insert(tk.END, "3 Delete the Email\n\n", "number")
                learn_more_text_widget.insert(tk.END, "🗑️ Move it to Spam/Junk or delete it from your inbox.\n\n", "normal")

                learn_more_text_widget.insert(tk.END, "4 If You Clicked by Mistake\n\n", "number")
                learn_more_text_widget.insert(tk.END, "🔐 Immediately change your passwords.\n\n", "normal")
                learn_more_text_widget.insert(tk.END, "🔔 Enable Two-Factor Authentication (2FA).\n\n", "normal")
                learn_more_text_widget.insert(tk.END, "🛡️ Notify your IT/security team.\n\n", "normal")
                learn_more_text_widget.insert(tk.END, "💻 Run an antivirus scan on your device.\n\n", "normal")

                learn_more_text_widget.insert(tk.END, "5 Stay Alert\n\n", "number")
                learn_more_text_widget.insert(tk.END, "✅ Continue using the phishing detection tool for future protection.\n", "normal")

                learn_more_text_widget.config(state="disabled")

            learn_more_btn = tk.Button(
                card_frame,
                text="Learn More",
                command=on_learn_more,
                bg=self.colors["secondary"],
                fg=self.colors["on_secondary"],
                font=self.fonts["button"],
                relief="flat",
                activebackground="#00bfa5",
                padx=15,
                pady=8,
                bd=0,
                cursor="hand2"
            )
            learn_more_btn.pack(pady=(0, 20))

            # Flash the indicator red briefly
            self.indicator.itemconfig(self.indicator_oval, fill=self.colors["error"])
            self.root.after(2000, lambda: self.indicator.itemconfig(self.indicator_oval, fill=self.colors["primary"]))
        else:
            notification.notify(
                title="✓ Safe Email",
                message="The received email is safe.",
                timeout=5
            )

    def extract_urls(self, text):
        """Extract URLs from text using regex"""
        url_pattern = re.compile(r'https?://[^\s]+')
        return url_pattern.findall(text)

    def check_urls_with_google_safe_browsing(self, urls):
        """Check URLs against Google Safe Browsing API"""
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        headers = {"Content-Type": "application/json"}
        body = {
            "client": {
                "clientId": "detectalone-app",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls]
            }
        }
        params = {"key": self.google_safe_browsing_api_key}
        try:
            response = requests.post(api_url, headers=headers, json=body, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            print(f"Google Safe Browsing API response: {data}")  # Debug log
            if "matches" in data:
                # Log matched URLs for debugging
                matched_urls = [match['threat']['url'] for match in data['matches']]
                print(f"Malicious URLs detected: {matched_urls}")
                return True
            return False
        except Exception as e:
            print(f"Error checking URLs with Google Safe Browsing API: {e}")
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingEmailDetectorApp(root)
    root.mainloop()
