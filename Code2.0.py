import csv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import customtkinter as ctk
from tkinter import filedialog, messagebox
from threading import Thread

class PasswordAnalyzerApp:
    def __init__(self):
        # GUI Configuration
        self.root = ctk.CTk()
        self.root.title("Password Strength Analyzer")
        self.root.geometry("600x400")
        
        # Variables
        self.csv_path = ctk.StringVar()
        self.sender_email = ctk.StringVar(value="atiyoussef608@gmail.com")
        self.smtp_password = ctk.StringVar()
        self.running = False
        
        # Create widgets
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Title
        ctk.CTkLabel(main_frame, text="Password Strength Analyzer", font=("Arial", 16)).pack(pady=10)
        
        # CSV file selection
        file_frame = ctk.CTkFrame(main_frame)
        file_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(file_frame, text="CSV File:").pack(side="left", padx=5)
        ctk.CTkEntry(file_frame, textvariable=self.csv_path, width=300).pack(side="left", padx=5)
        ctk.CTkButton(file_frame, text="Browse", command=self.browse_file).pack(side="left", padx=5)
        
        # SMTP Configuration
        smtp_frame = ctk.CTkFrame(main_frame)
        smtp_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(smtp_frame, text="Sender Email:").grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkEntry(smtp_frame, textvariable=self.sender_email).grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkLabel(smtp_frame, text="SMTP Password:").grid(row=1, column=0, padx=5, pady=5)
        ctk.CTkEntry(smtp_frame, textvariable=self.smtp_password, show="*").grid(row=1, column=1, padx=5, pady=5)
        
        # Action buttons
        btn_frame = ctk.CTkFrame(main_frame)
        btn_frame.pack(pady=20)
        
        ctk.CTkButton(btn_frame, text="Analyze Passwords", command=self.start_analysis).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Exit", command=self.root.quit).pack(side="left", padx=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(main_frame, text="Ready")
        self.status_label.pack()
        
    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            self.csv_path.set(filename)
    
    def start_analysis(self):
        if not self.csv_path.get():
            messagebox.showerror("Error", "Please select a CSV file first")
            return
            
        if not self.smtp_password.get():
            messagebox.showerror("Error", "Please enter your SMTP password")
            return
            
        self.running = True
        Thread(target=self.analyze_passwords).start()
    
    def analyze_passwords(self):
        self.status_label.configure(text="Analyzing...")
        
        # Common passwords list
        common_passwords = [
            "123456", "123456789", "qwerty", "password", "1234567",
            "12345678", "12345", "iloveyou", "111111", "123123",
            "abc123", "qwerty123", "1q2w3e4r", "admin", "letmein",
            "welcome", "monkey", "login", "football", "starwars",
            "dragon", "passw0rd", "master", "hello", "freedom",
            "whatever", "trustno1", "qazwsx", "654321", "baseball",
            "superman", "michael", "shadow", "pokemon", "ninja"
        ]
        
        # Function that determines a strong password
        def is_strong_password(password):
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()-_=+[]{}|;:',.<>/?`~ \"\\" for c in password)
            return len(password) >= 8 and has_upper and has_lower and has_digit and has_special
        
        # Function that sends the email based on the verified conditions
        def send_email(sender_email, message, receiver_email, subject="", smtp_server="smtp.gmail.com", smtp_port=587, password=""):
            try:
                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = receiver_email
                msg['Subject'] = subject
                msg.attach(MIMEText(message, 'plain'))

                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    server.starttls()
                    server.login(sender_email, password)
                    server.send_message(msg)
                return True
            except Exception as e:
                print(f"Error sending email: {e}")
                return False
        
        try:
            with open(self.csv_path.get(), 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if not self.running:
                        break
                        
                    password = row.get('password', '')
                    email = row.get('email', '')
                    username = row.get('username', 'User')
                    
                    if not password or not email:
                        continue
                    
                    warning_message = f"Hi {username},\n\nYour password does not meet security requirements. " \
                                    "Please use a password that:\n" \
                                    "- Contains at least 8 characters\n" \
                                    "- Includes uppercase and lowercase letters\n" \
                                    "- Contains numbers and special characters\n" \
                                    "- Is not a common password\n\n" \
                                    "Best regards,\nSecurity Team"
                    
                    if (len(password) < 8 or 
                        not is_strong_password(password) or 
                        password in common_passwords):
                        
                        send_email(
                            sender_email=self.sender_email.get(),
                            message=warning_message,
                            receiver_email=email,
                            subject="Password Security Alert",
                            smtp_server="smtp.gmail.com",
                            smtp_port=587,
                            password=self.smtp_password.get()
                        )
                        
                        
            
            self.status_label.configure(text="Analysis complete. The email was sent to the users with weak passwords.")
            messagebox.showinfo("Complete", "Password analysis completed successfully")
            
        except Exception as e:
            self.status_label.configure(text="Error occurred")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.running = False
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.run()
    