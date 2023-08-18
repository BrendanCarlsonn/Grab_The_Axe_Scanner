import tkinter as tk
from tkinter import messagebox
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email():
    sender_email = "your_email@example.com"
    sender_password = "your_email_password"

    receiver_email = receiver_entry.get()
    subject = subject_entry.get()
    body = body_text.get(1.0, tk.END)

    try:
        # Create a MIMEText object for the email content
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connect to the SMTP server and send the email
        smtp_server = 'smtp.example.com'
        smtp_port = 587  # Use 465 for SSL/TLS
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Use SSL/TLS
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())

        messagebox.showinfo("Email Sent", "The email has been sent successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("Send Email")

# Add widgets to the window
receiver_label = tk.Label(root, text="Receiver Email:")
receiver_label.pack()
receiver_entry = tk.Entry(root)
receiver_entry.pack()

subject_label = tk.Label(root, text="Subject:")
subject_label.pack()
subject_entry = tk.Entry(root)
subject_entry.pack()

body_label = tk.Label(root, text="Body:")
body_label.pack()
body_text = tk.Text(root, width=40, height=10)
body_text.pack()

send_button = tk.Button(root, text="Send Email", command=send_email)
send_button.pack()

# Run the GUI event loop
root.mainloop()