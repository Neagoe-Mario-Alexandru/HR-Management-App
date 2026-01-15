import pika
import json
import os
import smtplib
import time
from email.message import EmailMessage

# Setari
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") == "1"
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")

# LOgica citire
SMTP_PASS_FILE = os.environ.get("SMTP_PASS_FILE")
if SMTP_PASS_FILE and os.path.exists(SMTP_PASS_FILE):
    with open(SMTP_PASS_FILE, "r") as f:
        SMTP_PASS = f.read().strip()
else:
    SMTP_PASS = os.environ.get("SMTP_PASS", "")

def send_email_worker(to_email, subject, body):
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_USE_TLS: 
                server.starttls()
            
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            else:
                print(" [!] EROARE: Lipsesc SMTP_USER sau SMTP_PASS!")
                return False
                
            server.send_message(msg)
            print(f" [v] Email trimis cu succes către {to_email}")
            return True
    except Exception as e:
        print(f" [!] Error sending email: {e}")
        return False

def callback(ch, method, properties, body):
    print(f" [received] Mesaj primit: {body.decode()}")
    data = json.loads(body)
    
    # Attempt trimitere email
    success = send_email_worker(data.get('to'), data.get('subject'), data.get('body'))
    
    if success:
        # Confirmare mesaj
        ch.basic_ack(delivery_tag=method.delivery_tag)
    else:
        print(" [!] Trimitere eșuată. Mesajul rămâne în coadă.")
        # Incearca iar
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
        # Sleep sa nu am loop insane
        time.sleep(5)

# Setup RabbitMQ
print(' [*] Se conectează la RabbitMQ...')
connected = False
while not connected:
    try:
        params = pika.URLParameters(RABBITMQ_URL)
        conn = pika.BlockingConnection(params)
        ch = conn.channel()
        connected = True
    except Exception:
        print(" [!] RabbitMQ nu este gata... reîncercare în 5 secunde.")
        time.sleep(5)

ch.exchange_declare(exchange="email_exchange", exchange_type="topic", durable=True)
ch.queue_declare(queue="email_queue", durable=True)
ch.queue_bind(exchange="email_exchange", queue="email_queue", routing_key="email.send")

# Sa nu preia mai multe mesaje decat poate procesa
ch.basic_qos(prefetch_count=1)
ch.basic_consume(queue="email_queue", on_message_callback=callback)

print(' [*] Waiting for emails. To exit press CTRL+C')
ch.start_consuming()