FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV IN_DOCKER=1

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5001", "app:app"]


