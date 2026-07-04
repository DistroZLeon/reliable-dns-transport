FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py worker_pool.py crypto_utils.py transport.py .env ./
RUN mkdir -p uploads&& touch sessions.json

EXPOSE 53/udp
CMD ["python3", "server.py"]
