FROM python:3.11-slim

WORKDIR /app
COPY webhook.py .
RUN pip install --no-cache-dir flask requests

EXPOSE 8443
CMD ["python3", "webhook.py"]
