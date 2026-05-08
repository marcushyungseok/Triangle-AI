FROM python:3.11-slim

WORKDIR /app
COPY exporter.py .

RUN pip install --no-cache-dir \
    requests \
    opentelemetry-sdk \
    opentelemetry-exporter-otlp-proto-grpc \
    opentelemetry-exporter-otlp-proto-http \
    opentelemetry-semantic-conventions

CMD ["python3", "exporter.py"]
