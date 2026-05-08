FROM python:3.11-slim-bookworm

# Install BCC (BPF Compiler Collection) and kernel headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY tracer.py .

RUN pip install --no-cache-dir requests

# eBPF requires privileged mode
CMD ["python3", "tracer.py"]
