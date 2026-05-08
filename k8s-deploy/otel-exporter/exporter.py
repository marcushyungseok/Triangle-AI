# -*- coding: utf-8 -*-
"""
Triangle AI — OpenTelemetry Exporter
Exports Triangle AI security events in OTLP format for integration with
Grafana, Jaeger, Datadog, and other observability platforms.
"""
import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [OTEL-EXPORT] %(message)s')
log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
ANALYZER_URL = os.environ.get('ANALYZER_URL', 'http://pdf-analyzer-service:5000')
OTLP_ENDPOINT = os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://otel-collector:4317')
OTLP_PROTOCOL = os.environ.get('OTEL_EXPORTER_OTLP_PROTOCOL', 'grpc')  # grpc or http/protobuf
SERVICE_NAME = os.environ.get('OTEL_SERVICE_NAME', 'triangle-ai-security')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '5'))
ENABLE_TRACES = os.environ.get('OTEL_TRACES_ENABLED', 'true').lower() == 'true'
ENABLE_METRICS = os.environ.get('OTEL_METRICS_ENABLED', 'true').lower() == 'true'
ENABLE_LOGS = os.environ.get('OTEL_LOGS_ENABLED', 'true').lower() == 'true'

# --------------------------------------------------------------------------
# OpenTelemetry SDK Setup
# --------------------------------------------------------------------------

def init_otel():
    """Initialize OpenTelemetry SDK with traces, metrics, and logs exporters."""
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME as SN
    from opentelemetry.semconv.resource import ResourceAttributes

    resource = Resource.create({
        SN: SERVICE_NAME,
        ResourceAttributes.SERVICE_VERSION: "0.2.0",
        ResourceAttributes.DEPLOYMENT_ENVIRONMENT: os.environ.get('ENVIRONMENT', 'production'),
        "triangle.ai.component": "security-exporter",
    })

    # --- Traces ---
    if ENABLE_TRACES:
        if OTLP_PROTOCOL == 'grpc':
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        tracer_provider = TracerProvider(resource=resource)
        span_exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tracer_provider)
        log.info(f"✅ Traces exporter initialized → {OTLP_ENDPOINT}")

    # --- Metrics ---
    if ENABLE_METRICS:
        if OTLP_PROTOCOL == 'grpc':
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        else:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

        metric_exporter = OTLPMetricExporter(endpoint=OTLP_ENDPOINT)
        reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=10000)
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)
        log.info(f"✅ Metrics exporter initialized → {OTLP_ENDPOINT}")

    # --- Logs ---
    if ENABLE_LOGS:
        try:
            from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
            from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
            if OTLP_PROTOCOL == 'grpc':
                from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
            else:
                from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

            log_exporter = OTLPLogExporter(endpoint=OTLP_ENDPOINT)
            logger_provider = LoggerProvider(resource=resource)
            logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
            handler = LoggingHandler(logger_provider=logger_provider)
            logging.getLogger().addHandler(handler)
            log.info(f"✅ Logs exporter initialized → {OTLP_ENDPOINT}")
        except ImportError:
            log.warning("⚠️  OTLP Logs exporter not available (needs opentelemetry-sdk >= 1.20)")

    return (
        trace.get_tracer("triangle.ai.security") if ENABLE_TRACES else None,
        metrics.get_meter("triangle.ai.security") if ENABLE_METRICS else None,
    )


# --------------------------------------------------------------------------
# Security Event to OTLP Mapping
# --------------------------------------------------------------------------

# Severity mapping: Triangle AI verdict → OTEL severity
SEVERITY_MAP = {
    'HIGH RISK': 'ERROR',
    'MEDIUM RISK': 'WARN',
    'CLEAN': 'INFO',
    'UNKNOWN': 'DEBUG',
}


def export_scan_event_as_span(tracer, event):
    """Export a security scan event as an OpenTelemetry span (trace)."""
    if not tracer:
        return

    severity = SEVERITY_MAP.get(event.get('verdict', 'UNKNOWN'), 'INFO')
    with tracer.start_as_current_span(
        name=f"security.scan.{event.get('type', 'unknown').lower().replace(' ', '_')}",
        attributes={
            # File attributes
            "file.name": event.get('filename', ''),
            "file.path": event.get('file_path', ''),
            "file.hash.sha256": event.get('sha256', ''),
            "file.size": event.get('file_size', 0),
            "file.mime_type": event.get('mime_type', ''),
            # Security attributes
            "security.verdict": event.get('verdict', 'UNKNOWN'),
            "security.risk_score": event.get('risk_score', 0),
            "security.type": event.get('type', ''),
            "security.details": json.dumps(event.get('details', [])),
            # K8s context
            "k8s.namespace.name": event.get('namespace', 'unknown'),
            "k8s.pod.name": event.get('pod_name', 'unknown'),
            "k8s.node.name": event.get('node_name', 'unknown'),
        },
    ) as span:
        if event.get('verdict') in ('HIGH RISK', 'MEDIUM RISK'):
            span.set_status(trace.Status(trace.StatusCode.ERROR, event.get('verdict')))

        # Add AI insight as event if present
        ai_insight = event.get('ai_insight', '')
        if ai_insight:
            span.add_event("ai_insight", {"content": ai_insight[:1000]})


def update_metrics(meter, events, stats):
    """Update OpenTelemetry metrics from aggregated stats."""
    if not meter:
        return

    # Counter: total scans
    scan_counter = meter.create_counter(
        name="triangle.security.scans.total",
        description="Total number of security scans performed",
        unit="1",
    )

    # Counter: threats detected
    threat_counter = meter.create_counter(
        name="triangle.security.threats.total",
        description="Total threats detected",
        unit="1",
    )

    # Histogram: risk scores
    risk_histogram = meter.create_histogram(
        name="triangle.security.risk_score",
        description="Distribution of risk scores",
        unit="1",
    )

    # Gauge: active nodes (via UpDownCounter)
    node_gauge = meter.create_up_down_counter(
        name="triangle.security.active_nodes",
        description="Number of active scanner nodes",
        unit="1",
    )

    for event in events:
        labels = {
            "verdict": event.get('verdict', 'UNKNOWN'),
            "file_type": event.get('type', 'unknown'),
            "namespace": event.get('namespace', 'unknown'),
        }
        scan_counter.add(1, labels)

        if event.get('verdict') in ('HIGH RISK', 'MEDIUM RISK'):
            threat_counter.add(1, labels)

        risk_histogram.record(event.get('risk_score', 0), labels)


def export_ebpf_event_as_span(tracer, event):
    """Export an eBPF security event as an OpenTelemetry span."""
    if not tracer:
        return

    with tracer.start_as_current_span(
        name=f"security.ebpf.{event.get('category', 'unknown')}",
        attributes={
            "process.pid": event.get('pid', 0),
            "process.parent_pid": event.get('ppid', 0),
            "process.executable.name": event.get('comm', ''),
            "host.name": event.get('node', ''),
            "security.category": event.get('category', ''),
            "security.severity": event.get('severity', ''),
            "security.description": event.get('description', ''),
            "file.path": event.get('filename', ''),
            "syscall.type": event.get('syscall', ''),
        },
    ) as span:
        if event.get('severity') in ('critical', 'high'):
            span.set_status(trace.Status(trace.StatusCode.ERROR, event.get('description', '')))


# --------------------------------------------------------------------------
# Polling Loop: Fetch events from Triangle AI analyzer
# --------------------------------------------------------------------------
_last_event_count = 0


def poll_and_export(tracer, meter):
    """Poll the Triangle AI analyzer for new events and export them."""
    global _last_event_count
    import requests

    try:
        # Fetch scan events
        resp = requests.get(f"{ANALYZER_URL}/api/events?limit=50", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get('events', [])
            total = data.get('total', 0)

            if total > _last_event_count:
                new_events = events[:total - _last_event_count]
                for event in new_events:
                    export_scan_event_as_span(tracer, event)
                _last_event_count = total
                log.info(f"Exported {len(new_events)} new scan events")

        # Fetch stats for metrics
        resp = requests.get(f"{ANALYZER_URL}/api/stats", timeout=5)
        if resp.status_code == 200:
            stats = resp.json()
            # We update metrics based on cumulative stats
            # The meter SDK handles deduplication via instruments

    except Exception as e:
        log.debug(f"Poll error: {e}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("Triangle AI OpenTelemetry Exporter Starting")
    log.info(f"  OTLP Endpoint: {OTLP_ENDPOINT}")
    log.info(f"  Protocol:      {OTLP_PROTOCOL}")
    log.info(f"  Service Name:  {SERVICE_NAME}")
    log.info(f"  Traces:        {ENABLE_TRACES}")
    log.info(f"  Metrics:       {ENABLE_METRICS}")
    log.info(f"  Logs:          {ENABLE_LOGS}")
    log.info("=" * 60)

    try:
        tracer, meter = init_otel()
    except ImportError as e:
        log.error(f"OpenTelemetry SDK not installed: {e}")
        log.error("Install: pip install opentelemetry-sdk opentelemetry-exporter-otlp")
        sys.exit(1)

    log.info("Polling Triangle AI analyzer for security events...")
    try:
        while True:
            poll_and_export(tracer, meter)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log.info("Shutting down OTEL exporter...")


if __name__ == '__main__':
    main()
