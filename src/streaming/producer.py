
import json
import os
import uuid

from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from confluent_kafka import Producer
from src.contracts import validate_scan_error, validate_scan_request


# Load configuration from the .env file
load_dotenv()

KAFKA_BROKER = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092"
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC_SCAN_REQUESTS",
    "scan-requests"
)

KAFKA_ERROR_TOPIC = os.getenv(
    "KAFKA_TOPIC_SCAN_ERRORS",
    "scan-errors"
)


def delivery_report(error, message):
    """
    Called by Kafka after message delivery.
    """
    if error is not None:
        print(f"Message delivery failed: {error}")
    else:
        print(
            f"Message successfully delivered "
            f"to topic={message.topic()}, "
            f"partition={message.partition()}"
        )


def build_scan_event(
    project_name: str,
    dependencies: list[dict[str, str]]
) -> dict[str, Any]:
    """
    Build a standardized scan request event.
    """

    if not project_name.strip():
        raise ValueError("Project name cannot be empty.")

    if not dependencies:
        raise ValueError("At least one dependency is required.")

    for dependency in dependencies:
        required_fields = {"ecosystem", "name", "version"}

        if not required_fields.issubset(dependency):
            raise ValueError(
                "Each dependency must contain "
                "ecosystem, name and version."
            )

    event = {
        "scan_id": str(uuid.uuid4()),
        "event_type": "scan_request",
        "schema_version": "1.0",
        "project_name": project_name.strip(),
        "submitted_at": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "dependencies": dependencies
    }

    return validate_scan_request(event)


def build_scan_error_event(
    source_topic: str,
    raw_payload: Any,
    error_type: str,
    details: str,
) -> dict[str, Any]:
    """
    Build a standardized dead-letter event for invalid Kafka payloads.
    """

    event = {
        "error_id": str(uuid.uuid4()),
        "event_type": "scan_error",
        "schema_version": "1.0",
        "source_topic": source_topic,
        "error_type": error_type,
        "raw_payload": raw_payload,
        "details": details,
        "received_at": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    if isinstance(raw_payload, bytes):
        event["raw_payload"] = raw_payload.decode("utf-8", errors="replace")
    return validate_scan_error(event)


def publish_scan_request(
    project_name: str,
    dependencies: list[dict[str, str]]
) -> dict[str, Any]:
    """
    Publish a scan request to Kafka.
    """

    producer = Producer({
        "bootstrap.servers": KAFKA_BROKER
    })

    event = build_scan_event(
        project_name,
        dependencies
    )

    try:
        producer.produce(
            topic=KAFKA_TOPIC,
            key=event["scan_id"],
            value=json.dumps(event),
            callback=delivery_report
        )

        # Process delivery callbacks and wait for confirmation.
        remaining = producer.flush(timeout=10)

        if remaining > 0:
            raise TimeoutError(
                f"{remaining} message(s) not delivered."
            )

        print("\nPublished event:")
        print(json.dumps(event, indent=4))

        return event

    except Exception:
        producer.flush(timeout=5)
        raise


def publish_scan_error(
    source_topic: str,
    raw_payload: Any,
    error_type: str,
    details: str,
) -> dict[str, Any]:
    """
    Publish an invalid Kafka message to the configured dead-letter topic.
    """

    producer = Producer({
        "bootstrap.servers": KAFKA_BROKER
    })

    event = build_scan_error_event(
        source_topic=source_topic,
        raw_payload=raw_payload,
        error_type=error_type,
        details=details,
    )

    try:
        producer.produce(
            topic=KAFKA_ERROR_TOPIC,
            key=event["error_id"],
            value=json.dumps(event),
            callback=delivery_report
        )

        remaining = producer.flush(timeout=10)

        if remaining > 0:
            raise TimeoutError(
                f"{remaining} error message(s) not delivered."
            )

        print("\nPublished dead-letter event:")
        print(json.dumps(event, indent=4))

        return event

    except Exception:
        producer.flush(timeout=5)
        raise


if __name__ == "__main__":

    # Simulated dependencies for our first test
    sample_dependencies = [
        {
            "ecosystem": "PyPI",
            "name": "requests",
            "version": "2.31.0"
        },
        {
            "ecosystem": "PyPI",
            "name": "flask",
            "version": "3.0.0"
        }
    ]

    publish_scan_request(
        project_name="demo-python-project",
        dependencies=sample_dependencies
    )
