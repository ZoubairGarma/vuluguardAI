
from email.mime import message
import json
import os

from dotenv import load_dotenv
from confluent_kafka import (
    Consumer,
    KafkaError,
    KafkaException,
    error
)

from src.database.db import (
    initialize_database,
    save_scan_event,
    update_scan_status,
    get_scan_status
)
from src.streaming.producer import publish_scan_error


load_dotenv()

KAFKA_BROKER = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092"
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC_SCAN_REQUESTS",
    "scan-requests"
)

KAFKA_GROUP_ID = os.getenv(
    "KAFKA_GROUP_ID",
    "vulnguard-scan-consumer-dev"
)


def process_scan_event(event: dict):
    """
    Display the received scan request.
    """

    dependencies = event.get("dependencies", [])

    print("\n" + "=" * 55)
    print("NEW VULNGUARD SCAN REQUEST")
    print("=" * 55)

    print(f"Scan ID: {event.get('scan_id')}")
    print(f"Project: {event.get('project_name')}")

    print("\nDependencies:")

    for dependency in dependencies:

        print(
            f"- {dependency['name']} "
            f"== {dependency['version']} "
            f"({dependency['ecosystem']})"
        )

    print("=" * 55)


def report_scan_error(message, error_type: str, details: str, raw_payload=None):
    """
    Send malformed or invalid Kafka payloads to the scan-errors topic.
    """

    if raw_payload is None:
        raw_payload = message.value().decode("utf-8", errors="replace")

    try:
        publish_scan_error(
            source_topic=KAFKA_TOPIC,
            raw_payload=raw_payload,
            error_type=error_type,
            details=details,
        )
        print(f"Dead-letter event published: {error_type}")
    except Exception as error:
        print(f"Unable to publish dead-letter event: {error}")


def start_consumer():

    # Initialize the database before consuming messages.
    initialize_database()

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": KAFKA_GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False
    })

    consumer.subscribe([KAFKA_TOPIC])

    print(f"Listening to topic: {KAFKA_TOPIC}")
    print("Waiting for scan requests... Press Ctrl+C to stop.")

    try:

        while True:

            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():

                if message.error().code() == KafkaError._PARTITION_EOF:
                    continue

                raise KafkaException(message.error())

            try:

                # Decode the Kafka message
                raw_payload = message.value().decode("utf-8")
                event = json.loads(raw_payload)

                # Save the scan and its dependencies
                # 1. Save the scan and its dependencies.
                inserted = save_scan_event(event)

                if inserted:
                    print("\nNew scan successfully saved in SQLite.")
                else:
                    print("\nDuplicate scan detected.")

                # 2. Retrieve the current status.
                current_status = get_scan_status(event["scan_id"])

                if current_status is None:
                    raise ValueError("Scan was not found in SQLite.")

                # 3. Move a newly received scan to WAITING_ANALYSIS.
                # This transition means it is ready for the analysis module.
                if current_status == "RECEIVED":
                    update_scan_status(
                        scan_id=event["scan_id"],
                        new_status="WAITING_ANALYSIS",
                        details=(
                            "Scan stored successfully. "
                            "Waiting for vulnerability analysis."
                        )
                    )

                process_scan_event(event)

                # Commit only after successful database persistence.
                consumer.commit(
                    message=message,
                    asynchronous=False
                )

                print("Kafka message successfully committed.")

            except (json.JSONDecodeError, UnicodeDecodeError) as error:

                print(f"Invalid JSON message: {error}")
                report_scan_error(
                    message=message,
                    error_type="INVALID_JSON",
                    details=str(error),
                    raw_payload=message.value().decode("utf-8", errors="replace")
                )
                consumer.commit(
                    message=message,
                    asynchronous=False
                )

            except ValueError as error:

                print(f"Invalid scan payload: {error}")
                report_scan_error(
                    message=message,
                    error_type="INVALID_SCAN_PAYLOAD",
                    details=str(error),
                    raw_payload=json.loads(message.value().decode("utf-8", errors="replace"))
                    if message.value() else None
                )
                consumer.commit(
                    message=message,
                    asynchronous=False
                )

    except KeyboardInterrupt:

        print("\nConsumer stopped by user.")

    finally:

        consumer.close()

        print("Kafka connection closed.")


if __name__ == "__main__":
    start_consumer()
