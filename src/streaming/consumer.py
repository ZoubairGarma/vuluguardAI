
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
                event = json.loads(
                    message.value().decode("utf-8")
                )

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

                # Temporary development policy:
                # skip malformed messages.
                # We will improve this with an error topic later.
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
