
import json
import os

from dotenv import load_dotenv
from confluent_kafka import Consumer, KafkaError, KafkaException


# Load configuration
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
    Process the received scan request.
    For now, we only validate and display it.
    """

    if event.get("event_type") != "scan_request":
        print("Unknown event type. Ignoring message.")
        return

    dependencies = event.get("dependencies", [])

    if not dependencies:
        print("Scan request contains no dependencies.")
        return

    print("\n" + "=" * 55)
    print("NEW VULNGUARD SCAN REQUEST")
    print("=" * 55)

    print(f"Scan ID: {event.get('scan_id')}")
    print(f"Project: {event.get('project_name')}")
    print(f"Submitted at: {event.get('submitted_at')}")

    print("\nDependencies to analyze:")

    for dependency in dependencies:
        print(
            f"- {dependency['name']} "
            f"== {dependency['version']} "
            f"({dependency['ecosystem']})"
        )

    print("=" * 55)


def start_consumer():
    """
    Subscribe to Kafka and receive scan requests.
    """

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
                event = json.loads(
                    message.value().decode("utf-8")
                )

                process_scan_event(event)

                # Commit only after successful processing.
                consumer.commit(
                    message=message,
                    asynchronous=False
                )

            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                print(f"Invalid JSON message: {error}")

                # For this development prototype, skip malformed messages.
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

