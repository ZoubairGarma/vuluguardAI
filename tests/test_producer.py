
import json
import pytest

import src.streaming.producer as producer_module


class FakeMessage:

    def __init__(self, topic, partition):
        self._topic = topic
        self._partition = partition

    def topic(self):
        return self._topic

    def partition(self):
        return self._partition


class FakeProducer:
    """
    Simulates the Kafka Producer for unit testing.
    """

    instances = []

    def __init__(self, configuration):

        self.configuration = configuration
        self.messages = []

        FakeProducer.instances.append(self)

    def produce(
        self,
        topic,
        key,
        value,
        callback=None
    ):

        self.messages.append({
            "topic": topic,
            "key": key,
            "value": value
        })

        if callback:

            callback(
                None,
                FakeMessage(topic, 0)
            )

    def flush(self, timeout=None):
        return 0


def test_build_scan_event():

    dependencies = [
        {
            "ecosystem": "PyPI",
            "name": "requests",
            "version": "2.31.0"
        }
    ]

    event = producer_module.build_scan_event(
        "test-project",
        dependencies
    )

    assert event["event_type"] == "scan_request"

    assert event["project_name"] == "test-project"

    assert len(event["scan_id"]) > 0

    assert len(event["dependencies"]) == 1


def test_publish_scan_request(monkeypatch):

    FakeProducer.instances.clear()

    monkeypatch.setattr(
        producer_module,
        "Producer",
        FakeProducer
    )

    dependencies = [
        {
            "ecosystem": "PyPI",
            "name": "requests",
            "version": "2.31.0"
        }
    ]

    event = producer_module.publish_scan_request(
        project_name="test-project",
        dependencies=dependencies
    )

    fake_producer = FakeProducer.instances[-1]

    assert len(fake_producer.messages) == 1

    sent_message = fake_producer.messages[0]

    assert sent_message["topic"] == (
        producer_module.KAFKA_TOPIC
    )

    assert sent_message["key"] == event["scan_id"]

    decoded_event = json.loads(
        sent_message["value"]
    )

    assert decoded_event["scan_id"] == event["scan_id"]


def test_empty_project_name_is_rejected():

    with pytest.raises(ValueError):

        producer_module.build_scan_event(
            "",
            [
                {
                    "ecosystem": "PyPI",
                    "name": "requests",
                    "version": "2.31.0"
                }
            ]
        )


def test_dependency_with_missing_field_is_rejected():

    with pytest.raises(ValueError):

        producer_module.build_scan_event(
            "test-project",
            [
                {
                    "ecosystem": "PyPI",
                    "name": "requests"
                }
            ]
        )
