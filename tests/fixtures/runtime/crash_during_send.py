"""Disposable test process; provider submission is simulated, never networked."""

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from decision_mesh.producer import ExplicitProducer, enroll_producer
from decision_mesh.runtime import Runtime
from decision_mesh.settings import DestinationIdentity


class CrashChannel:
    def send_message(self, *_args):
        os._exit(79)


runtime = Runtime(Path(sys.argv[1]), local_only=True, channel=CrashChannel()).start()
runtime.store.update_settings(
    0,
    {"channel_active": True, "destination": DestinationIdentity(chat_id=42, bot_id=7)},
    now=datetime.now(UTC),
)
runtime.service.publish_policy()
enroll_producer(runtime.paths.producer)
ExplicitProducer(runtime.paths.producer, policy_path=runtime.paths.policy).create(
    {
        "source_request_id": "crash-fixture",
        "snapshot": {"kind": "question", "title": "Synthetic", "summary": "No real send"},
    }
)
runtime.scan_once()
with runtime.service.delivery_gate:
    runtime.delivery.tick(max_attempts=1)
raise AssertionError("crash fixture failed to reach simulated submission")
