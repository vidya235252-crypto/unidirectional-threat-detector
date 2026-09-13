import logging
from pathlib import Path
from typing import Iterator

from pydantic import ValidationError

from app.core.packet_event import PacketEvent

logger = logging.getLogger(__name__)


class ScenarioLoader:
    def __init__(self, scenario_path: Path):
        self.scenario_path = Path(scenario_path)
        self.parsed_count = 0
        self.rejected_count = 0

    def load(self) -> Iterator[PacketEvent]:
        if not self.scenario_path.exists():
            raise FileNotFoundError(f"Scenario file not found: {self.scenario_path}")

        with open(self.scenario_path, "r") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    packet = PacketEvent.from_json_line(line)
                    self.parsed_count += 1
                    yield packet
                except (ValidationError, ValueError) as e:
                    self.rejected_count += 1
                    logger.warning(
                        f"Rejected malformed packet at {self.scenario_path.name}:{line_number} - {e}"
                    )
                    continue

    def summary(self) -> dict:
        return {
            "parsed": self.parsed_count,
            "rejected": self.rejected_count,
        }