from pathlib import Path

BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]
DATA_DIR: Path = BACKEND_ROOT.parent / "data"
SCENARIOS_DIR: Path = DATA_DIR / "scenarios"
DB_PATH: Path = BACKEND_ROOT / "app" / "db" / "alerts.db"

FEATURE_WINDOW_SECONDS: float = 5.0

API_HOST: str = "127.0.0.1"
API_PORT: int = 8000

WS_EVENTS_PATH: str = "/ws/events"

ALERT_DEDUP_WINDOW_SECONDS: float = 10.0

CONTRACT_VERSION: str = "v1"