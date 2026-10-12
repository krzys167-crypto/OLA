import os
import sys
import tempfile
from pathlib import Path

# Make the repository root explicit on sys.path so CI and local pytest use
# the same application import boundary regardless of pytest import mode.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEST_DB_PATH = os.path.join(tempfile.mkdtemp(prefix="ola_pytest_"), "pytest.db")
os.environ["OLA_EG_DB_PATH"] = TEST_DB_PATH
# CI-only pepper; never use this public value for real client credentials.
os.environ.setdefault("OLA_API_KEY_PEPPER", "CI-ONLY-OLA-API-KEY-PEPPER-DO-NOT-USE-IN-PRODUCTION-20261012")

# Import the application database only after the test DB path is fixed.
from app.database import Base, engine
from app import models  # noqa: F401

Base.metadata.create_all(bind=engine)
