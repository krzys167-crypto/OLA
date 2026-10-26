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
# Test fixtures only; never use this pepper in production.
os.environ.setdefault("OLA_API_KEY_PEPPER", "test-only-api-key-pepper-not-for-production")

# Import the application database only after the test DB path is fixed.
from app.database import Base, engine
from app import models  # noqa: F401

Base.metadata.create_all(bind=engine)
