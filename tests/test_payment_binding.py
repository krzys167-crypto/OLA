from copy import deepcopy
from types import SimpleNamespace
import unittest

from app.payment_binding import checkout_result_matches


class PaymentBinding(unittest.TestCase):
    def setUp(self):
        self.evidence = {"tenant_id": "tenant-A", "stripe_event_id": "evt-A", "checkout_session_id": "cs-A", "ola_run_id": "run-A"}
        self.event = SimpleNamespace(status="COMPLETED", task="same task", event_id="evt-A", run_id="run-A")
        self.result = {"status": "COMPLETED", "event_id": "evt-A", "checkout_session_id": "cs-A", "ola_run_id": "run-A"}

    def matches(self, session="cs-A", evidence=None, event=None, result=None):
        return checkout_result_matches("tenant-A", session, "same task", self.evidence if evidence is None else evidence, self.event if event is None else event, self.result if result is None else result)

    def test_exact_checkout_event_and_run_match(self):
        self.assertTrue(self.matches())

    def test_same_task_different_checkout_cannot_return_result(self):
        self.assertFalse(self.matches(session="cs-B"))

    def test_other_tenant_cannot_return_result(self):
        self.assertFalse(self.matches(evidence=dict(self.evidence, tenant_id="tenant-B")))

    def test_mismatched_stored_result_is_rejected(self):
        for key in self.result:
            changed = deepcopy(self.result)
            changed[key] = "foreign"
            with self.subTest(field=key):
                self.assertFalse(self.matches(result=changed))

    def test_mismatched_event_is_rejected(self):
        for key in vars(self.event):
            changed = deepcopy(self.event)
            setattr(changed, key, "foreign")
            with self.subTest(field=key):
                self.assertFalse(self.matches(event=changed))

    def test_missing_provenance_is_rejected(self):
        for key in self.evidence:
            changed = deepcopy(self.evidence)
            changed.pop(key)
            self.assertFalse(self.matches(evidence=changed))


if __name__ == "__main__":
    unittest.main()
