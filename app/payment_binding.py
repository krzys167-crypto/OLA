"""Fail-closed correlation of a paid checkout and its completed execution."""


def checkout_result_matches(tenant_id, session_id, task, evidence, event, result):
    if not all(isinstance(value, str) and value for value in (tenant_id, session_id, task)):
        return False
    if not isinstance(evidence, dict) or not isinstance(result, dict):
        return False
    event_id = evidence.get("stripe_event_id")
    run_id = evidence.get("ola_run_id")
    return bool(
        event_id and run_id
        and evidence.get("tenant_id") == tenant_id
        and evidence.get("checkout_session_id") == session_id
        and event.status == "COMPLETED"
        and event.task == task
        and event.event_id == event_id
        and event.run_id == run_id
        and result.get("status") == "COMPLETED"
        and result.get("event_id") == event_id
        and result.get("checkout_session_id") == session_id
        and result.get("ola_run_id") == run_id
    )
