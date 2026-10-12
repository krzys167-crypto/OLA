import threading
from ola_events.outbox import connect, enqueue, claim, complete, fail


def test_dedup_and_tenant_isolation(tmp_path):
    db=connect(tmp_path/"events.db")
    enqueue(db,"a","evt","h","{}")
    enqueue(db,"a","evt","h","{}")
    enqueue(db,"b","evt","h","{}")
    assert db.execute("SELECT count(*) FROM deliveries").fetchone()[0]==2
    assert claim(db,"missing",now=100) is None
    a=claim(db,"a",now=100)
    assert a is not None
    assert not complete(db,"b",a[0],a[-1])
    assert complete(db,"a",a[0],a[-1])
    assert claim(db,"a",now=1000) is None
    assert claim(db,"b",now=100) is not None


def test_retry_dead_letter_and_stale_token(tmp_path):
    db=connect(tmp_path/"events.db")
    enqueue(db,"a","evt","h","{}")
    first=claim(db,"a",now=100,lease_seconds=5)
    assert claim(db,"a",now=104) is None
    second=claim(db,"a",now=106)
    assert second[-1]!=first[-1]
    assert not complete(db,"a",first[0],first[-1])
    assert fail(db,"a",second[0],second[-1],now=106,max_attempts=3)
    assert claim(db,"a",now=107) is None
    third=claim(db,"a",now=1000)
    assert fail(db,"a",third[0],third[-1],now=1000,max_attempts=3)
    assert db.execute("SELECT state FROM deliveries").fetchone()[0]=="dead"


def test_concurrent_claim_one_winner(tmp_path):
    path=tmp_path/"events.db"
    db=connect(path)
    enqueue(db,"a","evt","h","{}")
    results=[]
    def worker():
        conn=connect(path)
        results.append(claim(conn,"a",now=100))
        conn.close()
    threads=[threading.Thread(target=worker) for _ in range(8)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert sum(r is not None for r in results)==1


def test_duplicate_event_cannot_silently_replace_or_hide_conflicting_payload(tmp_path):
    import pytest
    db = connect(tmp_path / "events.db")
    enqueue(db, "tenant", "evt", "handler", '{"amount":10}')
    enqueue(db, "tenant", "evt", "handler", '{"amount":10}')
    with pytest.raises(ValueError, match="conflicting duplicate"):
        enqueue(db, "tenant", "evt", "handler", '{"amount":10000}')
    assert db.execute("SELECT payload FROM deliveries").fetchone()[0] == '{"amount":10}'
