import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from verify_github_signatures import Blocked,gate,allowed_keys
BASE="a"*40; HEAD="e"*40; SHAS=["b"*40,"c"*40,"d"*40,HEAD]; FPR="A"*40
def fixture():
    pr={"state":"open","head":{"sha":HEAD},"base":{"ref":"main","sha":BASE},"commits":4}
    items=[{"sha":s} for s in SHAS]; details={}
    parent=BASE
    for s in SHAS:
        details[s]={"sha":s,"parents":[{"sha":parent}],"commit":{
            "author":{"email":"user@example.com"},
            "verification":{"verified":True,"reason":"valid","signature":"-----BEGIN PGP SIGNATURE-----\nx","payload":"p"+s}}}
        parent=s
    def fetch(path):
        if path=="pulls/64":return pr
        if path.endswith("page=1"):return items
        if path.startswith("commits/"):return details[path.split("/")[-1]]
        raise RuntimeError(path)
    return pr,items,details,fetch
class GateTests(unittest.TestCase):
    def call(self,change=None,verify=None,keys=FPR,head=HEAD,base=BASE):
        pr,items,details,fetch=fixture()
        if change:change(pr,items,details)
        return gate(repo="org/repo",pr_number=64,head=head,base=base,
                    fingerprints=keys,fetch=fetch,verify=verify or (lambda *args:FPR))
    def test_all_four(self):
        self.assertEqual(self.call()["verified_count"],4)
    def test_unsigned_blocks(self):
        with self.assertRaisesRegex(Blocked,"unsigned"):
            self.call(lambda p,i,d:d[SHAS[1]]["commit"]["verification"].update(verified=False))
    def test_other_signer_blocks(self):
        with self.assertRaisesRegex(Blocked,"unapproved"):
            self.call(verify=lambda *x:"F"*40)
    def test_missing_allowlist_blocks(self):
        with self.assertRaisesRegex(Blocked,"allowlist"):self.call(keys="")
    def test_head_drift_blocks(self):
        with self.assertRaisesRegex(Blocked,"head drift"):self.call(head="0"*40)
    def test_base_drift_blocks(self):
        with self.assertRaisesRegex(Blocked,"base drift"):self.call(base="0"*40)
    def test_duplicate_blocks(self):
        with self.assertRaisesRegex(Blocked,"duplicate"):
            self.call(lambda p,i,d:i.__setitem__(2,i[1]))
    def test_missing_page_blocks(self):
        with self.assertRaisesRegex(Blocked,"commit count"):
            self.call(lambda p,i,d:i.pop())
    def test_merge_commit_blocks(self):
        with self.assertRaisesRegex(Blocked,"nonlinear"):
            self.call(lambda p,i,d:d[SHAS[1]].update(parents=[{"sha":SHAS[0]},{"sha":"f"*40}]))
    def test_invalid_key_format_blocks(self):
        with self.assertRaisesRegex(Blocked,"allowlist"):allowed_keys("bad")
    def test_uid_is_forwarded(self):
        def verify(sig,payload,email,keys):
            if email!="user@example.com":raise Blocked("UID wrong")
            return FPR
        with self.assertRaisesRegex(Blocked,"UID wrong"):
            self.call(lambda p,i,d:d[SHAS[0]]["commit"]["author"].update(email="changed@example.com"),verify=verify)

class ProductionWorkflowSafetyTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "final-production-gate.yml").read_text(encoding="utf-8")
    def test_source_checkout_is_pinned_and_asserted(self):
        self.assertIn("ref: ${{ steps.target.outputs.sha }}", self.workflow)
        self.assertIn("- name: Verify checked out source SHA", self.workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "${{ steps.target.outputs.sha }}"', self.workflow)
    def test_release_attestations_are_main_push_only(self):
        import re
        for step in ("Export release image", "Create source snapshot subjects",
                     "Attest source snapshot", "Attest release image archive",
                     "Independently verify source and image attestations"):
            with self.subTest(step=step):
                pattern = (r"(?m)^      - name: " + re.escape(step) +
                           r"\n        if: github.event_name == 'push' && github.ref == 'refs/heads/main'$")
                self.assertRegex(self.workflow, pattern)

if __name__=="__main__":unittest.main()
