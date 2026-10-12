import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from verify_main_push_signatures import validate_main_push,GateBlocked,GITHUB_WEBFLOW_SIGNER_FPR

PRE="a"*40
HEAD="e"*40
OWNER="b"*40
OTHER="c"*40
FPR="A"*40

def make_fetch(bad=False):
    commits={
        OWNER:{"sha":OWNER,"parents":[{"sha":PRE}],"commit":{
            "author":{"email":"owner@example.org"},"committer":{"name":"Owner","email":"owner@example.org"},
            "verification":{"verified":True,"reason":"valid","signature":"-----BEGIN PGP SIGNATURE-----\nSIG\n-----END PGP SIGNATURE-----","payload":"test payload"}}},
        HEAD:{"sha":HEAD,"parents":[{"sha":PRE},{"sha":OWNER}],"commit":{
            "author":{"email":"owner@example.org"},"committer":{"name":"GitHub","email":"noreply@github.com"},
            "verification":{"verified":True,"reason":"valid","signature":"-----BEGIN PGP SIGNATURE-----\nSIG\n-----END PGP SIGNATURE-----","payload":"signed merge"}}}
    }
    if bad:commits[OWNER]["commit"]["verification"]["verified"]=False
    return lambda sha:commits[sha]

class MainPushSignatureTests(unittest.TestCase):
    def test_entrypoint_uses_real_verifier_class(self):
        # Regression: the main() entrypoint formerly imported an unavailable
        # GPGVerifier class, making actual signed pushes fail before policy.
        import json
        import os
        import tempfile
        from unittest.mock import patch
        from verify_main_push_signatures import main as entrypoint
        with tempfile.TemporaryDirectory() as root:
            previous = os.getcwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": "invalid/repo"}, clear=True):
                    code = entrypoint()
                with open("main-signature-result.json", encoding="utf-8") as stream:
                    evidence = json.load(stream)
            finally:
                os.chdir(previous)
        self.assertEqual(code, 1)
        self.assertEqual(evidence["status"], "BLOCKED")
        self.assertEqual(evidence["reason"], "unexpected target repository")


    def call(self,**params):
        a=dict(before=PRE,head=HEAD,commits=[OWNER,HEAD],allowed_fprs=FPR,fetch=make_fetch(),
               verify=lambda signature,payload,email,allowed:(GITHUB_WEBFLOW_SIGNER_FPR if allowed=={GITHUB_WEBFLOW_SIGNER_FPR} else FPR))
        a.update(params)
        return validate_main_push(**a)
    def test_owner_and_github_signed_merge_pass(self):
        result=self.call()
        self.assertEqual((result["status"],result["verified_count"],result["owner_signed_count"],result["github_merge_count"]),
                         ("VERIFIED",2,1,1))
        self.assertEqual(result["production_go"],"NO-GO")
    def test_unsigned_ancestor_blocks_even_if_merge_verified(self):
        with self.assertRaisesRegex(GateBlocked,"unverified"):self.call(fetch=make_fetch(bad=True))
    def test_wrong_signer_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"unapproved signer"):self.call(verify=lambda *_:"F"*40)
    def test_truncated_commit_range_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"incomplete merge ancestry"):self.call(commits=[HEAD])
    def test_duplicate_list_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"duplicate"):self.call(commits=[OWNER,OWNER,HEAD])
    def test_unsigned_merge_blocks(self):
        original=make_fetch()
        def tamper(sha):
            r=original(sha)
            if sha==HEAD:r["commit"]["verification"]["verified"]=False
            return r
        with self.assertRaisesRegex(GateBlocked,"unverified"):self.call(fetch=tamper)
    def test_merged_commit_must_use_official_github_signer(self):
        # A GitHub-verified signature combined with a spoofed committer
        # name cannot bypass the independently authorized signing key.
        calls = []
        def adversarial_verify(signature, payload, email, allowed):
            calls.append((email, allowed))
            if email == "noreply@github.com":
                raise GateBlocked("untrusted GitHub merge signature")
            return FPR
        with self.assertRaisesRegex(GateBlocked, "untrusted GitHub merge signature"):
            self.call(verify=adversarial_verify)
        self.assertTrue(any(email == "noreply@github.com" for email, _ in calls))

    def test_wrong_github_merge_key_blocks(self):
        def forged_signer(signature,payload,email,allowed):
            return "F"*40 if email=="noreply@github.com" else FPR
        with self.assertRaisesRegex(GateBlocked,"untrusted GitHub merge signature"):
            self.call(verify=forged_signer)
    def test_not_github_merge_identity_blocks(self):
        original=make_fetch()
        def tamper(sha):
            r=original(sha)
            if sha==HEAD:r["commit"]["committer"]["name"]="Attacker"
            return r
        with self.assertRaisesRegex(GateBlocked,"untrusted merge identity"):self.call(fetch=tamper)
    def test_invalid_sha_range_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"invalid"):self.call(before="0"*40)
    def test_missing_allowlist_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"allowlist"):self.call(allowed_fprs="")
    def test_unexpected_extra_parent_blocks(self):
        original=make_fetch()
        def tamper(sha):
            r=original(sha)
            if sha==HEAD:r["parents"]+=[{"sha":OTHER}]
            return r
        with self.assertRaisesRegex(GateBlocked,"unexpected parent count"):self.call(fetch=tamper)
    def test_api_failure_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"API"):
            self.call(fetch=lambda sha:(_ for _ in ()).throw(OSError("network unavailable")))
    def test_parent_outside_range_other_than_before_blocks(self):
        original=make_fetch()
        def tamper(sha):
            r=original(sha)
            if sha==HEAD:r["parents"][0]["sha"]=OTHER
            return r
        with self.assertRaisesRegex(GateBlocked,"incomplete merge ancestry"):self.call(fetch=tamper)
if __name__=="__main__":unittest.main()
