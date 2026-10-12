import re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from verify_github_signatures import GPG,Blocked
@unittest.skipUnless(shutil.which("gpg"),"gpg required")
class GPGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="ola-gpg-tests-"); cls.root=Path(cls.tmp.name)
        cls.home=cls.root/"gnupg";cls.home.mkdir(mode=0o700)
        subprocess.run(["gpg","--homedir",str(cls.home),"--batch","--passphrase","","--pinentry-mode","loopback","--quick-generate-key","Test Owner <user@example.com>","ed25519","sign","1d"],check=True,capture_output=True)
        k=subprocess.run(["gpg","--homedir",str(cls.home),"--with-colons","--fingerprint","--list-keys"],check=True,capture_output=True,text=True)
        cls.fpr=re.search(r"^fpr:::::::::([0-9A-Fa-f]{40}):",k.stdout,re.MULTILINE).group(1).upper()
        public=subprocess.run(["gpg","--homedir",str(cls.home),"--armor","--export",cls.fpr],check=True,capture_output=True)
        cls.verifier=GPG(public.stdout);cls.message="fixture payload\n"
        p=cls.root/"payload";s=cls.root/"signature.asc";p.write_text(cls.message)
        subprocess.run(["gpg","--homedir",str(cls.home),"--batch","--armor","--detach-sign","-o",str(s),str(p)],check=True,capture_output=True)
        cls.signature=s.read_text()
    @classmethod
    def tearDownClass(cls):cls.verifier.close();cls.tmp.cleanup()
    def test_real_signature(self):
        self.assertEqual(self.verifier.verify(self.signature,self.message,"user@example.com",{self.fpr}),self.fpr)
    def test_wrong_fingerprint_rejected(self):
        with self.assertRaisesRegex(Blocked,"unapproved"):self.verifier.verify(self.signature,self.message,"user@example.com",{"F"*40})
    def test_wrong_uid_rejected(self):
        with self.assertRaisesRegex(Blocked,"UID"):self.verifier.verify(self.signature,self.message,"other@example.com",{self.fpr})
    def test_tamper_rejected(self):
        with self.assertRaisesRegex(Blocked,"invalid"):self.verifier.verify(self.signature,"tampered","user@example.com",{self.fpr})
if __name__=="__main__":unittest.main()
