import os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from verify_main_push_signatures import _rev_list,GateBlocked

class GitRangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        def git(*args):
            return subprocess.run(["git","-C",str(self.root),*args],
                                  capture_output=True,text=True,check=True).stdout.strip()
        self.git=git
        git("init","-q");git("config","user.name","Fixture");git("config","user.email","fixture@example.org")
        (self.root/"README").write_text("base\n");git("add","README");git("commit","-qm","base")
        self.before=git("rev-parse","HEAD")
        (self.root/"README").write_text("next\n");git("commit","-qam","change1")
        self.mid=git("rev-parse","HEAD")
        (self.root/"NEW").write_text("extra\n");git("add","NEW");git("commit","-qm","change2")
        self.head=git("rev-parse","HEAD")
        self.old=os.getcwd();os.chdir(self.root)
    def tearDown(self):
        os.chdir(self.old);self.tmp.cleanup()
    def test_real_git_push_lists_all_added_commits(self):
        self.assertEqual(_rev_list(self.before,self.head),[self.mid,self.head])
    def test_reversed_commit_direction_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"ancestry"):_rev_list(self.head,self.before)
    def test_missing_base_blocks(self):
        with self.assertRaisesRegex(GateBlocked,"ancestry"):_rev_list("d"*40,self.head)
if __name__=="__main__":unittest.main()
