import os
import subprocess
import unittest
import shutil


class TestFileTransfer(unittest.TestCase):
    def test_transfer_script_runs(self):
        """Smoke/integration test: run scripts/auto_file_test.sh via bash.

        The script controls Docker and may take several seconds. The test
        skips when Docker is not available on the test host.
        """
        if not shutil.which('docker'):
            self.skipTest('docker not available')

        script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'auto_file_test.sh'))
        res = subprocess.run(['bash', script], cwd=os.path.dirname(script))
        self.assertEqual(res.returncode, 0)


if __name__ == '__main__':
    unittest.main()
