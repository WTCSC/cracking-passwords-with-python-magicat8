import unittest
import subprocess
import hashlib
from unittest.mock import patch

class TestJillScript(unittest.TestCase):
    def test_average_output(self):
        # Run the script with the sample.txt file
        result = subprocess.run(['python3', 'jill.py', 'passwords.txt',
            'wordlist.txt'], capture_output=True, text=True)

        # Expected output (replace with the actual expected output)
        expected_output = "tom:maverick\n"
        expected_output += "luke:starwars\n"
        expected_output += "mike:jordan\n"

        # Check if the output matches the expected output
        self.assertEqual(result.stdout, expected_output)

    def test_jit_input(self):
        # Create a temporary file with random passwords in the format
        # username:sha256(password)

        with open('passwords.tmp.txt', 'w') as f:
            h = hashlib.sha256()

            h.update('123456'.encode())
            f.write('larry:' + h.hexdigest() + '\n')

            h = hashlib.sha256()

            h.update('password'.encode())
            f.write('curly:' + h.hexdigest() + '\n')

            h = hashlib.sha256()

            h.update('qwerty'.encode())
            f.write('moe:' + h.hexdigest() + '\n')

            h = hashlib.sha256()

            h.update('maverick'.encode())
            f.write('tom:' + h.hexdigest() + '\n')

        # Create a wordlist file with the passwords
        with open('wordlist.tmp.txt', 'w') as f:
            f.write('123456\n')
            f.write('password\n')
            f.write('qwerty\n')

        # Run the script with the sample.txt file
        result = subprocess.run(['python3', 'jill.py', 'passwords.tmp.txt',
            'wordlist.tmp.txt'], capture_output=True, text=True)

        # Remove the temporary files
        subprocess.run(['rm', 'passwords.tmp.txt'])
        subprocess.run(['rm', 'wordlist.tmp.txt'])

        # Expected output (replace with the actual expected output)
        expected_output = "larry:123456\n"
        expected_output += "curly:password\n"
        expected_output += "moe:qwerty\n"

        # Check if the output matches the expected output
        self.assertEqual(result.stdout, expected_output)

if __name__ == '__main__':
    unittest.main()
