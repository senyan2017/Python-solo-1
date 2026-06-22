"""
Test suite for unified cipher interfaces and CLI.
"""

import io
import os
import sys
import tempfile
import unittest

from ciphers import a1z26, caesar_cipher, rsa_cipher, vigenere_cipher
from ciphers.cli import main as cli_main


class TestCaesarCipher(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "The quick brown fox jumps over the lazy dog"
        key = 8
        ciphertext = caesar_cipher.encrypt_text(plaintext, key)
        decrypted = caesar_cipher.decrypt_text(ciphertext, key)
        assert decrypted == plaintext

    def test_encrypt_known_vector(self):
        assert caesar_cipher.encrypt_text("Hello, captain", 2) == "Jgnnq, ecrvckp"

    def test_decrypt_known_vector(self):
        assert caesar_cipher.decrypt_text("Jgnnq, ecrvckp", 2) == "Hello, captain"


class TestVigenereCipher(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "This is Harshil Darji from Dharmaj."
        key = "HDarji"
        ciphertext = vigenere_cipher.encrypt_text(plaintext, key)
        decrypted = vigenere_cipher.decrypt_text(ciphertext, key)
        assert decrypted == plaintext

    def test_encrypt_known_vector(self):
        assert (
            vigenere_cipher.encrypt_text("This is Harshil Darji from Dharmaj.", "HDarji")
            == "Akij ra Odrjqqs Gaisq muod Mphumrs."
        )

    def test_decrypt_known_vector(self):
        assert (
            vigenere_cipher.decrypt_text("Akij ra Odrjqqs Gaisq muod Mphumrs.", "HDarji")
            == "This is Harshil Darji from Dharmaj."
        )


class TestA1Z26Cipher(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "myname"
        ciphertext = a1z26.encrypt_text(plaintext)
        decrypted = a1z26.decrypt_text(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_known_vector(self):
        assert a1z26.encrypt_text("myname") == "13 25 14 1 13 5"

    def test_decrypt_known_vector(self):
        assert a1z26.decrypt_text("13 25 14 1 13 5") == "myname"

    def test_key_parameter_ignored(self):
        assert a1z26.encrypt_text("abc", "unused_key") == "1 2 3"
        assert a1z26.decrypt_text("1 2 3", "unused_key") == "abc"


class TestRSACipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = rsa_cipher.rkg.generate_key(16)
        cls.pub_str = f"{cls.public_key[0]},{cls.public_key[1]}"
        cls.priv_str = f"{cls.private_key[0]},{cls.private_key[1]}"

    def test_parse_key(self):
        n, e = rsa_cipher._parse_rsa_key(self.pub_str)
        assert (n, e) == self.public_key

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "Hello RSA World"
        ciphertext = rsa_cipher.encrypt_text(plaintext, self.pub_str)
        decrypted = rsa_cipher.decrypt_text(ciphertext, self.priv_str)
        assert decrypted == plaintext

    def test_short_message(self):
        plaintext = "Hi"
        ciphertext = rsa_cipher.encrypt_text(plaintext, self.pub_str)
        decrypted = rsa_cipher.decrypt_text(ciphertext, self.priv_str)
        assert decrypted == plaintext

    def test_invalid_key_format(self):
        with self.assertRaises(ValueError):
            rsa_cipher._parse_rsa_key("not_a_key")

    def test_invalid_ciphertext_format(self):
        with self.assertRaises(ValueError):
            rsa_cipher.decrypt_text("bad_format", self.priv_str)
        with self.assertRaises(ValueError):
            rsa_cipher.decrypt_text("12_abc", self.priv_str)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.tmp_dir):
            os.remove(os.path.join(self.tmp_dir, f))
        os.rmdir(self.tmp_dir)

    def _run_cli(self, argv):
        old_stdout = sys.stdout
        old_stdin = sys.stdin
        sys.stdout = io.StringIO()
        try:
            cli_main(argv)
            return sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
            sys.stdin = old_stdin

    def test_caesar_encrypt_text_arg(self):
        output = self._run_cli(
            ["encrypt", "--algorithm", "caesar", "--key", "3", "--text", "Hello"]
        )
        assert output.strip() == "Khoor"

    def test_caesar_decrypt_text_arg(self):
        output = self._run_cli(
            ["decrypt", "--algorithm", "caesar", "--key", "3", "--text", "Khoor"]
        )
        assert output.strip() == "Hello"

    def test_caesar_file_roundtrip(self):
        input_path = os.path.join(self.tmp_dir, "plain.txt")
        output_path = os.path.join(self.tmp_dir, "cipher.txt")
        decrypt_path = os.path.join(self.tmp_dir, "decrypted.txt")
        original = "The quick brown fox"

        with open(input_path, "w") as f:
            f.write(original)

        self._run_cli(
            [
                "encrypt",
                "--algorithm",
                "caesar",
                "--key",
                "5",
                "--input",
                input_path,
                "--output",
                output_path,
            ]
        )
        assert os.path.exists(output_path)

        self._run_cli(
            [
                "decrypt",
                "--algorithm",
                "caesar",
                "--key",
                "5",
                "--input",
                output_path,
                "--output",
                decrypt_path,
            ]
        )
        with open(decrypt_path) as f:
            assert f.read() == original

    def test_vigenere_text_arg(self):
        output = self._run_cli(
            [
                "encrypt",
                "--algorithm",
                "vigenere",
                "--key",
                "KEY",
                "--text",
                "ATTACK",
            ]
        )
        decrypted = self._run_cli(
            [
                "decrypt",
                "--algorithm",
                "vigenere",
                "--key",
                "KEY",
                "--text",
                output.strip(),
            ]
        )
        assert decrypted.strip() == "ATTACK"

    def test_a1z26_text_arg(self):
        output = self._run_cli(
            ["encrypt", "--algorithm", "a1z26", "--key", "x", "--text", "abc"]
        )
        assert output.strip() == "1 2 3"
        decrypted = self._run_cli(
            ["decrypt", "--algorithm", "a1z26", "--key", "x", "--text", "1 2 3"]
        )
        assert decrypted.strip() == "abc"

    def test_rsa_roundtrip(self):
        public_key, private_key = rsa_cipher.rkg.generate_key(16)
        pub_str = f"{public_key[0]},{public_key[1]}"
        priv_str = f"{private_key[0]},{private_key[1]}"

        encrypted = self._run_cli(
            [
                "encrypt",
                "--algorithm",
                "rsa",
                "--key",
                pub_str,
                "--text",
                "Test RSA",
            ]
        )
        decrypted = self._run_cli(
            [
                "decrypt",
                "--algorithm",
                "rsa",
                "--key",
                priv_str,
                "--text",
                encrypted.strip(),
            ]
        )
        assert decrypted.strip() == "Test RSA"


if __name__ == "__main__":
    unittest.main()
