"""
Convert a string of characters to a sequence of numbers
corresponding to the character's position in the alphabet.

https://www.dcode.fr/letter-number-cipher
http://bestcodes.weebly.com/a1z26.html
"""

from __future__ import annotations


def encode(plain: str) -> list[int]:
    """
    >>> encode("myname")
    [13, 25, 14, 1, 13, 5]
    """
    return [ord(elem) - 96 for elem in plain]


def decode(encoded: list[int]) -> str:
    """
    >>> decode([13, 25, 14, 1, 13, 5])
    'myname'
    """
    return "".join(chr(elem + 96) for elem in encoded)


def encrypt_text(text: str, key: str | None = None) -> str:
    """
    Unified encrypt interface for CLI: (text, key) -> ciphertext
    A1Z26 has no key, the key parameter is ignored.
    Returns space-separated numbers as string.
    """
    encoded = encode(text.lower())
    return " ".join(str(x) for x in encoded)


def decrypt_text(ciphertext: str, key: str | None = None) -> str:
    """
    Unified decrypt interface for CLI: (ciphertext, key) -> plaintext
    A1Z26 has no key, the key parameter is ignored.
    Expects space-separated numbers as string.
    """
    encoded = [int(x) for x in ciphertext.split()]
    return decode(encoded)


def main() -> None:
    encoded = encode(input("-> ").strip().lower())
    print("Encoded: ", encoded)
    print("Decoded:", decode(encoded))


if __name__ == "__main__":
    main()
