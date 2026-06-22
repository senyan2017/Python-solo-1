from __future__ import annotations

import argparse
import sys

from . import a1z26, caesar_cipher, rsa_cipher, vigenere_cipher

ALGORITHMS = {
    "caesar": (caesar_cipher.encrypt_text, caesar_cipher.decrypt_text, int),
    "vigenere": (vigenere_cipher.encrypt_text, vigenere_cipher.decrypt_text, str),
    "rsa": (rsa_cipher.encrypt_text, rsa_cipher.decrypt_text, str),
    "a1z26": (a1z26.encrypt_text, a1z26.decrypt_text, str),
}


def parse_key(raw_key: str, converter):
    try:
        return converter(raw_key)
    except Exception as exc:
        raise argparse.ArgumentTypeError(f"Invalid key format: {exc}")


def get_input(args) -> str:
    if args.text is not None:
        return args.text
    if args.input is not None:
        with open(args.input, "r", encoding="utf-8") as f:
            return f.read()
    return sys.stdin.read()


def write_output(args, content: str) -> None:
    if args.output is not None:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciphers",
        description="Unified command-line tool for common cipher algorithms",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd_name in ("encrypt", "decrypt"):
        sub = subparsers.add_parser(cmd_name, help=f"{cmd_name} a message")
        sub.add_argument(
            "--algorithm",
            "-a",
            required=True,
            choices=sorted(ALGORITHMS.keys()),
            help="Cipher algorithm to use",
        )
        sub.add_argument(
            "--key",
            "-k",
            required=True,
            help="Encryption/decryption key (caesar: int, vigenere: str, rsa: 'n,e'/'n,d', a1z26: unused)",
        )
        src_group = sub.add_mutually_exclusive_group()
        src_group.add_argument("--input", "-i", help="Input file path")
        src_group.add_argument("--text", "-t", help="Input text directly")
        sub.add_argument("--output", "-o", help="Output file path (default: stdout)")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    encrypt_fn, decrypt_fn, key_converter = ALGORITHMS[args.algorithm]
    key = parse_key(args.key, key_converter)
    data = get_input(args)

    if args.command == "encrypt":
        result = encrypt_fn(data, key)
    else:
        result = decrypt_fn(data, key)

    write_output(args, result)


if __name__ == "__main__":
    main()
