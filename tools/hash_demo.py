"""
## Concepts

Encryption: Scrambles readable text into an unreadable format using a mathematical algorithm and a key. It is a two-way process that ensures data confidentiality.

Hashing: A one-way algorithm that converts data into a fixed-length string of characters. Hashes help verify integrity when compared against a trusted expected hash.

Salting: The process of adding random characters to a password before hashing it. This ensures that two identical passwords will result in completely different hashes, prevents reuse of precomputed/rainbow tables and forces an attacker to attack each salted hash separately.

Dictionary Attacks: These attacks work against unsalted hashes because an attacker can simply take a list of common passwords, hash them all, and compare their generated hashes to the stolen hashes to reveal the users' passwords.

Avalanche Effect: Ensures that making even a microscopic change to the input—such as capitalizing one letter or adding a single space—completely and unpredictably changes the entire resulting hash.
"""
import hashlib
import secrets


def hash_text(text: str) -> str:
    """Return the SHA-256 hexadecimal digest for text."""
    # we encode because hashlib requires bytes-like objects, not strings
    # hexdigest() returns the hash as a string of hexadecimal digits
    return hashlib.sha256(text.encode()).hexdigest()


if __name__ == "__main__":
    original_text = "Hello"
    changed_text = "hello"

    original_hash = hash_text(original_text)
    changed_hash = hash_text(changed_text)

    print("--- Avalanche effect ---")
    print("Changing one letter's capitalization produces a different hash.")
    print(f"Original text: {original_text} -> Hash: {original_hash}")
    print(f"Changed text:  {changed_text} -> Hash: {changed_hash}")

    salt = secrets.token_hex(16)
    demo_password = "demo123"
    salted_input = salt + demo_password
    unsalted_hash = hash_text(demo_password)
    salted_hash = hash_text(salted_input)

    print("\n--- Salting demonstration ---")
    print(f"Password: {demo_password}")
    print(f"Salt: {salt}")
    print(f"Unsalted hash: {unsalted_hash}")
    print(f"Salted hash:   {salted_hash}")

    # The list and target are fictional values created only for this demo.
    candidate_passwords = ["password1", "password2", "password3", "password4", "password5"]
    target_password = "password3"
    target_unsalted_hash = hash_text(target_password)
    target_salted_hash = hash_text(salt + target_password)

    print("\n--- Dictionary attack demonstration ---")
    for candidate in candidate_passwords:
        candidate_hash = hash_text(candidate)
        if candidate_hash == target_unsalted_hash:
            print(f"The unsalted demo hash matched: {candidate}")
            print(f"The same password with a salt has a different hash: {target_salted_hash}")
            break
    
