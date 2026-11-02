"""
## Concepts

The Caesar Cipher (Substitution Cipher): It works by shifting each plaintext letter by a fixed number (shift key) of steps. For example, with a shift of 3, 'A' becomes 'D', 'B' becomes 'E', and so on. It is very predictable.

Frequency Analysis (The Weakness): In any language, we always have letters which repeat themselves much more than others; for example, in English we have the letters "E" and "A". So, an attacker, just by looking at the encrypted text, can likely guess the real letters without even knowing the shift key.

Modern Encryption: With modern encryption like AES(Advanced Encryption Standard), we do not just shift letters. We use complex mathematics, large keys, and multiple rounds of scrambling to ensure confusion and diffusion. This ensures the destruction of the original pattern, making frequency analysis very difficult.

To Brute force a caesar cipher, we can try all possible shift keys (from 0 to 25) and see which one gives us a meaningful plaintext. This is feasible because there are only 26 possible shifts. NB For a broader scope we need to include different alphbets and symbols, but for this example we will only consider the English alphabet.
"""

def shift_letter(letter: str, shift: int) -> str:
    if "A" <= letter <= "Z":
        base = ord("A")
    elif "a" <= letter <= "z":
        base = ord("a")
    else:
        return letter  # Non-letters are returned unchanged.

    position = ord(letter) - base
    new_position = (position + shift) % 26

    return chr(base + new_position)


def caesar_cipher(text: str, shift_key: int) -> str:
    return "".join(shift_letter(letter, shift_key) for letter in text)


def brute_force(ciphertext: str) -> None:
    for shift in range(26):
        candidate = caesar_cipher(ciphertext, -shift)
        print(f"Decrypt shift {shift:2}: {candidate}") 


if __name__ == "__main__":
    text = "I know who did it let's meet at the park at 1pm"
    shift_key = 3

    ciphertext = caesar_cipher(text, shift_key)
    print(f"plaintext: {text}\n"
          f"ciphertext: {ciphertext}")

    recovered_text = caesar_cipher(ciphertext, -shift_key)
    print(f"recovered text: {recovered_text}")

    brute_force(ciphertext)