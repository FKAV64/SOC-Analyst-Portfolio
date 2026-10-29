"""
## Concepts

Password EntropyEntropy is a mathematical measurement of how unpredictable a password is. Measured in bits, it calculates the total number of possible combinations an attacker would have to guess to find the correct password. The formula relies on two factors: the size of the character pool (e.g., 52 upper and lowercase letters, 10 numbers, 32 symbols) and the length of the password. High entropy means a brute-force attack would take an extremely long time (centuries); low entropy means it takes milliseconds.

Length vs. ComplexityA long simple password has a higher entropy than a short complex password. For example, an 8-character password has a pool of 94, thus $94^8$ combinations (about 6 quadrillion), but a 16-character password only using lowercase letters (a pool of 26) yields $26^{16}$ combinations (about 43 million quadrillion).

Common-Password Lists It is a dataset of all passwords which happen to be breached (e.g., rockyou.txt). If you have a high entropy password, but that password happens to be in the common-password lists, then it will take attackers no time to get access to your account. Because before attackers start guessing your password, they start their brute-force attacks with the common-password list.
"""
import math
import string
import getpass


MINIMUM_LENGTH = 8
DEMO_COMMON_PASSWORDS = {"demo-only-password", "example-not-secret"}

def is_too_short(password: str, min_length: int) -> bool:
    """Return whether the password has fewer characters than the minimum."""
    return len(password) < min_length

def estimate_entropy(password: str) -> float:
    """Estimate bits from ASCII-style character groups; this is not a strength verdict."""
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    
    if pool_size == 0:
        return 0.0
    
    return len(password) * math.log2(pool_size)

def is_common_password(password: str, common_passwords: set[str]) -> bool:
    """Return whether the password exactly matches an entry in the supplied set."""
    return password in common_passwords


if __name__ == "__main__":

    """Prompt for a password and display the checker signals without storing it."""
    password = getpass.getpass("Enter a password (input is hidden): ")

    length_status = (
        f"below the {MINIMUM_LENGTH}-character minimum"
        if is_too_short(password, MINIMUM_LENGTH)
        else f"meets the {MINIMUM_LENGTH}-character minimum"
    )
    entropy = estimate_entropy(password)
    common_match = is_common_password(password, DEMO_COMMON_PASSWORDS)

    print(f"Length: {len(password)} characters ({length_status}).")
    print(f"Estimated entropy: {entropy:.1f} bits (rough estimate only).")
    print(
        "Demo common-password list: "
        + ("exact match found." if common_match else "no exact match found.")
    )

