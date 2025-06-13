import requests
import base64
import time

# Base URL of the challenge
BASE_URL = "http://rsac-challenges.picoctf.net:54610"

# API Endpoints
STATUS_URL = f"{BASE_URL}/status"
ENCRYPT_URL = f"{BASE_URL}/encrypt"
SOLVE_URL = f"{BASE_URL}/solve"

# Session to persist cookies
session = requests.Session()

# Helper Functions
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def get_score():
    try:
        response = session.get(STATUS_URL)
        response.raise_for_status()
        return response.json().get("score", 0)
    except Exception as e:
        print(f"Error fetching score: {e}")
        return None

def submit_plaintexts(m0, m1, m0_raw, m1_raw):
    try:
        # Log for verification
        print(f"Sending m0 (hex): {m0}")
        print(f"Sending m1 (hex): {m1}")
        print(f"m0 (raw, hex): {m0_raw.hex()}")
        print(f"m1 (raw, hex): {m1_raw.hex()}")
        
        response = session.post(
            ENCRYPT_URL,
            json={"m0": m0, "m1": m1},
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        json_data = response.json()
        if "error" in json_data:
            print(f"Encryption error: {json_data['error']}")
            return None
        ciphertext = json_data["ciphertext"]
        print(f"Received ciphertext: {ciphertext}")
        return ciphertext
    except Exception as e:
        print(f"Error submitting plaintexts: {e}")
        return None

def submit_guess(guess):
    try:
        response = session.post(
            SOLVE_URL,
            json={"guess": guess},
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        json_data = response.json()
        if "flag" in json_data:
            print(f"🎉 FLAG: {json_data['flag']}")
            return True
        print(f"Guess recorded. New score: {json_data.get('score', 'unknown')}")
        return False
    except Exception as e:
        print(f"Error submitting guess: {e}")
        return None

# Attack Logic
def main():
    # Plaintexts (16 bytes each)
    m0_raw = b"\x00" * 16
    m1_raw = b"\x00" * 15 + b"\x01"
    # Encode as hex for JSON
    m0 = m0_raw.hex()  # "00000000000000000000000000000000"
    m1 = m1_raw.hex()  # "00000000000000000000000000000001"
    
    keystream = None
    prev_score = get_score()
    print(f"Initial score: {prev_score}")

    while prev_score is not None and prev_score < 10:
        # Submit plaintexts
        ciphertext_b64 = submit_plaintexts(m0, m1, m0_raw, m1_raw)
        if not ciphertext_b64:
            print("Failed to get ciphertext. Retrying...")
            time.sleep(1)
            continue

        # Decode ciphertext
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            if len(ciphertext) != 32:
                print(f"Unexpected ciphertext length: {len(ciphertext)}")
                break
            c = ciphertext[16:]  # Skip 16-byte IV/nonce
            print(f"Ciphertext (last 16 bytes, hex): {c.hex()}")
        except Exception as e:
            print(f"Error decoding ciphertext: {e}")
            continue

        # Guess logic
        if keystream:
            p = xor_bytes(c, keystream)
            guess = 0 if p == m0_raw else 1 if p == m1_raw else None
            if guess is None:
                print("Keystream mismatch. Resetting keystream.")
                keystream = None
                guess = 0  # Random guess
            else:
                print(f"Decrypted plaintext: {p.hex()}, Guessing b = {guess}")
        else:
            guess = 0  # Random guess until keystream is learned

        # Submit guess
        print(f"Guessing b = {guess} for ciphertext: {ciphertext_b64}")
        result = submit_guess(guess)
        if result is True:  # Flag received
            break
        elif result is None:
            print("Error submitting guess. Retrying...")
            time.sleep(1)
            continue

        # Update keystream if guess was correct
        score = get_score()
        if score is None:
            print("Failed to fetch score. Exiting...")
            break
        if score > prev_score and keystream is None:
            keystream = xor_bytes(c, m0_raw if guess == 0 else m1_raw)
            print(f"Learned keystream: {keystream.hex()}")
        elif score < prev_score:
            print("Incorrect guess. Keystream may be invalid.")
            keystream = None  # Reset if guess was wrong

        prev_score = score
        print(f"Current score: {score}")
        time.sleep(1)  # Avoid overwhelming the server

    if prev_score is not None and prev_score >= 10:
        print("Score reached 10! Check for flag.")
    else:
        print("Attack failed or interrupted.")

if __name__ == "__main__":
    main()