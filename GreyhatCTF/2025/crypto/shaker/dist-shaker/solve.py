from pwn import *
import hashlib

# Define the known alphabet
alphabet = b'01234567_abcdefghiklnoqrtuvwyz{}'

# Initialize the flag array with known characters
flag = [0 for _ in range(64)]
flag[:29] = b'grey{kinda_long_flag_but_what'
flag[-1:] = b'}'

# Function to perform one iteration: connect, open twice, and get possible characters for a given position
def get_possible_chars(pos):
    try:
        # Connect to the server
        io = remote("challs.nusgreyhats.org", 33302)

        # First open
        io.sendlineafter(b'> ', b'2')
        io.recvuntil(b'Result: ')
        ct = bytes.fromhex(io.recvline().rstrip().decode())

        # Compute x for the given position based on the first ciphertext
        mapping = {}
        for i in alphabet:
            mapping[i] = ct[pos] ^ i

        # Second open
        io.sendlineafter(b'> ', b'2')
        io.recvuntil(b'Result: ')
        ct = bytes.fromhex(io.recvline().rstrip().decode())

        # Find possible characters
        possible_word = []
        for key in mapping.keys():
            x_ = mapping[key] ^ ct[pos]
            if x_ in alphabet:
                possible_word.append(key)

        # Close the connection
        io.close()
        return set(possible_word)  # Return as a set for intersection

    except Exception as e:
        print(f"Error in connection for position {pos}: {e}")
        return set()

# Main logic
def main():
    max_iterations = 50  # Maximum iterations per position to prevent infinite loops

    # Iterate over each unknown position (29 to 62)
    for pos in range(29, 63):
        if flag[pos] != 0:  # Skip known positions
            continue

        print(f"\nBrute-forcing position {pos}")
        intersection = None
        iteration = 0

        # Keep collecting sets until a single character is found or max iterations reached
        while True:
            iteration += 1
            if iteration > max_iterations:
                print(f"Reached maximum iterations ({max_iterations}) for position {pos} without finding a unique character.")
                return

            print(f"Iteration {iteration} for position {pos}")
            possible_chars = get_possible_chars(pos)
            if not possible_chars:
                print("No characters found in this iteration")
                continue

            print(f"Possible characters: {possible_chars}")
            
            # Update intersection
            if intersection is None:
                intersection = possible_chars
            else:
                intersection &= possible_chars

            print(f"Current intersection: {intersection}")
            
            # Check intersection size
            if len(intersection) == 1:
                # Found a unique character
                char = list(intersection)[0]
                flag[pos] = char  # Update the flag array
                print(f"Likely character at position {pos}: {chr(char)}")
                print(f"Current flag: {bytes(flag)}")
                break
            elif len(intersection) == 0:
                print(f"Intersection became empty for position {pos}. Check alphabet or server behavior.")
                return

    # Print and verify the final flag
    final_flag = bytes(flag)
    print(f"\nFinal flag: {final_flag.decode(errors='replace')}")
    
    # Verify MD5 hash
    md5_hash = hashlib.md5(final_flag).hexdigest()
    expected_hash = "4839d730994228d53f64f0dca6488f8d"
    if md5_hash == expected_hash:
        print("Flag verified with MD5 hash!")
    else:
        print(f"Flag does not match MD5 hash. Got {md5_hash}, expected {expected_hash}.")

if __name__ == "__main__":
    main()