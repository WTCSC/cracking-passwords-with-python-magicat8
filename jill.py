import hashlib
import sys

# Function to hash a password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Jill function to crack passwords based on username:hash and wordlist
def jill(hash_file, wordlist_file):
    found_passwords = []

    # Read the hashes from the hash file (username:hash format)
    try:
        with open(hash_file, 'r') as hash_f:
            user_hash_pairs = [line.strip().split(':') for line in hash_f.readlines()]
    except FileNotFoundError:
        print(f"Error: Hash file '{hash_file}' not found.", file=sys.stderr)
        return 1  # Return an error code to indicate failure

    # Read the wordlist from the wordlist file
    try:
        with open(wordlist_file, 'r') as wordlist_f:
            wordlist = [word.strip() for word in wordlist_f.readlines()]
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.", file=sys.stderr)
        return 1  # Return an error code to indicate failure

    # Attempt to crack each username:hash pair using the wordlist
    for username, password_hash in user_hash_pairs:
        for word in wordlist:
            if hash_password(word) == password_hash:
                found_passwords.append(f"{username}:{word}")
                break  # Move to the next username once password is found

    # Output results in expected format
    if found_passwords:
        print("\n".join(found_passwords))
        return 0  # Success code
    else:
        print("No passwords found.", file=sys.stderr)
        return 2  # Return a different error code to indicate no matches

# If the script is run directly (not imported), parse the command-line arguments
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 jill.py <hash_file> <wordlist_file>", file=sys.stderr)
        sys.exit(1)

    hash_file = sys.argv[1]
    wordlist_file = sys.argv[2]

    # Call the jill function and exit with its return code
    exit_code = jill(hash_file, wordlist_file)
    sys.exit(exit_code)
