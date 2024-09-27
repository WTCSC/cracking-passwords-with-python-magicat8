import hashlib
import sys
import argparse
import time

# Function to hash a password using a given algorithm
def hash_password(password, algorithm):
    if algorithm == 'sha256':
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode('utf-8')).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(password.encode('utf-8')).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

# Jill function to crack passwords based on username:hash and wordlist
def jill(hash_file, wordlist_file, algorithm='sha256', verbose=False):
    found_passwords = []
    not_found_count = 0

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
        start_time = time.time()  # Start timer
        cracked = False

        for word in wordlist:
            if hash_password(word, algorithm) == password_hash:
                elapsed_time = time.time() - start_time  # Time taken to crack
                if verbose:
                    found_passwords.append(f"{username}:{word} ({elapsed_time:.4f} seconds)")
                else:
                    found_passwords.append(f"{username}:{word}")
                cracked = True
                break  # Move to the next username once password is found

        if not cracked:
            not_found_count += 1

    # Output found passwords
    if found_passwords:
        print("\n".join(found_passwords))

    # Output number of passwords that could not be cracked if verbose is enabled
    if verbose:
        print(f"\n{not_found_count} passwords could not be cracked.")

    # Return success code if any passwords were found
    return 0 if found_passwords else 2

# If the script is run directly (not imported), parse the command-line arguments
if __name__ == "__main__":
    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description="Jill - Password Cracking Tool")
    parser.add_argument("hash_file", help="File containing usernames and password hashes (username:hash format)")
    parser.add_argument("wordlist_file", help="File containing the list of potential passwords")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (time to crack, number of failures)")
    parser.add_argument("-a", "--algorithm", choices=['sha256', 'sha512', 'md5'], default='sha256',
                        help="Hashing algorithm to use (default: sha256)")

    # Parse the arguments
    args = parser.parse_args()

    # Call the jill function with parsed arguments
    exit_code = jill(args.hash_file, args.wordlist_file, args.algorithm, args.verbose)
    sys.exit(exit_code)
