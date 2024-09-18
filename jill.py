import hashlib

def jill(password_file, password_dict):
    found_passwords = {}
    
    # Read the password file
    with open(password_file, 'r') as file:
        lines = file.readlines()
    
    # Iterate through each line in the password file
    for line in lines:
        user, hashed_password = line.strip().split(':')
        
        # Check each password in the dictionary
        for password in password_dict:
            # Hash the password using the same algorithm (assuming SHA-256)
            hashed = hashlib.sha256(password.encode()).hexdigest()
            
            # Compare the hashed password with the one in the file
            if hashed == hashed_password:
                found_passwords = f"{user}:{password}"
                break
    
    return found_passwords

# Example usage
password_file = 'passwords.txt'
password_dict = 'wordlist.txt'
found = jill(password_file, password_dict)
print(found)
