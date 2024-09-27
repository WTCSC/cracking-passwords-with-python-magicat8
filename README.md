[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/mzvVphHE)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=16025456)
# Jill the Heckler

Jill the Heckler is a password cracker that uses a dictionary attack to crack
passwords. Your task is to implement the entire program in Python, following the
patterns and tools we have covered in class.

## Files

The following files are provided in this repository:

- `jill.py`: The main program file. This is where you will implement the
  password cracker.
- `passwords.txt`: A file containing usernames and hashed passwords.
- `dictionary.txt`: A file containing passwords to try.
- `test_jill.py`: A test file containing automated tests for the password
  cracker.

## Requirements

Your solution must adhere to the following requirements:

- Jill **must** accept two parameters: a file containing usernames and hashed
  passwords (in the format `username:hashed_password`), and a dictionary file
  containing passwords to try (one word per line).
- Jill **must** run by executing
  `python3 jill.py <password_file> <dictionary_file>`.
- Jill **must** output the cracked passwords in the format `username:password`
  as they are cracked.
- Jill **must** use the `argparse` module to parse command line arguments.
- Jill **must** use the `hashlib` module to hash passwords in SHA-256 format.
- Jull **must not** output passwords that could not be cracked.
- Jill **should** iterate over every line in the dictionary file and compare the
  hashed password with the hashed passwords in the file.
- Jill **should** be tested using the `pytest` command.
- Jill **should** be properly documented using appropriate code comments.
- Jill **should** be tested using your own password and word lists.

### Example Input

```bash
python3 jill.py passwords.txt dictionary.txt
```

### Example Output

```bash
alice:password
bob:password
```

### Extra Credit

If you would like to earn up to 10 points of extra credit on this assignment,
you can implement the following features:

- Jill **should** output the time it took to crack each password when the `-v`
  or `--verbose` flag is provided.
- Jill **should** output the number of passwords that could not be cracked when
  the `-v` or `--verbose` flag is provided.
- Jill **should** be able to change the hashing algorithm used to crack
  passwords by providing the `-a` or `--algorithm` flag, supporting the
  `sha256`, `sha512`, and `md5` algorithms. The default algorithm should be
  `sha256` when the `-a` or `--algorithm` flag is not provided.

#### Example Input

```bash
python3 jill.py passwords.txt dictionary.txt -v -a sha512
```

#### Example Output

```bash
alice:password (0.0001 seconds)
bob:password (0.0002 seconds)
charlie:password (0.0003 seconds)
david:password (0.0004 seconds)

4 passwords could not be cracked.
```

## Hints

The following modules and functions **may** be helpful in your attempt to
complete this project:

- `argparse.ArgumentParser`
- `hashlib.sha256()`
- `hashlib.hexdigest()`
- `file.open()`
- `file.readline()`
- `string.strip()`
- `string.split()`
- `string.encode()`
