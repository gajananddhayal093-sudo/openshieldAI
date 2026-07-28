import hashlib
import base64
import urllib.parse
import string
import random


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def check_password_strength(password):
    if len(password) < 8:
        return "Weak (Too short)"

    if (any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in string.punctuation for c in password)):
        return "Strong"

    return "Medium"


def get_hash(text, algo):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()


def main():
    while True:
        print("\n--- Security Tools ---")
        print("1. Password Generator")
        print("2. Password Strength Checker")
        print("3. MD5 Hash")
        print("4. SHA1 Hash")
        print("5. SHA256 Hash")
        print("6. Base64 Encode/Decode")
        print("7. URL Encode/Decode")
        print("8. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            print("Generated Password:", generate_password())

        elif choice == '2':
            pwd = input("Enter password: ")
            print("Strength:", check_password_strength(pwd))

        elif choice == '3':
            text = input("Enter text: ")
            print("MD5:", get_hash(text, 'md5'))

        elif choice == '4':
            text = input("Enter text: ")
            print("SHA1:", get_hash(text, 'sha1'))

        elif choice == '5':
            text = input("Enter text: ")
            print("SHA256:", get_hash(text, 'sha256'))

        elif choice == '6':
            mode = input("E for Encode, D for Decode: ").upper()
            text = input("Enter text: ")

            if mode == 'E':
                print(base64.b64encode(text.encode()).decode())
            elif mode == 'D':
                print(base64.b64decode(text).decode())
            else:
                print("Invalid mode!")

        elif choice == '7':
            mode = input("E for Encode, D for Decode: ").upper()
            text = input("Enter text: ")

            if mode == 'E':
                print(urllib.parse.quote(text))
            elif mode == 'D':
                print(urllib.parse.unquote(text))
            else:
                print("Invalid mode!")

        elif choice == '8':
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
