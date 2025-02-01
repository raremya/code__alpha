import hashlib


correct_username = "admin"
correct_password_hash = hashlib.sha256("password123".encode()).hexdigest()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(username, password):
    # Hash the entered password
    password_hash = hash_password(password)


    if username == correct_username and password_hash == correct_password_hash:
        return True
    return False


def main():
    try:

        username = input("Enter your username: ")
        password = input("Enter your password: ")


        if not username or not password:
            raise ValueError("Username and password cannot be empty.")

        if authenticate(username, password):
            print("Access granted.")
        else:
            print("Access denied.")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
