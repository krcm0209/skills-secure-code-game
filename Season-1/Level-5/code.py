# Welcome to Secure Code Game Season-1/Level-5!

# This is the last level of our first season, good luck!

import binascii
import secrets
import hashlib
import os
import bcrypt

class Random_generator:

    # generates a random token
    def generate_token(self, length=8, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    )):
        # SECURITY FIX: Use secrets module instead of random for cryptographically secure token generation
        # The random module uses a pseudorandom generator unsuitable for security purposes
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    # generates salt
    def generate_salt(self, rounds=12):
        # SECURITY FIX: Use bcrypt's built-in secure salt generation instead of weak random generation
        # Original implementation used weak randomness and limited character set (only digits)
        # bcrypt.gensalt() provides cryptographically secure salts with full entropy
        return bcrypt.gensalt(rounds)

class SHA256_hasher:

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = bcrypt.hashpw(password, salt)
        return password_hash.decode('ascii')

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = password_hash.encode('ascii')
        return bcrypt.checkpw(password, password_hash)

class MD5_hasher:

    # same as above but using a different algorithm to hash which is MD5
    def password_hash(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def password_verification(self, password, password_hash):
        password = self.password_hash(password)
        return secrets.compare_digest(password.encode(), password_hash.encode())

# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
# SECURITY FIX: Load SECRET_KEY from environment variable with secure fallback
# Hardcoded secrets in source code are a critical security vulnerability
# Anyone with access to the code can see and use the secret key
# If no environment variable is set, generate a secure random key
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
# SECURITY FIX: Use SHA256_hasher as default instead of the cryptographically broken MD5_hasher
# MD5 is vulnerable to collision attacks and should not be used for password hashing
PASSWORD_HASHER = 'SHA256_hasher'


# Contribute new levels to the game in 3 simple steps!
# Read our Contribution Guideline at github.com/skills/secure-code-game/blob/main/CONTRIBUTING.md