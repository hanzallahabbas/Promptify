# =============================================================
#  PROMPTIFY — User Schema and Model
#  File: models/user.py
# =============================================================

import bcrypt
from datetime import datetime, timezone

class User:
    """
    User model representing the user document stored in MongoDB.
    
    Fields:
      - name: str (1-100 chars)
      - email: str (validated, unique)
      - password: bytes (bcrypt hash)
      - created_at: datetime
    """
    def __init__(self, name, email, password, created_at=None):
        self.name = name.strip()
        self.email = email.strip().lower()
        self.password = password  # This is the bcrypt hashed bytes
        self.created_at = created_at or datetime.now(timezone.utc)

    @staticmethod
    def validate_registration_input(name, email, password):
        """
        Validates input for registration. Returns (True, None) if valid,
        or (False, "error message") if invalid.
        """
        if not name or not email or not password:
            return False, "Name, email, and password are all required."
        
        if len(name) < 2 or len(name) > 100:
            return False, "Name must be between 2 and 100 characters."

        if '@' not in email or '.' not in email:
            return False, "Please enter a valid email address."

        if len(password) < 6:
            return False, "Password must be at least 6 characters."

        return True, None

    @staticmethod
    def hash_password(password_plain):
        """
        Hashes password with bcrypt.
        """
        return bcrypt.hashpw(
            password_plain.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        )

    @staticmethod
    def verify_password(password_plain, password_hash):
        """
        Checks if the plain password matches the bcrypt hash.
        """
        if isinstance(password_hash, str):
            password_hash = password_hash.encode('utf-8')
        return bcrypt.checkpw(password_plain.encode('utf-8'), password_hash)

    def to_dict(self):
        """
        Converts the User instance into a dictionary suitable for MongoDB.
        """
        return {
            "name": self.name,
            "email": self.email,
            "password": self.password,
            "created_at": self.created_at
        }

    @classmethod
    def from_dict(cls, data):
        """
        Creates a User instance from a MongoDB document.
        """
        if not data:
            return None
        return cls(
            name=data.get("name"),
            email=data.get("email"),
            password=data.get("password"),
            created_at=data.get("created_at")
        )
