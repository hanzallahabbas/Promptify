# =============================================================
#  PROMPTIFY — Prompt History Schema and Model
#  File: models/prompt_history.py
# =============================================================

from datetime import datetime, timezone

class PromptHistory:
    """
    PromptHistory model representing the prompt scan record in MongoDB history_col.
    
    Fields:
      - user_email: str
      - user_name: str
      - original: str
      - sanitized: str
      - risk_level: str ("safe", "medium", "high")
      - risk_score: int (0-100)
      - detected: dict (e.g. {"email": 1, "cnic": 2})
      - mode: str ("strict", "minimal", "standard")
      - timestamp: datetime
    """
    def __init__(self, user_email, user_name, original, sanitized, risk_level, risk_score, detected, mode, timestamp=None):
        self.user_email = user_email.strip().lower()
        self.user_name = user_name.strip()
        self.original = original
        self.sanitized = sanitized
        self.risk_level = risk_level
        self.risk_score = int(risk_score)
        self.detected = detected or {}
        self.mode = mode
        self.timestamp = timestamp or datetime.now(timezone.utc)

    @staticmethod
    def validate_scan_data(original, mode):
        """
        Validates the input parameters for a scan database entry.
        """
        if not original:
            return False, "Original prompt content cannot be empty."
        if mode not in ("standard", "minimal", "strict"):
            return False, "Invalid scan mode."
        return True, None

    def to_dict(self):
        """
        Converts the PromptHistory instance into a dictionary suitable for MongoDB.
        """
        return {
            "user_email": self.user_email,
            "user_name": self.user_name,
            "original": self.original,
            "sanitized": self.sanitized,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "detected": self.detected,
            "mode": self.mode,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data):
        """
        Creates a PromptHistory instance from a MongoDB document.
        """
        if not data:
            return None
        return cls(
            user_email=data.get("user_email"),
            user_name=data.get("user_name"),
            original=data.get("original"),
            sanitized=data.get("sanitized"),
            risk_level=data.get("risk_level"),
            risk_score=data.get("risk_score"),
            detected=data.get("detected"),
            mode=data.get("mode"),
            timestamp=data.get("timestamp")
        )
