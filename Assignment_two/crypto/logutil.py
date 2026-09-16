"""Simple assignment logging."""


def log(role: str, message: str, status: str = "INFO") -> None:
    print(f"[{role}] [{status}] {message}")
