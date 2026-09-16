"""Simple assignment logging."""


def log(role: str, message: str, status: str = "INFO") -> None:
    print(f"[{role}] [{status}] {message}")


def fail_text(exc: BaseException) -> str:
    text = str(exc).strip()
    if text:
        return text
    return type(exc).__name__
