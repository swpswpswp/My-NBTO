import os


def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


DATABASE_URL = env("DATABASE_URL") or "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/sim"
JWT_SECRET = env("JWT_SECRET") or "dev-secret-change-me"
JWT_ALGO = env("JWT_ALGO") or "HS256"
ACCESS_MINUTES = int(env("ACCESS_MINUTES", "720") or "720")
AUTO_CREATE_TABLES = (env("AUTO_CREATE_TABLES", "1") or "1") == "1"
