from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    BASE_URL: str = "http://localhost:8080"

    SECRET_KEY: str = "dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    AUTH_CODE_EXPIRE_MINUTES: int = 10

    DATABASE_URL: str = "sqlite+aiosqlite:///./mcp_oauth.db"

    REQUIRE_PKCE: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
