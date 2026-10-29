from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """.env faylidagi qiymatlarni o'qiydi."""

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    # AI: "ollama" (lokal) yoki "anthropic" (bulut)
    ai_provider: str = "ollama"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
