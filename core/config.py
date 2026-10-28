from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """.env faylidagi qiymatlarni o'qiydi."""

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
