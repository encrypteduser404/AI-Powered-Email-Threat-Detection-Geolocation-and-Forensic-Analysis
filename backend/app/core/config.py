from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    cors_origin: str = "http://localhost:5173"
    max_upload_bytes: int = 10 * 1024 * 1024
    max_body_chars: int = 500_000
    max_header_value_chars: int = 20_000
    parser_version: str = "echo-email-parser-1.0"
    analysis_engine_version: str = "echo-analysis-engine-1.0"
    max_report_records: int = 100

    model_config = SettingsConfigDict(extra="ignore")


settings = Settings()