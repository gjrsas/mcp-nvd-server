from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    server_name: str = "mcp-nvd-server"
    nvd_api_key: str | None = None
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json"
    http_timeout_seconds: int = 30
    cache_ttl_seconds: int = 900
    log_level: str = "INFO"
    enable_kev: bool = True
    kev_source_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )


settings = Settings()
