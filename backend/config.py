from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    openai_api_key: str
    openai_chat_model: str = "gpt-4.1"
    openai_embedding_model: str = "text-embedding-3-small"
    chroma_persist_path: str = "./chroma_data"
    chroma_collection_cwe: str = "cwe_docs"
    chroma_collection_wstg: str = "wstg_docs"
    top_k_cwe: int = 2
    top_k_wstg: int = 2

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
