from dataclasses import dataclass
import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from .config import settings

_embedding_fn = OpenAIEmbeddingFunction(
    api_key=settings.openai_api_key,
    model_name=settings.openai_embedding_model,
)

_client = chromadb.PersistentClient(path=settings.chroma_persist_path)

_cwe_collection = _client.get_or_create_collection(
    name=settings.chroma_collection_cwe,
    embedding_function=_embedding_fn,
    metadata={"hnsw:space": "cosine"},
)

_wstg_collection = _client.get_or_create_collection(
    name=settings.chroma_collection_wstg,
    embedding_function=_embedding_fn,
    metadata={"hnsw:space": "cosine"},
)


@dataclass
class RetrievedDoc:
    id: str
    source: str   # "CWE" or "WSTG"
    title: str
    content: str


def query_knowledge(query_text: str) -> list[RetrievedDoc]:
    """Query both collections and return merged results."""
    results: list[RetrievedDoc] = []

    for collection, source in ((_cwe_collection, "CWE"), (_wstg_collection, "WSTG")):
        count = collection.count()
        if count == 0:
            continue
        k = min(
            settings.top_k_cwe if source == "CWE" else settings.top_k_wstg,
            count,
        )
        hits = collection.query(query_texts=[query_text], n_results=k)
        for i, doc_id in enumerate(hits["ids"][0]):
            results.append(
                RetrievedDoc(
                    id=doc_id,
                    source=source,
                    title=hits["metadatas"][0][i].get("title", doc_id),
                    content=hits["documents"][0][i],
                )
            )

    return results
