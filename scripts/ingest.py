"""
Ingest CWE and WSTG knowledge base documents into ChromaDB.

Usage:
    python -m scripts.ingest
    python -m scripts.ingest --reset   # drop collections and re-ingest
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from backend.config import settings

CWE_DIR = Path("data/knowledge_base/cwe")
WSTG_DIR = Path("data/knowledge_base/wstg")


def _get_or_create(client: chromadb.PersistentClient, name: str, embed_fn, reset: bool):
    if reset:
        try:
            client.delete_collection(name)
            print(f"Dropped collection: {name}")
        except Exception:
            pass
    return client.get_or_create_collection(
        name=name,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )


def ingest_directory(collection, directory: Path, source: str, batch_size: int = 100) -> int:
    files = list(directory.glob("*.txt"))
    if not files:
        print(f"  No .txt files found in {directory}")
        return 0

    ids, documents, metadatas = [], [], []
    for f in files:
        doc_id = f.stem
        content = f.read_text(encoding="utf-8")
        title = content.splitlines()[0].split(":", 1)[-1].strip() if content else doc_id
        ids.append(doc_id)
        documents.append(content)
        metadatas.append({"source": source, "title": title})

    total = len(ids)
    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        collection.upsert(
            ids=ids[start:end],
            documents=documents[start:end],
            metadatas=metadatas[start:end],
        )
        print(f"    batch {start // batch_size + 1}: {end - start} docs upserted")

    return total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Drop collections before ingesting")
    args = parser.parse_args()

    embed_fn = OpenAIEmbeddingFunction(
        api_key=settings.openai_api_key,
        model_name=settings.openai_embedding_model,
    )
    client = chromadb.PersistentClient(path=settings.chroma_persist_path)

    cwe_col = _get_or_create(client, settings.chroma_collection_cwe, embed_fn, args.reset)
    wstg_col = _get_or_create(client, settings.chroma_collection_wstg, embed_fn, args.reset)

    print(f"Ingesting CWE docs from {CWE_DIR}...")
    n_cwe = ingest_directory(cwe_col, CWE_DIR, "CWE")
    print(f"  {n_cwe} documents ingested into '{settings.chroma_collection_cwe}'")

    print(f"Ingesting WSTG docs from {WSTG_DIR}...")
    n_wstg = ingest_directory(wstg_col, WSTG_DIR, "WSTG")
    print(f"  {n_wstg} documents ingested into '{settings.chroma_collection_wstg}'")

    print(f"\nDone. Total: {n_cwe + n_wstg} documents.")


if __name__ == "__main__":
    main()
