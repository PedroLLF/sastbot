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
MAX_CHARS_PER_CHUNK = 6000
CHUNK_OVERLAP_CHARS = 400


def _chunk_text(text: str, max_chars: int = MAX_CHARS_PER_CHUNK, overlap: int = CHUNK_OVERLAP_CHARS) -> list[str]:
    text = text.strip()
    if not text:
        return []

    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    start = 0
    text_len = len(text)

    while start < text_len:
        end = min(start + max_chars, text_len)
        if end < text_len:
            split_at = text.rfind("\n", start, end)
            if split_at == -1 or split_at <= start + max_chars // 2:
                split_at = text.rfind(". ", start, end)
                if split_at != -1:
                    split_at += 1
            if split_at != -1 and split_at > start:
                end = split_at + 1

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        if end >= text_len:
            break

        start = max(end - overlap, start + 1)

    return chunks


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


def ingest_directory(collection, directory: Path, source: str) -> int:
    files = list(directory.glob("*.txt"))
    if not files:
        print(f"  No .txt files found in {directory}")
        return 0

    ingested = 0
    for f in files:
        doc_id = f.stem
        content = f.read_text(encoding="utf-8")
        # first line is always "ID: Title" — extract title
        title = content.splitlines()[0].split(":", 1)[-1].strip() if content else doc_id

        chunks = _chunk_text(content)
        if not chunks:
            continue

        for chunk_index, chunk in enumerate(chunks, start=1):
            chunk_id = f"{doc_id}::chunk{chunk_index:03d}" if len(chunks) > 1 else doc_id
            collection.upsert(
                ids=[chunk_id],
                documents=[chunk],
                metadatas=[
                    {
                        "source": source,
                        "title": title,
                        "source_id": doc_id,
                        "chunk_index": chunk_index,
                        "chunk_count": len(chunks),
                    }
                ],
            )
            ingested += 1

    return ingested


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
