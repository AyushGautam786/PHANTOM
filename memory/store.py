import chromadb

class PhantomMemory:
    def __init__(self, session_id: str):
        self.session_id = session_id
        # Use EphemeralClient (in-memory) — works on all platforms, no config needed
        self.client = chromadb.EphemeralClient()
        self.collection = self.client.get_or_create_collection(
            name=f"phantom_{session_id}"
        )

    def store(self, agent: str, key: str, data: dict, status: str = "PENDING"):
        import json
        doc_id = f"{agent}_{key}_{self.session_id}"
        try:
            serialized = json.dumps(data)
        except (ValueError, TypeError):
            serialized = json.dumps(data, default=lambda o: str(o))
        self.collection.upsert(
            ids=[doc_id],
            documents=[serialized],
            metadatas=[{"agent": agent, "key": key, "status": status,
                        "session": self.session_id}]
        )

    def get_failed_attempts(self, technique: str) -> list:
        try:
            results = self.collection.query(
                query_texts=[technique],
                n_results=5,
                where={"status": "FAILED"}
            )
            import json
            return [json.loads(doc) for doc in results["documents"][0]]
        except Exception:
            return []

    def get_all(self, agent: str = None) -> list:
        try:
            where = {"agent": agent} if agent else None
            results = self.collection.get(where=where)
            import json
            return [json.loads(doc) for doc in results["documents"]]
        except Exception:
            return []
