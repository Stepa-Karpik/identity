from fastapi import FastAPI

app = FastAPI(title="identity")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "identity"}
