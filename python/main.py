from fastapi import FastAPI, Request
from middleware import AuthAndGatekeeperMiddleware

app = FastAPI()

app.add_middleware(
    AuthAndGatekeeperMiddleware,
    gatekeeper_url="http://localhost:8082/gatekeeper"
)

@app.get("/")
async def root(request: Request):
    return {
        "message": "Hello World",
        "realm": getattr(request.state, "realm", None),
        "validation": getattr(request.state, "validation", None)
    }

@app.post("/question")
async def question(request: Request):
    return {
        "message": "This is a validated /question endpoint.",
        "token_payload": getattr(request.state, "token_payload", None),
        "validation": getattr(request.state, "validation", None),
    }

@app.get("/question")
async def question(request: Request):
    return {
        "message": "This is a validated /question endpoint.",
        "token_payload": getattr(request.state, "token_payload", None),
        "validation": getattr(request.state, "validation", None),
    }