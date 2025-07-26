import jwt
import httpx
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional, Dict

logger = logging.getLogger("middleware")
logging.basicConfig(level=logging.INFO) 

class AuthAndGatekeeperMiddleware(BaseHTTPMiddleware):
    
    def __init__(self, app, gatekeeper_url: str, http_client: Optional[httpx.AsyncClient] = None):
        super().__init__(app)
        self.gatekeeper_url = gatekeeper_url.rstrip("/")
        self.http_client = http_client or httpx.AsyncClient()

    async def dispatch(self, request: Request, call_next):
        # Step 1: Token validation
        auth_result = self._extract_token(request)
        if isinstance(auth_result, JSONResponse):
            return auth_result

        request.state.realm = auth_result["realm"]
        request.state.token_payload = auth_result["payload"]

        # Step 2: Gatekeeper validation
        validation_result = await self._validate_with_gatekeeper(request)
        if isinstance(validation_result, JSONResponse):
            return validation_result

        request.state.validation = validation_result

        # Step 3: Call route handler and return response
        response = await call_next(request)

        # Step 4: Record usage (after response)
        await self._record_usage(request)

        return response

    def _extract_token(self, request: Request) -> Dict | JSONResponse:
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse({"detail": "Missing or invalid auth token"}, status_code=401)

        token = auth_header[7:]

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            realm = payload.get("realm")
            if not realm:
                raise ValueError("Missing 'realm'")
            logger.debug(f"Token realm: {realm}")
            return {"realm": realm, "payload": payload}
        except Exception as e:
            logger.warning(f"JWT error: {str(e)}")
            return JSONResponse({"detail": f"Invalid token: {str(e)}"}, status_code=401)

    async def _validate_with_gatekeeper(self, request: Request) -> Dict | JSONResponse:
        realm = request.state.realm
        method = request.method
        path = request.url.path

        payload = {
            "organization_name": realm,
            "method": method,
            "path": path,
        }

        try:
            logger.debug(f"Calling gatekeeper for {realm} {method} {path}")
            response = await self.http_client.post(f"{self.gatekeeper_url}/validate", json=payload)

            if response.status_code != 200:
                return JSONResponse({"detail": "Unauthorized by gatekeeper"}, status_code=403)

            return response.json()
        except Exception as e:
            logger.error(f"Gatekeeper validation error: {str(e)}")
            return JSONResponse({"detail": f"Gatekeeper validation failed: {str(e)}"}, status_code=500)

    async def _record_usage(self, request: Request) -> None:
        try:
            realm = request.state.realm
            method = request.method
            path = request.url.path

            usage_payload = {
                "organization_name": realm,
                "method": method,
                "path": path,
            }

            logger.debug(f"Recording usage for {realm} {method} {path}")
            response = await self.http_client.post(f"{self.gatekeeper_url}/usage", json=usage_payload)

            if response.status_code != 200:
                logger.warning(f"Usage recording failed: {response.status_code} {response.text}")
            else:
                logger.debug(f"Usage recorded: {response.text}")
        except Exception as e:
            logger.error(f"Usage recorder error: {str(e)}")
