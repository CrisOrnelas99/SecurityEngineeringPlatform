import json
import os
import subprocess
from typing import Any


class CryptoCoreClient:
    def __init__(self) -> None:
        self.binary = os.getenv("SECURITY_CORE_BIN", "security_core")
        self.jwt_secret = os.getenv("JWT_ACCESS_SECRET", "")

    def _run(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            [self.binary, operation],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            return {"success": False, "error": proc.stderr.decode("utf-8")[:256]}
        try:
            return json.loads(proc.stdout.decode("utf-8"))
        except json.JSONDecodeError:
            return {"success": False, "error": "invalid json from core"}

    def verify_jwt(self, token: str) -> dict[str, Any]:
        if not self.jwt_secret:
            return {"success": False, "error": "missing JWT_ACCESS_SECRET"}
        return self._run("verify-jwt", {"token": token, "secret": self.jwt_secret})
