"""Contract test (ADR-0016 §8): FastMCP's stock JWTVerifier, configured as
docs/reference/identity-assertion.md shows, accepts the proxy's assertion and refuses one for another
audience, an expired one and one signed with another key.

    python verify.py <fixture dir>   (scripts/assertion/run.sh)
"""

import asyncio
import functools
import http.server
import json
import sys
import threading

from fastmcp.server.auth.providers.jwt import JWTVerifier


def main() -> int:
    fixture_dir = sys.argv[1]
    with open(f"{fixture_dir}/tokens.json") as fh:
        f = json.load(fh)
    # The proxy's JWKS, served on loopback as the proxy serves /.well-known/jwks.json.
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=fixture_dir)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # --- the docs' example ---
    verifier = JWTVerifier(
        jwks_uri=f"http://127.0.0.1:{srv.server_port}/jwks.json",  # the proxy's /.well-known/jwks.json
        issuer=f["issuer"],  # the proxy's public origin
        audience=f["audience"],  # this upstream's URL exactly as the proxy's BYWARD_UPSTREAM_URL says
        algorithm="ES256",
    )
    # --- end of the example ---

    async def run() -> int:
        failed = 0
        ok = await verifier.verify_token(f["valid"])
        if ok is None or ok.client_id != f["client_id"] or ok.claims.get("sub") != f["subject"]:
            print("FAIL valid assertion:", ok, file=sys.stderr)
            failed += 1
        else:
            print("ok   valid assertion accepted")
        for name in ("wrong_audience", "expired", "other_key"):
            if await verifier.verify_token(f[name]) is not None:
                print(f"FAIL {name}: accepted, want refused", file=sys.stderr)
                failed += 1
            else:
                print(f"ok   {name} refused")
        return failed

    failed = asyncio.run(run())
    srv.shutdown()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
