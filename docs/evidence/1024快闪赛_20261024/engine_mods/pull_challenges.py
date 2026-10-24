#!/usr/bin/env python3
"""Pull challenges from a CTFd instance to a local directory.

CTFd interaction and HTML helpers based on es3n1n/Eruditus
(https://github.com/es3n1n/Eruditus) — thank you!

Usage:
    python pull_challenges.py --url https://ctf.example.com \
        --username myteam --password s3cr3t [--output ./challenges]

    python pull_challenges.py --url https://ctf.example.com \
        --token ctfd_abc123... [--output ./challenges]

Directory layout:
    <output>/<challenge-slug>/
        metadata.yml   # name, description, value, tags, connection_info, hints
        distfiles/     # attached files
"""

import argparse
import asyncio
import io
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

import aiohttp
from bs4 import BeautifulSoup
from markdownify import markdownify as html2md

USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def token_headers(token: str) -> dict:
    return {"User-Agent": USER_AGENT, "Authorization": f"Token {token}"}


async def login_password(session: aiohttp.ClientSession, base_url: str, username: str, password: str) -> bool:
    """Login to CTFd and populate session cookies. Returns True on success."""
    # Fetch login page to get nonce + initial cookies
    async with session.get(f"{base_url}/login", headers={"User-Agent": USER_AGENT}) as resp:
        nonce_tag = BeautifulSoup(await resp.text(), "html.parser").find("input", {"id": "nonce"})
        if nonce_tag is None:
            print("ERROR: Could not find nonce on login page.", file=sys.stderr)
            return False
        nonce = nonce_tag["value"]

    # POST credentials
    async with session.post(
        f"{base_url}/login",
        data={
            "name": username,
            "password": password,
            "_submit": "Submit",
            "nonce": nonce,
        },
        headers={"User-Agent": USER_AGENT},
        allow_redirects=False,
    ) as resp:
        # CTFd redirects (302) on success; 200 means wrong credentials
        if resp.status == 200:
            print("ERROR: Login failed — bad credentials?", file=sys.stderr)
            return False
        return True


async def verify_token(base_url: str, token: str) -> bool:
    """Check that the token is valid by hitting /api/v1/users/me."""
    async with aiohttp.request(
        method="get",
        url=f"{base_url}/api/v1/users/me",
        headers=token_headers(token),
        allow_redirects=False,
        ssl=False,
    ) as resp:
        if resp.status != 200:
            print("ERROR: Token auth failed — invalid token?", file=sys.stderr)
            return False
        data = await resp.json()
        return data.get("success", False)


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

async def api_get(session: aiohttp.ClientSession, url: str, extra_headers: Optional[dict] = None) -> Optional[dict]:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    async with session.get(url, headers=headers, allow_redirects=False) as resp:
        if resp.status != 200:
            return None
        data = await resp.json()
        if not data.get("success"):
            return None
        return data


async def fetch_bytes(session: aiohttp.ClientSession, url: str, extra_headers: Optional[dict] = None) -> Optional[io.BytesIO]:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    async with session.get(url, headers=headers, allow_redirects=False) as resp:
        if resp.status != 200:
            return None
        return io.BytesIO(await resp.read())


# ---------------------------------------------------------------------------
# HTML / text helpers (mirrors Eruditus utils/formatting.py and utils/html.py)
# ---------------------------------------------------------------------------

def html_to_markdown(html: Optional[str]) -> str:
    if not html:
        return ""
    md = html2md(html, heading_style="atx", escape_asterisks=False, escape_underscores=False)
    # strip embedded image lines (keep file links but not inline images)
    md = re.sub(r"[^\S\r\n]*!\[[^\]]*\]\([^)]*\)\s*", "", md)
    md = re.sub(r"\n{3,}", "\n\n", md)
    return md.strip()


def slugify(name: str) -> str:
    """Convert a challenge name to a lowercase hyphenated slug."""
    slug = name.lower().strip()
    slug = re.sub(r'[<>:"/\\|?*.\x00-\x1f]', "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "challenge"


def filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name or "file"


def make_absolute(url: str, base_url: str) -> str:
    if url.startswith("http"):
        return url
    return f"{base_url.rstrip('/')}/{url.lstrip('/')}"


# ---------------------------------------------------------------------------
# Challenge pulling
# ---------------------------------------------------------------------------

async def get_csrf_nonce(session: aiohttp.ClientSession, base_url: str, extra_headers: Optional[dict]) -> Optional[str]:
    """Fetch CSRF nonce from the challenges page. Not needed for token auth."""
    if extra_headers and "Authorization" in extra_headers:
        return None
    async with session.get(f"{base_url}/challenges", headers={"User-Agent": USER_AGENT}) as resp:
        match = re.search(r"csrfNonce': \"([A-Fa-f0-9]+)\"", await resp.text())
        return match.group(1) if match else None


async def fetch_hints(
    session: aiohttp.ClientSession,
    base_url: str,
    hints: list[dict],
    extra_headers: Optional[dict] = None,
) -> list[dict]:
    """Fetch full hint content for all hints, unlocking free (cost <= 0) ones via
    POST /api/v1/unlocks then GET /api/v1/hints/{id}."""
    if not hints:
        return []

    csrf_nonce = await get_csrf_nonce(session, base_url, extra_headers)

    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    if csrf_nonce:
        headers["CSRF-Token"] = csrf_nonce

    result = []
    for i, hint in enumerate(hints, 1):
        hint_id = hint.get("id")
        cost = hint.get("cost", 1)
        content = hint.get("content")  # present if already unlocked in a prior session

        if cost <= 0 and content is None:
            # Unlock via /api/v1/unlocks (works even if already unlocked — we ignore the
            # "already unlocked" 400 and fall through to the GET either way)
            async with session.post(
                f"{base_url}/api/v1/unlocks",
                json={"target": hint_id, "type": "hints"},
                headers=headers,
            ) as resp:
                data = await resp.json()
                if resp.status not in (200, 400):
                    print(f"    WARN: POST /api/v1/unlocks for hint {hint_id} returned {resp.status}", file=sys.stderr)

        # GET the hint to retrieve content (and name) for both free and paid hints.
        # For free hints this returns the content now that we've unlocked it.
        # For paid locked hints this returns the locked view with the name but null content.
        async with session.get(
            f"{base_url}/api/v1/hints/{hint_id}",
            headers=headers,
            allow_redirects=False,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("success"):
                    hint_data = data["data"]
                    content = hint_data.get("content")
                    hint = {**hint, **hint_data}

        result.append({"id": hint_id, "cost": cost, "content": content, "index": i,
                        "name": hint.get("title")})
    return result


async def pull_challenges(session: aiohttp.ClientSession, base_url: str, extra_headers: Optional[dict] = None):
    """Yield full challenge dicts from the CTFd API."""
    data = await api_get(session, f"{base_url}/api/v1/challenges", extra_headers)
    if data is None:
        print("ERROR: Could not fetch challenge list. Are you logged in?", file=sys.stderr)
        return

    for stub in data["data"]:
        if stub.get("type") == "hidden":
            continue
        detail = await api_get(session, f"{base_url}/api/v1/challenges/{stub['id']}", extra_headers)
        if detail is None:
            print(f"  WARN: Could not fetch details for challenge {stub['id']}", file=sys.stderr)
            continue
        yield detail["data"]


# ---------------------------------------------------------------------------
# Writing to disk
# ---------------------------------------------------------------------------

def build_metadata(challenge: dict, hints: list[dict]) -> dict:
    tags = [t["value"] if isinstance(t, dict) else str(t) for t in (challenge.get("tags") or [])]
    description = html_to_markdown(challenge.get("description") or "")

    meta = {
        "version": "beta1",
        "name": challenge.get("name", "Unknown"),
        "category": challenge.get("category", ""),
        "description": description,
        "value": challenge.get("value", 0),
    }

    if challenge.get("solves") is not None:
        meta["solves"] = challenge["solves"]

    if tags:
        meta["tags"] = tags

    if challenge.get("connection_info"):
        meta["connection_info"] = challenge["connection_info"]

    if hints:
        meta["hints"] = []
        for hint in hints:
            entry = {"cost": hint["cost"]}
            if hint.get("name"):
                entry["title"] = hint["name"]
            if hint.get("content"):
                entry["content"] = html_to_markdown(hint["content"])
            meta["hints"].append(entry)

    return meta


async def save_challenge(
    session: aiohttp.ClientSession,
    base_url: str,
    challenge: dict,
    output_dir: Path,
    extra_headers: Optional[dict] = None,
):
    slug = slugify(challenge.get("name", f"challenge-{challenge['id']}"))
    chdir = output_dir / slug
    chdir.mkdir(parents=True, exist_ok=True)

    distfiles_dir = chdir / "distfiles"

    for raw_url in challenge.get("files") or []:
        distfiles_dir.mkdir(exist_ok=True)
        url = make_absolute(raw_url, base_url)
        fname = filename_from_url(raw_url)
        dest = distfiles_dir / fname

        content = await fetch_bytes(session, url, extra_headers)
        if content is None:
            print(f"    WARN: Could not download {url}", file=sys.stderr)
        else:
            dest.write_bytes(content.read())
            print(f"    Downloaded: {fname}")

    raw_hints = challenge.get("hints") or []
    hints = await fetch_hints(session, base_url, raw_hints, extra_headers)

    meta = build_metadata(challenge, hints)
    (chdir / "metadata.yml").write_text(
        yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main(url: str, output: str, username: Optional[str], password: Optional[str], token: Optional[str]):
    base_url = url.rstrip("/")
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    extra_headers: Optional[dict] = None

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        if token:
            print(f"Verifying token against {base_url}...")
            if not await verify_token(base_url, token):
                sys.exit(1)
            extra_headers = token_headers(token)
            print("Token verified.\n")
        else:
            print(f"Logging in to {base_url} as {username}...")
            if not await login_password(session, base_url, username, password):
                sys.exit(1)
            print("Login successful.\n")

        count = 0
        async for challenge in pull_challenges(session, base_url, extra_headers):
            cname = challenge.get("name", f"id={challenge['id']}")
            ccat = challenge.get("category", "?")
            cval = challenge.get("value", 0)
            print(f"  [{ccat}] {cname} ({cval} pts)")
            await save_challenge(session, base_url, challenge, output_dir, extra_headers)
            count += 1

        print(f"\nDone. Pulled {count} challenge(s) to {output_dir.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pull challenges from a CTFd instance.")
    parser.add_argument("--url", required=True, help="Base URL of the CTFd instance")
    parser.add_argument("--output", default="./challenges", help="Output directory (default: ./challenges)")

    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument("--token", help="CTFd API access token")
    auth.add_argument("--username", help="Login username or team name (use with --password)")

    parser.add_argument("--password", help="Login password (required with --username)")
    args = parser.parse_args()

    if args.username and not args.password:
        parser.error("--password is required when using --username")

    asyncio.run(main(args.url, args.output, args.username, args.password, args.token))
