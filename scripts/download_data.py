#!/usr/bin/env python3
"""Download the open datasets used by the ML layer into data/raw/ (git-ignored).

Sources (Hugging Face and UCI only):
  * UCI SMS Spam Collection           - CC BY 4.0      - ~0.2 MB
  * zefang-liu/phishing-email-dataset - LGPL-3.0       - ~52 MB (pinned revision)

A hard 500 MB budget is enforced for the whole data/ directory, both from the
advertised Content-Length and while streaming. Files that already exist are
kept, so you can also place them by hand if your network blocks a host.

Usage:
    python scripts/download_data.py           # download missing files
    python scripts/download_data.py --force   # re-download everything
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
MANIFEST = RAW_DIR / "MANIFEST.json"

MB = 1024 * 1024
TOTAL_BUDGET_BYTES = 500 * MB
CHUNK = 256 * 1024
USER_AGENT = "TrustGate-dataset-downloader/0.1 (+https://github.com/hasancomert/trustgateforfinance)"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    filename: str
    max_bytes: int
    license: str
    homepage: str
    extract_member: str | None = None  # for zip archives: the single member we keep
    extracted_name: str | None = None

    @property
    def directory(self) -> Path:
        return RAW_DIR / self.name

    @property
    def final_path(self) -> Path:
        return self.directory / (self.extracted_name or self.filename)


SOURCES: tuple[Source, ...] = (
    Source(
        name="sms_spam_collection",
        url="https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
        filename="sms_spam_collection.zip",
        max_bytes=5 * MB,
        license="CC BY 4.0",
        homepage="https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
        extract_member="SMSSpamCollection",
        extracted_name="SMSSpamCollection.tsv",
    ),
    Source(
        name="phishing_email",
        url="https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/34085a032c123ca237f314a01a67909cdea35e34/Phishing_Email.csv",
        filename="Phishing_Email.csv",
        max_bytes=80 * MB,
        license="LGPL-3.0",
        homepage="https://huggingface.co/datasets/zefang-liu/phishing-email-dataset",
    ),
)


class BudgetExceeded(RuntimeError):
    pass


def dir_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stream_download(source: Source, dest: Path, budget_left: int) -> int:
    """Stream `source.url` to `dest`, aborting if the size limits are crossed."""
    limit = min(source.max_bytes, budget_left)
    request = urllib.request.Request(source.url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(request, timeout=60) as response:
        advertised = response.headers.get("Content-Length")
        if advertised and int(advertised) > limit:
            raise BudgetExceeded(f"{source.name}: server reports {int(advertised) / MB:.1f} MB, limit is {limit / MB:.1f} MB")
        written = 0
        with tmp.open("wb") as out:
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    out.close()
                    tmp.unlink(missing_ok=True)
                    raise BudgetExceeded(f"{source.name}: exceeded {limit / MB:.1f} MB while downloading")
                out.write(chunk)
    tmp.replace(dest)
    return written


def extract_single_member(archive: Path, member: str, target: Path, max_bytes: int) -> None:
    """Extract exactly one named member from a zip without trusting archive paths."""
    with zipfile.ZipFile(archive) as zf:
        matches = [info for info in zf.infolist() if Path(info.filename).name == member and not info.is_dir()]
        if not matches:
            raise RuntimeError(f"{archive.name}: member '{member}' not found")
        info = matches[0]
        if info.file_size > max_bytes:
            raise BudgetExceeded(f"{archive.name}: member '{member}' is {info.file_size / MB:.1f} MB")
        with zf.open(info) as src:
            data = src.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise BudgetExceeded(f"{archive.name}: member '{member}' exceeds {max_bytes / MB:.1f} MB")
        target.write_bytes(data)


def download(source: Source, force: bool) -> dict:
    source.directory.mkdir(parents=True, exist_ok=True)
    archive_path = source.directory / source.filename

    if source.final_path.exists() and not force:
        print(f"[skip] {source.name}: {source.final_path.relative_to(ROOT)} already present")
    else:
        budget_left = TOTAL_BUDGET_BYTES - dir_size(DATA_DIR)
        if budget_left <= 0:
            raise BudgetExceeded("data/ already uses the full 500 MB budget")
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                print(f"[get ] {source.name}: {source.url}")
                size = stream_download(source, archive_path, budget_left)
                print(f"[ ok ] {source.name}: {size / MB:.2f} MB")
                last_error = None
                break
            except urllib.error.HTTPError as exc:  # 4xx/5xx: retrying will not help for policy blocks
                last_error = exc
                if exc.code in (401, 403, 404, 407):
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = exc
            if attempt < 3:
                time.sleep(2 ** attempt)
        if last_error is not None:
            raise RuntimeError(
                f"Could not download {source.name}: {last_error}\n"
                f"  -> Download it manually from {source.homepage}\n"
                f"     and save it as {archive_path.relative_to(ROOT)}"
            ) from last_error

        if source.extract_member:
            extract_single_member(archive_path, source.extract_member, source.final_path, source.max_bytes)
            archive_path.unlink(missing_ok=True)

    return {
        "name": source.name,
        "path": str(source.final_path.relative_to(ROOT)),
        "bytes": source.final_path.stat().st_size,
        "sha256": sha256(source.final_path),
        "url": source.url,
        "license": source.license,
        "homepage": source.homepage,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="re-download even if files exist")
    args = parser.parse_args(argv)

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    try:
        for source in SOURCES:
            entries.append(download(source, args.force))
    except (BudgetExceeded, RuntimeError) as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 1

    total = dir_size(DATA_DIR)
    MANIFEST.write_text(json.dumps({
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_bytes": total,
        "budget_bytes": TOTAL_BUDGET_BYTES,
        "files": entries,
    }, indent=2))
    print(f"[done] data/ uses {total / MB:.1f} MB of the {TOTAL_BUDGET_BYTES / MB:.0f} MB budget")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
