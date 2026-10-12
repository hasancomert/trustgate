"""Download the real-world evaluation data for the Derby measurement into data/eval/ (git-ignored).

Sources (Hugging Face only, pinned revisions, size-capped, hash-checked):
  * akuysal/turkishSMS-ds - 850 Turkish SMS (spam / legitimate) from Uysal et al. (2013),
    "The impact of feature extraction and selection on SMS spam filtering". No licence is
    stated, so it is used for measurement only: its texts are never committed or quoted.
  * kudzaiprichard/aura-phishing-email-corpus, TREC_07.csv - a byte-identical copy of the
    TREC 2007 public spam corpus from the "Phishing Email Curated Datasets" Zenodo record
    (CC BY 4.0).

Neither source is part of, or derived from, the classifier's training data (UCI SMS Spam
Collection, zefang-liu/phishing-email-dataset). build_real_set.py additionally drops every
message that duplicates or nearly duplicates a training text.

    python eval/derby/download_eval_data.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
EVAL_DIR = DATA_DIR / "eval"
MANIFEST = EVAL_DIR / "MANIFEST.json"
MB = 1024 * 1024
TOTAL_BUDGET_BYTES = 500 * MB  # everything under data/, training data included
CHUNK = 256 * 1024
USER_AGENT = "TrustGate-eval-downloader/0.1 (+https://github.com/hasancomert/trustgate)"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    filename: str
    max_bytes: int
    md5: str | None
    license: str
    homepage: str


TR_SMS_REV = "66fde603d92a65c3942250535084971ac7ceffc7"
AURA_REV = "539567cee21d03c83bd2fb1b142c18a80904eb72"
SOURCES = (
    Source("turkish_sms", f"https://huggingface.co/datasets/akuysal/turkishSMS-ds/resolve/{TR_SMS_REV}/data/train-00000-of-00001-59e75adfecabf4d4.parquet",
           "train.parquet", 2 * MB, None, "not stated (measurement only)", "https://huggingface.co/datasets/akuysal/turkishSMS-ds"),
    Source("turkish_sms", f"https://huggingface.co/datasets/akuysal/turkishSMS-ds/resolve/{TR_SMS_REV}/data/validation-00000-of-00001-806ae48564fe3c4c.parquet",
           "validation.parquet", 1 * MB, None, "not stated (measurement only)", "https://huggingface.co/datasets/akuysal/turkishSMS-ds"),
    Source("trec07", f"https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus/resolve/{AURA_REV}/TREC_07.csv",
           "TREC_07.csv", 110 * MB, "e5a5ae0de1580965191cb32806dc0dae", "CC BY 4.0", "https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus"),
)


def dir_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download(source: Source, dest: Path, budget_left: int) -> None:
    limit = min(source.max_bytes, budget_left)
    request = urllib.request.Request(source.url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    written = 0
    with urllib.request.urlopen(request, timeout=120) as response, tmp.open("wb") as out:
        advertised = response.headers.get("Content-Length")
        if advertised and int(advertised) > limit:
            raise RuntimeError(f"{source.filename}: {int(advertised) / MB:.1f} MB exceeds the {limit / MB:.1f} MB limit")
        while chunk := response.read(CHUNK):
            written += len(chunk)
            if written > limit:
                raise RuntimeError(f"{source.filename}: exceeded {limit / MB:.1f} MB")
            out.write(chunk)
    tmp.replace(dest)


def main() -> int:
    manifest = {"downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": []}
    for source in SOURCES:
        dest = EVAL_DIR / source.name / source.filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            budget_left = TOTAL_BUDGET_BYTES - dir_size(DATA_DIR)
            print(f"downloading {source.name}/{source.filename} …", flush=True)
            download(source, dest, budget_left)
        if source.md5 and digest(dest, "md5") != source.md5:
            dest.unlink()
            raise RuntimeError(f"{source.filename}: MD5 mismatch, file removed")
        manifest["files"].append({
            "path": str(dest.relative_to(ROOT)), "url": source.url, "bytes": dest.stat().st_size,
            "sha256": digest(dest, "sha256"), "license": source.license, "homepage": source.homepage,
        })
        print(f"ok  {dest.relative_to(ROOT)}  {dest.stat().st_size / MB:.1f} MB")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"data/ now holds {dir_size(DATA_DIR) / MB:.0f} MB (limit {TOTAL_BUDGET_BYTES // MB} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
