"""Resolve the local media files behind Mac WeChat 4.x chat messages.

Image, video and received-file messages only store metadata in the message
database. The bytes live under the account's ``msg/`` folder:

- images: ``msg/attach/<md5(chat)>/<YYYY-MM>/Img/<md5>[_h|_t].dat`` (AES + XOR
  wrapped); the md5 sits in the message's ``packed_info_data``.
- videos: ``msg/video/<YYYY-MM>/<md5>.mp4`` plus ``<md5>_thumb.jpg``.

This module only reads those files. Decoded images are written to a private
cache inside the vault (mode 0700/0600) so an agent can open them as ordinary
jpg/png files. It never opens WeChat, contacts the network or changes WeChat
data. A missing file means the client never downloaded it (or it was cleaned);
callers must report that instead of guessing the picture.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

from group_image_media import _decode_image_bytes, _image_format, image_key_candidates

RECORD_ID_IN_BYTES = re.compile(rb"(?<![0-9a-fA-F])([0-9a-f]{16})(?![0-9a-fA-F])")
RECORD_INDEX = re.compile(r"^\d+(?:_\d+)*$")
MD5_IN_BYTES = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])")
WXID_PART = re.compile(r"(?i)^wxid_[A-Za-z0-9_-]+$")
IMAGE_EXTS = ("jpg", "png", "gif", "webp")
# Ordered best first: original, high-resolution, thumbnail.
IMAGE_VARIANTS = (("", "original"), ("_h", "high-resolution"), ("_t", "thumbnail"))
V1_KEY = b"cfcd208495d565ef"  # md5("0")[:16], used by the older V1 container
XOR_SIGNATURES = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF")


def packed_md5(packed) -> str | None:
    """Return the media md5 stored in a message's packed_info_data blob."""
    if not packed:
        return None
    data = packed.encode() if isinstance(packed, str) else bytes(packed)
    match = MD5_IN_BYTES.search(data)
    return match.group(1).decode("ascii").lower() if match else None


def packed_record_ids(packed) -> list[str]:
    """16-hex ids naming the msg/attach/<chat>/<month>/Rec/<id> folder of a merged forward."""
    if not packed:
        return []
    data = packed.encode() if isinstance(packed, str) else bytes(packed)
    return list(dict.fromkeys(m.group(1).decode("ascii") for m in RECORD_ID_IN_BYTES.finditer(data)))


def _index_key(index: str) -> tuple[int, ...]:
    return tuple(int(part) for part in index.split("_"))


def neighbour_months(ts: int) -> list[str]:
    """The message month first, then the next and previous month (boundary cases)."""
    when = datetime.fromtimestamp(ts)
    months = [when.strftime("%Y-%m")]
    year, month = when.year, when.month
    nxt = (year + (month == 12), month % 12 + 1)
    prev = (year - (month == 1), (month - 2) % 12 + 1)
    months.extend(f"{y:04d}-{m:02d}" for y, m in (nxt, prev))
    return months


def _xor_decode(data: bytes) -> bytes | None:
    """Pre-4.0 images: the whole file XORed with one byte."""
    if len(data) < 4:
        return None
    for signature in XOR_SIGNATURES:
        key = data[0] ^ signature[0]
        if all(data[i] ^ key == signature[i] for i in range(len(signature))):
            return bytes(value ^ key for value in data)
    return None


class MediaResolver:
    """Find and decode the media files of one account. One instance per command."""

    def __init__(self, db_dir: Path, vault_dir: Path, source_config: Path | None = None):
        self.db_dir = Path(db_dir)
        self.account_dir = self.db_dir.parent
        self.media_dir = Path(vault_dir) / "media"
        self.cache_dir = self.media_dir / "images"
        self.source_config = source_config
        self._keys: list[dict] | None = None
        self._key: dict | None = None
        self.stats = {"ok": 0, "thumbnail_only": 0, "missing": 0, "error": 0}

    def _ensure_private_dirs(self) -> None:
        for folder in (self.media_dir, self.cache_dir):
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            folder.chmod(0o700)

    # ---- paths -------------------------------------------------------------
    def public_path(self, path: Path) -> str:
        """Return a path without the account wxid segment.

        Output is redacted for wxid_* strings, which would break a real path.
        A private symlink inside the vault points at the account folder instead.
        """
        parts = Path(path).parts
        for index, part in enumerate(parts):
            if WXID_PART.match(part):
                target = Path(*parts[: index + 1])
                alias = self.media_dir / ("account-" + hashlib.sha256(str(target).encode()).hexdigest()[:8])
                try:
                    self._ensure_private_dirs()
                    if alias.is_symlink() and Path(alias.readlink()) != target:
                        alias.unlink()
                    if not alias.exists() and not alias.is_symlink():
                        alias.symlink_to(target, target_is_directory=True)
                except OSError:
                    return str(path)
                return str(alias.joinpath(*parts[index + 1 :]))
        return str(path)

    def chat_attach_dir(self, chat_username: str) -> Path:
        return self.account_dir / "msg/attach" / hashlib.md5(chat_username.encode()).hexdigest()

    # ---- images ------------------------------------------------------------
    def find_image_dats(self, chat_username: str, ts: int, md5: str) -> list[tuple[Path, str, str]]:
        base = self.chat_attach_dir(chat_username)
        found = []
        for month in neighbour_months(ts):
            folder = base / month / "Img"
            if not folder.is_dir():
                continue
            for suffix, level in IMAGE_VARIANTS:
                candidate = folder / f"{md5}{suffix}.dat"
                if candidate.is_file() and not candidate.is_symlink():
                    found.append((candidate, suffix, level))
            if found:
                break
        return found

    def _key_candidates(self) -> list[dict]:
        if self._keys is None:
            keys: list[dict] = []
            if self.source_config and self.source_config.exists():
                try:
                    keys = image_key_candidates(self.source_config, self.db_dir)
                except Exception:
                    keys = []
            self._keys = keys
        return self._keys

    def _decode(self, data: bytes) -> bytes:
        if data.startswith(b"\x07\x08V1\x08\x07"):
            return _decode_image_bytes(data, aes_key=V1_KEY, xor_key=data[-1] ^ 0xD9 if data else 0)
        if data.startswith(b"\x07\x08V2\x08\x07"):
            ordered = ([self._key] if self._key else []) + [k for k in self._key_candidates() if k is not self._key]
            if not ordered:
                raise ValueError("no-image-key")
            last: Exception | None = None
            for key in ordered:
                try:
                    clear = _decode_image_bytes(data, aes_key=bytes(key["aesKey"]), xor_key=int(key["xorKey"]))
                    _image_format(clear)
                    self._key = key
                    return clear
                except Exception as error:  # wrong key -> try the next candidate
                    last = error
            raise ValueError("image-key-mismatch") from last
        clear = _xor_decode(data)
        if clear is None:
            raise ValueError("unsupported-image-dat")
        return clear

    def _cached(self, stem: str) -> Path | None:
        for ext in IMAGE_EXTS:
            path = self.cache_dir / f"{stem}.{ext}"
            if path.is_file() and path.stat().st_size > 0:
                return path
        return None

    def _write_preview(self, stem: str, clear: bytes) -> Path:
        self._ensure_private_dirs()
        fmt = _image_format(clear)
        if fmt != "wxgf":
            target = self.cache_dir / f"{stem}.{fmt}"
            target.write_bytes(clear)
            target.chmod(0o600)
            return target
        # wxgf is WeChat's HEVC still-image wrapper; ffmpeg reads the raw stream.
        if not shutil.which("ffmpeg"):
            raise ValueError("wxgf-needs-ffmpeg")
        raw = self.cache_dir / f"{stem}.wxgf"
        raw.write_bytes(clear)
        target = self.cache_dir / f"{stem}.jpg"
        try:
            subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "hevc", "-i", str(raw),
                 "-frames:v", "1", "-update", "1", str(target)],
                check=True, timeout=30, capture_output=True,
            )
        finally:
            raw.unlink(missing_ok=True)
        target.chmod(0o600)
        return target

    def image(self, chat_username: str, ts: int, packed) -> dict:
        md5 = packed_md5(packed)
        if not md5:
            self.stats["missing"] += 1
            return {"kind": "image", "status": "missing", "reason": "no-md5"}
        dats = self.find_image_dats(chat_username, ts, md5)
        if not dats:
            self.stats["missing"] += 1
            return {"kind": "image", "status": "missing", "md5": md5, "reason": "not-downloaded"}
        last_error = ""
        for path, suffix, level in dats:
            stem = md5 + suffix
            try:
                preview = self._cached(stem) or self._write_preview(stem, self._decode(path.read_bytes()))
            except Exception as error:
                last_error = str(error) or type(error).__name__
                continue
            self.stats["thumbnail_only" if level == "thumbnail" else "ok"] += 1
            return {"kind": "image", "status": "ok", "md5": md5, "level": level, "path": str(preview)}
        self.stats["error"] += 1
        return {"kind": "image", "status": "error", "md5": md5, "reason": last_error}

    # ---- videos ------------------------------------------------------------
    def video(self, chat_username: str, ts: int, packed) -> dict:
        md5 = packed_md5(packed)
        if not md5:
            self.stats["missing"] += 1
            return {"kind": "video", "status": "missing", "reason": "no-md5"}
        for month in neighbour_months(ts):
            folder = self.account_dir / "msg/video" / month
            mp4 = folder / f"{md5}.mp4"
            thumb = folder / f"{md5}_thumb.jpg"
            if mp4.is_file():
                self.stats["ok"] += 1
                result = {"kind": "video", "status": "ok", "md5": md5, "level": "original", "path": self.public_path(mp4)}
                if thumb.is_file():
                    result["thumbnail"] = self.public_path(thumb)
                return result
            if thumb.is_file():
                self.stats["thumbnail_only"] += 1
                return {"kind": "video", "status": "ok", "md5": md5, "level": "thumbnail", "path": self.public_path(thumb)}
        self.stats["missing"] += 1
        return {"kind": "video", "status": "missing", "md5": md5, "reason": "not-downloaded"}

    # ---- merged forwards ("聊天记录") ---------------------------------------
    def record_dir(self, chat_username: str, ts: int, packed) -> Path | None:
        ids = packed_record_ids(packed)
        if not ids:
            return None
        base = self.chat_attach_dir(chat_username)
        for month in neighbour_months(ts):
            for rec_id in ids:
                folder = base / month / "Rec" / rec_id
                if folder.is_dir() and not folder.is_symlink():
                    return folder
        return None

    def record(self, chat_username: str, ts: int, packed) -> dict:
        """Attachments of one merged-forward message, keyed by item index (e.g. 0_1_3).

        Only items the client already downloaded exist; an empty F/<index>
        folder means the file was never downloaded.
        """
        folder = self.record_dir(chat_username, ts, packed)
        if folder is None:
            return {"kind": "record", "status": "missing", "reason": "not-downloaded", "items": []}
        items: list[dict] = []
        img = folder / "Img"
        if img.is_dir():
            indexes = sorted({p.name.removesuffix("_t") for p in img.iterdir()
                              if p.is_file() and RECORD_INDEX.match(p.name.removesuffix("_t"))}, key=_index_key)
            for index in indexes:
                variants = [(img / index, "", "original"), (img / f"{index}_t", "_t", "thumbnail")]
                item = {"index": index, "kind": "image", "status": "error", "reason": ""}
                for path, suffix, level in variants:
                    if not path.is_file() or path.is_symlink():
                        continue
                    stem = f"rec-{folder.name}-{index}{suffix}"
                    try:
                        preview = self._cached(stem) or self._write_preview(stem, self._decode(path.read_bytes()))
                    except Exception as error:
                        item["reason"] = str(error) or type(error).__name__
                        continue
                    item = {"index": index, "kind": "image", "status": "ok", "level": level, "path": str(preview)}
                    break
                items.append(item)
        video = folder / "V"
        if video.is_dir():
            for path in sorted(video.glob("*.mp4"), key=lambda p: _index_key(p.stem) if RECORD_INDEX.match(p.stem) else (10**9,)):
                if path.is_file() and not path.is_symlink():
                    items.append({"index": path.stem, "kind": "video", "status": "ok", "level": "original",
                                  "path": self.public_path(path)})
        files = folder / "F"
        if files.is_dir():
            for slot in sorted((p for p in files.iterdir() if p.is_dir() and RECORD_INDEX.match(p.name)), key=lambda p: _index_key(p.name)):
                real = [p for p in slot.iterdir() if p.is_file() and not p.is_symlink() and not p.name.startswith(".")]
                if real:
                    for path in real:
                        items.append({"index": slot.name, "kind": "file", "status": "ok", "name": path.name,
                                      "path": self.public_path(path)})
                else:
                    items.append({"index": slot.name, "kind": "file", "status": "missing", "reason": "not-downloaded"})
        items.sort(key=lambda item: _index_key(item["index"]))
        return {"kind": "record", "status": "ok", "record_id": folder.name, "items": items}


RECORD_MEDIA_TYPES = {"2": "image", "4": "video", "8": "file"}


def merge_record_titles(record: dict, titles: dict[str, dict]) -> dict:
    """Attach names/senders from the forward XML; list media items never downloaded."""
    items = record.setdefault("items", [])
    seen = {(item["index"], item["kind"]) for item in items}
    for item in items:
        meta = titles.get(item["index"]) or {}
        if meta.get("title") and item["kind"] == "file" and not item.get("name"):
            item["name"] = meta["title"]
        if meta.get("source"):
            item["source"] = meta["source"]
    for index, meta in titles.items():
        kind = RECORD_MEDIA_TYPES.get(meta.get("datatype", ""))
        if kind and (index, kind) not in seen:
            entry = {"index": index, "kind": kind, "status": "missing", "reason": "not-downloaded"}
            if kind == "file" and meta.get("title"):
                entry["name"] = meta["title"]
            if meta.get("source"):
                entry["source"] = meta["source"]
            items.append(entry)
    items.sort(key=lambda item: _index_key(item["index"]))
    if items and record.get("status") == "missing":
        record["status"] = "partial"
    return record


def describe_record(record: dict) -> str:
    """Lines appended under a rendered merged forward."""
    if not record.get("items"):
        return ""
    lines = ["[聊天记录附件]（序号=记录里第几条，从 0 开始，嵌套用 _ 连接）"]
    names = {"image": "图片", "video": "视频", "file": "文件"}
    for item in record["items"]:
        label = names.get(item["kind"], item["kind"])
        if item.get("name"):
            label += f" {item['name']}"
        if item.get("source"):
            label = f"{item['source']} 发的{label}"
        if item["status"] == "ok":
            level = "·缩略图" if item.get("level") == "thumbnail" else ""
            lines.append(f"  #{item['index']} [{label}{level}] {item['path']}")
        elif item["status"] == "missing":
            lines.append(f"  #{item['index']} [{label}] 未下载（需在微信里点开这条聊天记录并下载）")
        else:
            lines.append(f"  #{item['index']} [{label}] 解码失败 {item.get('reason', '')}".rstrip())
    return "\n".join(lines)


def describe(media: dict) -> str:
    """One-line label used inside message content."""
    kind = "图片" if media.get("kind") == "image" else "视频"
    status = media.get("status")
    if status == "ok":
        if media.get("level") == "thumbnail":
            label = f"[{kind}·缩略图]" if kind == "图片" else "[视频·仅封面]"
        else:
            label = f"[{kind}]"
        return f"{label} {media['path']}"
    if status == "missing":
        return f"[{kind}：本机无缓存，微信未下载过或已被清理]"
    return f"[{kind}：本地文件解码失败 {media.get('reason', '')}]".replace(" ]", "]")
