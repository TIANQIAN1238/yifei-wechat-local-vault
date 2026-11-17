import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from Crypto.Cipher import AES  # noqa: E402

import chat_media  # noqa: E402
from chat_media import MediaResolver, describe, describe_record, merge_record_titles, neighbour_months, packed_md5, packed_record_ids  # noqa: E402
from message_display import record_item_titles  # noqa: E402
import vault_cli  # noqa: E402

JPEG = b"\xff\xd8\xff\xe0" + b"fake-jpeg-body" * 20 + b"\xff\xd9"
MD5 = "0123456789abcdef0123456789abcdef"
CHAT = "12345@chatroom"
AES_KEY = b"0123456789abcdef"
XOR_KEY = 0x5A


def v2_dat(clear: bytes, aes_size: int = 32, xor_size: int = 16) -> bytes:
    head, middle, tail = clear[:aes_size], clear[aes_size:len(clear) - xor_size], clear[len(clear) - xor_size:]
    pad = 16 - len(head) % 16
    enc = AES.new(AES_KEY, AES.MODE_ECB).encrypt(head + bytes([pad]) * pad)
    return (b"\x07\x08V2\x08\x07" + struct.pack("<I", aes_size) + struct.pack("<I", xor_size) + b"\x01"
            + enc + middle + bytes(b ^ XOR_KEY for b in tail))


class MediaResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.account = root / "xwechat_files" / "wxid_test_abcd"
        self.db_dir = self.account / "db_storage"
        self.db_dir.mkdir(parents=True)
        self.vault = root / "vault"
        self.ts = int(datetime(2026, 11, 16, 12).timestamp())
        self.img_dir = self.account / "msg/attach" / hashlib.md5(CHAT.encode()).hexdigest() / "2026-11" / "Img"
        self.img_dir.mkdir(parents=True)
        self.resolver = MediaResolver(self.db_dir, self.vault)
        self.resolver._keys = [{"aesKey": b"wrong-key-123456", "xorKey": 1}, {"aesKey": AES_KEY, "xorKey": XOR_KEY}]

    def tearDown(self):
        self.tmp.cleanup()

    def test_packed_md5_reads_the_hash_from_the_blob(self):
        blob = b'\x08\t\x10\x12\x1a"" ' + MD5.encode() + b"X\x00"
        self.assertEqual(packed_md5(blob), MD5)
        self.assertIsNone(packed_md5(b"\x00\x01"))
        self.assertIsNone(packed_md5(None))

    def test_neighbour_months_wrap_years(self):
        self.assertEqual(neighbour_months(int(datetime(2026, 12, 31).timestamp())), ["2026-12", "2027-01", "2026-11"])
        self.assertEqual(neighbour_months(int(datetime(2026, 1, 2).timestamp())), ["2026-01", "2026-02", "2025-12"])

    def test_v2_image_is_decoded_with_the_matching_key_and_cached(self):
        (self.img_dir / f"{MD5}.dat").write_bytes(v2_dat(JPEG))
        result = self.resolver.image(CHAT, self.ts, MD5.encode())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["level"], "original")
        out = Path(result["path"])
        self.assertEqual(out.read_bytes(), JPEG)
        self.assertEqual(out.suffix, ".jpg")
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(out.parent).st_mode & 0o777, 0o700)
        # Second lookup is served from the cache even if the source vanished.
        (self.img_dir / f"{MD5}.dat").unlink()
        (self.img_dir / f"{MD5}.dat").write_bytes(b"garbage")
        self.assertEqual(self.resolver.image(CHAT, self.ts, MD5.encode())["path"], str(out))

    def test_original_is_preferred_over_thumbnail(self):
        (self.img_dir / f"{MD5}_t.dat").write_bytes(v2_dat(JPEG))
        self.assertEqual(self.resolver.image(CHAT, self.ts, MD5.encode())["level"], "thumbnail")
        (self.img_dir / f"{MD5}.dat").write_bytes(v2_dat(JPEG))
        self.assertEqual(self.resolver.image(CHAT, self.ts, MD5.encode())["level"], "original")

    def test_legacy_xor_image(self):
        (self.img_dir / f"{MD5}.dat").write_bytes(bytes(b ^ 0x33 for b in JPEG))
        result = self.resolver.image(CHAT, self.ts, MD5.encode())
        self.assertEqual(Path(result["path"]).read_bytes(), JPEG)

    def test_missing_and_undecodable_images_are_reported_not_guessed(self):
        missing = self.resolver.image(CHAT, self.ts, MD5.encode())
        self.assertEqual(missing["status"], "missing")
        self.assertIn("本机无缓存", describe(missing))
        (self.img_dir / f"{MD5}.dat").write_bytes(b"\x07\x08V2\x08\x07" + b"\x00" * 40)
        self.assertEqual(self.resolver.image(CHAT, self.ts, MD5.encode())["status"], "error")

    def test_other_chats_files_are_not_used(self):
        other = self.account / "msg/attach" / hashlib.md5(b"other@chatroom").hexdigest() / "2026-11" / "Img"
        other.mkdir(parents=True)
        (other / f"{MD5}.dat").write_bytes(v2_dat(JPEG))
        self.assertEqual(self.resolver.image(CHAT, self.ts, MD5.encode())["status"], "missing")

    def test_video_prefers_mp4_and_falls_back_to_cover(self):
        folder = self.account / "msg/video/2026-11"
        folder.mkdir(parents=True)
        (folder / f"{MD5}_thumb.jpg").write_bytes(JPEG)
        cover = self.resolver.video(CHAT, self.ts, MD5.encode())
        self.assertEqual(cover["level"], "thumbnail")
        self.assertIn("仅封面", describe(cover))
        (folder / f"{MD5}.mp4").write_bytes(b"mp4")
        self.assertEqual(self.resolver.video(CHAT, self.ts, MD5.encode())["level"], "original")

    def test_public_path_hides_the_wxid_but_still_opens(self):
        folder = self.account / "msg/file/2026-11"
        folder.mkdir(parents=True)
        (folder / "a.txt").write_text("hello")
        shown = self.resolver.public_path(folder / "a.txt")
        self.assertNotIn("wxid_", shown)
        self.assertEqual(Path(shown).read_text(), "hello")
        self.assertEqual(vault_cli.redact_text(shown), shown)

    def record_folder(self, rec_id="76b26af6ec2cc5a3"):
        folder = self.img_dir.parent / "Rec" / rec_id
        (folder / "Img").mkdir(parents=True)
        (folder / "F" / "1").mkdir(parents=True)
        (folder / "F" / "3").mkdir(parents=True)
        (folder / "V").mkdir()
        return folder

    def test_merged_forward_attachments_are_listed_by_index(self):
        folder = self.record_folder()
        (folder / "Img" / "0").write_bytes(v2_dat(JPEG))
        (folder / "Img" / "0_t").write_bytes(v2_dat(JPEG))
        (folder / "Img" / "2_t").write_bytes(v2_dat(JPEG))
        (folder / "V" / "0_1.mp4").write_bytes(b"mp4")
        (folder / "F" / "1" / "1.txt").write_text("hello txt", encoding="utf-8")
        packed = b"\x08\x12J\x12\n\x10" + folder.name.encode()
        self.assertEqual(packed_record_ids(packed), [folder.name])
        record = self.resolver.record(CHAT, self.ts, packed)
        got = {(i["index"], i["kind"]): i for i in record["items"]}
        self.assertEqual(got[("0", "image")]["level"], "original")
        self.assertEqual(got[("2", "image")]["level"], "thumbnail")
        self.assertEqual(Path(got[("0", "image")]["path"]).read_bytes(), JPEG)
        self.assertEqual(Path(got[("1", "file")]["path"]).read_text(encoding="utf-8"), "hello txt")
        self.assertNotIn("wxid_", got[("1", "file")]["path"])
        self.assertEqual(got[("3", "file")]["status"], "missing")
        self.assertEqual(got[("0_1", "video")]["status"], "ok")
        self.assertEqual([i["index"] for i in record["items"]], ["0", "0_1", "1", "2", "3"])

    def test_record_titles_name_missing_files_and_add_undownloaded_items(self):
        xml = ("<msg><appmsg><type>19</type><recorditem><![CDATA[<recordinfo><datalist>"
               "<dataitem datatype=\"1\"><sourcename>甲</sourcename><datadesc>hi</datadesc></dataitem>"
               "<dataitem datatype=\"8\"><sourcename>乙</sourcename><datatitle>1.txt</datatitle></dataitem>"
               "<dataitem datatype=\"17\"><datatitle>群聊的聊天记录</datatitle><recordinfo><datalist>"
               "<dataitem datatype=\"2\"><sourcename>丙</sourcename></dataitem></datalist></recordinfo></dataitem>"
               "<dataitem datatype=\"8\"><datatitle>2.txt</datatitle></dataitem>"
               "</datalist></recordinfo>]]></recorditem></appmsg></msg>")
        titles = record_item_titles(xml)
        self.assertEqual(titles["1"]["title"], "1.txt")
        self.assertEqual(titles["2_0"]["datatype"], "2")
        self.assertEqual(titles["3"]["title"], "2.txt")
        record = {"kind": "record", "status": "ok", "items": [{"index": "1", "kind": "file", "status": "missing"}]}
        merged = merge_record_titles(record, titles)
        names = {(i["index"], i["kind"]): i for i in merged["items"]}
        self.assertEqual(names[("1", "file")]["name"], "1.txt")
        self.assertEqual(names[("1", "file")]["source"], "乙")
        self.assertEqual(names[("3", "file")]["name"], "2.txt")
        self.assertEqual(names[("2_0", "image")]["status"], "missing")
        text = describe_record(merged)
        self.assertIn("乙 发的文件 1.txt", text)
        self.assertIn("未下载", text)
        self.assertEqual(describe_record({"items": []}), "")

    def test_media_hint_uses_the_resolver_only_when_media_is_on(self):
        (self.img_dir / f"{MD5}.dat").write_bytes(v2_dat(JPEG))
        out = {}
        hint = vault_cli.media_hint(3, "", True, self.db_dir, CHAT, self.ts, MD5.encode(), self.resolver, out)
        self.assertTrue(hint.startswith("[图片] "))
        self.assertEqual(out["status"], "ok")
        self.assertEqual(vault_cli.media_hint(3, "", False, self.db_dir, CHAT, self.ts, MD5.encode(), self.resolver), "[图片]")


if __name__ == "__main__":
    unittest.main()
