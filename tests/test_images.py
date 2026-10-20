from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from jianxun.client import image_dimensions, jpeg_dimensions
from jianxun.config import Config
from jianxun.im import WKIMClient
from main import group_view_menu


def png(width=320, height=180):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    scanline = b"\0" + b"\x30\x90\xe0" * width
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scanline * height)) + chunk(b"IEND", b""))


class ImageTests(unittest.TestCase):
    def test_png_dimensions_detected_by_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "image-without-extension"
            path.write_bytes(png())
            self.assertEqual(image_dimensions(str(path)), (320, 180))
            self.assertEqual(jpeg_dimensions(str(path)), (320, 180))

    def test_jpeg_dimensions_with_metadata_fill_and_multiple_sof_types(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "photo.jpg"
            for marker in (0xC0, 0xC2, 0xC9):
                with self.subTest(marker=marker):
                    path.write_bytes(b"\xff\xd8\xff\xe0\0\x04AB\xff\xff" + bytes([marker])
                                     + struct.pack(">HBHHB", 11, 8, 2800, 1272, 1)
                                     + b"\x01\x11\0\xff\xd9")
                    self.assertEqual(image_dimensions(str(path)), (1272, 2800))

    def test_invalid_or_truncated_headers_return_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "broken.png"
            for data in (b"", b"not an image", png()[:23], png(0, 1),
                         b"\xff\xd8\xff\xe0\0\0", b"\xff\xd8\xff\xc0\0\x11\x08"):
                with self.subTest(data=data[:24]):
                    path.write_bytes(data)
                    self.assertEqual(image_dimensions(str(path)), (0, 0))

    def test_menu_sends_preview_path_and_real_png_dimensions(self):
        api, im = Mock(token="test-token"), Mock(connected=False)
        api.upload_file.return_value = {"path": "file/preview/chat/2/group/upload",
                                        "url": "https://storage.example.test/upload"}
        im.connect.side_effect = lambda: setattr(im, "connected", True)
        im.send_image.return_value = SimpleNamespace(reason_code=1, message_id=123, message_seq=20)
        cfg = Config.load()
        cfg.uid = "test-user"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.png"
            path.write_bytes(png())
            output = io.StringIO()
            with patch("main.ask", side_effect=["4", str(path), "6"]), \
                    patch("main.WKIMClient", return_value=im), redirect_stdout(output):
                group_view_menu(api, {"group_no": "group"}, cfg)
        im.send_image.assert_called_once_with("group", "file/preview/chat/2/group/upload", 320, 180)
        self.assertIn("320x180", output.getvalue())

    def test_menu_rejects_unknown_image_before_upload(self):
        api = Mock(token="test-token")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "broken.png"
            path.write_bytes(b"not an image")
            with patch("main.ask", side_effect=["4", str(path), "6"]), \
                    patch("main.WKIMClient") as constructor, redirect_stdout(io.StringIO()):
                group_view_menu(api, {"group_no": "group"}, Config.load())
        api.upload_file.assert_not_called()
        constructor.assert_not_called()

    def test_menu_does_not_send_storage_url_when_preview_path_missing(self):
        api = Mock(token="test-token")
        api.upload_file.return_value = {"url": "https://storage.example.test/upload"}
        with patch("main.ask", side_effect=["4", "test.png", "6"]), \
                patch("main.image_dimensions", return_value=(320, 180)), \
                patch("main.WKIMClient") as constructor, redirect_stdout(io.StringIO()):
            group_view_menu(api, {"group_no": "group"}, Config.load())
        constructor.assert_not_called()

    def test_image_api_rejects_zero_dimensions_before_socket_write(self):
        im = WKIMClient()
        with patch.object(im, "_send_payload") as send:
            for width, height in ((0, 0), (0, 180), (320, -1)):
                with self.assertRaises(ValueError):
                    im.send_image("group", "file/preview/image", width, height)
            send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
