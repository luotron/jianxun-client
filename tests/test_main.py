from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

from requests.exceptions import ReadTimeout

from main import group_view_menu, watch_group_messages
from jianxun.config import Config
from jianxun.im import WKIMTimeout


def message(identity, sequence, channel="group", channel_type=2):
    return SimpleNamespace(message_id=identity, message_seq=sequence,
                           channel_id=channel, channel_type=channel_type,
                           from_uid="peer", message_time=123,
                           content={"content": f"push-{identity}", "type": 1})


class MainChatTests(unittest.TestCase):
    def test_history_then_live_filters_deduplicates_and_keeps_connection(self):
        api = Mock()
        api.request.return_value = {"messages": [
            {"message_id": "102", "message_seq": 2, "payload": {"content": "history-two"}},
            {"message_id": 101, "message_seq": 1, "payload": {"content": "history-one"}},
        ]}
        im = Mock()
        im.recv_message.side_effect = [message(102, 2), message(200, 1, "other-group"),
                                       message(201, 2, channel_type=1), WKIMTimeout(),
                                       message(103, 3), message(103, 3), KeyboardInterrupt()]
        output = io.StringIO()
        with redirect_stdout(output):
            watch_group_messages(api, im, "group")
        text = output.getvalue()
        self.assertLess(text.index("history-one"), text.index("history-two"))
        self.assertLess(text.index("history-two"), text.index("push-103"))
        self.assertEqual(text.count("push-103"), 1)
        for unwanted in ("push-102", "push-200", "push-201"):
            self.assertNotIn(unwanted, text)
        self.assertIn("返回群菜单", text)
        im.close.assert_not_called()
        api.request.assert_called_once_with("POST", "/message/channel/sync", {
            "channel_id": "group", "channel_type": 2, "start_message_seq": 0,
            "end_message_seq": 0, "limit": 20, "pull_mode": 0,
        })

    def test_history_timeout_still_listens(self):
        api = Mock()
        api.request.side_effect = ReadTimeout("HTTP unavailable")
        im = Mock()
        im.recv_message.side_effect = [message(103, 3), KeyboardInterrupt()]
        output = io.StringIO()
        with redirect_stdout(output):
            watch_group_messages(api, im, "group")
        self.assertIn("历史加载失败", output.getvalue())
        self.assertIn("push-103", output.getvalue())
        im.close.assert_not_called()

    def test_skip_history_and_interrupt_while_loading(self):
        api, im = Mock(), Mock()
        im.recv_message.side_effect = KeyboardInterrupt()
        with redirect_stdout(io.StringIO()):
            watch_group_messages(api, im, "group", history_limit=0)
        api.request.assert_not_called()
        api.request.side_effect = KeyboardInterrupt()
        im.reset_mock()
        with redirect_stdout(io.StringIO()):
            watch_group_messages(api, im, "group")
        im.recv_message.assert_not_called()
        im.close.assert_not_called()

    def test_menu_reuses_connection_after_listening_until_leaving_group(self):
        api = Mock(token="test-token")
        im = Mock(connected=False)
        im.connect.side_effect = lambda: setattr(im, "connected", True)
        im.send_text.return_value = SimpleNamespace(reason_code=1, message_id=1,
                                                   message_seq=1, client_seq=1)
        im.recv_message.side_effect = KeyboardInterrupt()
        cfg = Config.load()
        cfg.uid = "test-user"
        with patch("main.ask", side_effect=["3", "before", "5", "0", "3", "after", "6"]), \
                patch("main.WKIMClient", return_value=im) as constructor, \
                redirect_stdout(io.StringIO()):
            group_view_menu(api, {"group_no": "group", "name": "test"}, cfg)
        constructor.assert_called_once()
        im.connect.assert_called_once()
        self.assertEqual(im.send_text.call_args_list[0].args, ("group", "before"))
        self.assertEqual(im.send_text.call_args_list[1].args, ("group", "after"))
        im.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
