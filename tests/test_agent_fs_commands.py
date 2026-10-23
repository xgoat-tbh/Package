"""Test suite for agent filesystem command dispatching."""

import json
import os
import shutil
import tempfile
import unittest

from syspy.agent import commands


class MockAgent:
    def __init__(self):
        self.sent_json = []
        self.replies = []
        self.cwd = os.getcwd()
        self.processes = set()

    def send_json(self, payload):
        self.sent_json.append(payload)

    def reply(self, msg):
        self.replies.append(msg)


class TestAgentCommands(unittest.TestCase):
    def setUp(self):
        self.agent = MockAgent()
        self.test_dir = tempfile.mkdtemp(prefix="syspy_cmd_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fs_drives_cmd(self):
        commands.execute(self.agent, "fs.drives")
        self.assertGreater(len(self.agent.sent_json), 0)
        res = self.agent.sent_json[-1]
        self.assertEqual(res.get("kind"), "drives")
        self.assertIn("drives", res)
        self.assertIn("special_folders", res)

    def test_fs_list_cmd(self):
        commands.execute(self.agent, f'fs.list "{self.test_dir}"')
        self.assertGreater(len(self.agent.sent_json), 0)
        res = self.agent.sent_json[-1]
        self.assertEqual(res.get("kind"), "listing")
        self.assertEqual(res.get("path"), os.path.abspath(self.test_dir))

    def test_fs_touch_and_read_and_save(self):
        file_path = os.path.join(self.test_dir, "hello.txt")
        # Touch
        commands.execute(self.agent, f'fs.touch "{file_path}"')
        res_touch = self.agent.sent_json[-1]
        self.assertEqual(res_touch.get("kind"), "fs_op_result")
        self.assertTrue(res_touch.get("success"))

        # Read
        commands.execute(self.agent, f'fs.read "{file_path}"')
        res_read = self.agent.sent_json[-1]
        self.assertEqual(res_read.get("kind"), "file_content")
        self.assertEqual(res_read.get("content"), "")
        sha = res_read.get("sha")

        # Save
        save_payload = json.dumps({"path": file_path, "content": "Updated via fs.save", "expected_sha": sha})
        commands.execute(self.agent, f"fs.save {save_payload}")
        res_save = self.agent.sent_json[-1]
        self.assertEqual(res_save.get("kind"), "save_result")
        self.assertTrue(res_save.get("success"))

        # Read again to verify content on disk
        with open(file_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "Updated via fs.save")

    def test_fs_search(self):
        file_path = os.path.join(self.test_dir, "my_special_file.txt")
        with open(file_path, "w") as f:
            f.write("content")
        commands.execute(self.agent, f'fs.search {json.dumps({"root": self.test_dir, "query": "special"})}')
        res = self.agent.sent_json[-1]
        self.assertEqual(res.get("kind"), "search_results")
        self.assertGreaterEqual(res.get("count", 0), 1)

    def test_fs_prop(self):
        file_path = os.path.join(self.test_dir, "meta.txt")
        with open(file_path, "w") as f:
            f.write("meta content")
        commands.execute(self.agent, f'fs.prop "{file_path}"')
        res = self.agent.sent_json[-1]
        self.assertEqual(res.get("kind"), "properties")
        self.assertEqual(res.get("name"), "meta.txt")
        self.assertIn("sha256", res)

    def test_py_command(self):
        commands.execute(self.agent, 'py print("PY_EXEC_TEST_OUTPUT")')
        self.assertTrue(any("PY_EXEC_TEST_OUTPUT" in rep for rep in self.agent.replies), self.agent.replies)

    def test_cmd_command(self):
        commands.execute(self.agent, 'cmd echo CMD_TEST_OK')
        self.assertTrue(any("CMD_TEST_OK" in rep for rep in self.agent.replies), self.agent.replies)


if __name__ == "__main__":
    unittest.main()
