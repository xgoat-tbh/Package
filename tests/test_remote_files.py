"""Automated end-to-end verification tests for Windows File Explorer module."""

import os
import shutil
import tempfile
import unittest

from syspy.agent import files


class TestRemoteFilesExplorer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="syspy_test_fs_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_list_drives(self):
        drives = files.list_drives()
        self.assertIsInstance(drives, list)
        self.assertGreater(len(drives), 0, "At least one drive should be detected on Windows")
        first = drives[0]
        self.assertIn("letter", first)
        self.assertIn("drive_type", first)
        self.assertIn("total", first)
        self.assertIn("free", first)
        self.assertIn("percent_used", first)
        print(f"\n[OK] Drives detected: {[d['name'] for d in drives]}")

    def test_02_special_folders(self):
        specials = files.get_special_folders()
        self.assertIsInstance(specials, dict)
        self.assertIn("Desktop", specials)
        self.assertIn("Documents", specials)
        self.assertTrue(os.path.exists(specials["Desktop"]), "Desktop path should exist")
        print(f"[OK] Special folders resolved: Desktop={specials.get('Desktop')}")

    def test_03_list_directory_this_pc(self):
        res = files.list_directory("")
        self.assertTrue(res.get("is_this_pc"))
        self.assertIn("drives", res)
        self.assertIn("special_folders", res)

    def test_04_create_read_save_conflict(self):
        # Create file
        file_path = os.path.join(self.test_dir, "test_document.txt")
        initial_content = "Hello, SysPy Windows Explorer!\r\nLine 2\r\n"
        cr_res = files.create_file(file_path, initial_content)
        self.assertTrue(cr_res.get("success"), cr_res)

        # Read file
        read_res = files.read_file_content(file_path)
        self.assertTrue(read_res.get("success"))
        self.assertEqual(read_res["content"], initial_content)
        initial_sha = read_res["sha"]
        self.assertIsNotNone(initial_sha)

        # Safe save with matching expected_sha
        new_content = "Hello, SysPy Windows Explorer!\r\nLine 2 updated\r\n"
        save_res = files.save_file_content(file_path, new_content, expected_sha=initial_sha)
        self.assertTrue(save_res.get("success"), save_res)
        updated_sha = save_res["sha"]
        self.assertNotEqual(initial_sha, updated_sha)

        # Concurrency conflict test: saving with old initial_sha should fail with conflict=True
        conflict_res = files.save_file_content(file_path, "Stale edit", expected_sha=initial_sha)
        self.assertFalse(conflict_res.get("success"))
        self.assertTrue(conflict_res.get("conflict"))
        print("[OK] Safe atomic write and optimistic concurrency conflict verified")

    def test_05_rename_and_copy_move(self):
        src_file = os.path.join(self.test_dir, "file_a.txt")
        files.create_file(src_file, "Original A")

        # Rename
        ren_res = files.rename_item(src_file, "file_a_renamed.txt")
        self.assertTrue(ren_res.get("success"), ren_res)
        renamed_path = ren_res["new_path"]
        self.assertTrue(os.path.exists(renamed_path))

        # Subdirectory
        sub_dir = os.path.join(self.test_dir, "sub_folder")
        files.create_directory(sub_dir)

        # Copy
        cp_res = files.copy_or_move([renamed_path], sub_dir, is_move=False)
        self.assertTrue(cp_res.get("success"))
        self.assertTrue(os.path.exists(os.path.join(sub_dir, "file_a_renamed.txt")))
        self.assertTrue(os.path.exists(renamed_path))

        # Move
        mv_res = files.copy_or_move([renamed_path], sub_dir, is_move=True, conflict_resolution="replace")
        self.assertTrue(mv_res.get("success"))
        self.assertFalse(os.path.exists(renamed_path))
        print("[OK] Rename, Copy, Move with conflict resolution verified")

    def test_06_search_and_properties(self):
        target_file = os.path.join(self.test_dir, "syspy_search_needle.py")
        files.create_file(target_file, "# syspy target search test\n")

        # Search
        search_res = files.search_filesystem(self.test_dir, "search_needle")
        self.assertGreater(search_res.get("count", 0), 0)
        self.assertEqual(search_res["results"][0]["name"], "syspy_search_needle.py")

        # Properties
        prop_res = files.get_properties(target_file)
        self.assertEqual(prop_res["name"], "syspy_search_needle.py")
        self.assertIn("sha256", prop_res)
        self.assertIn("attributes", prop_res)
        print(f"[OK] Search and properties verified: SHA-256={prop_res['sha256'][:16]}...")

    def test_07_recycle_bin_and_permanent_delete(self):
        f1 = os.path.join(self.test_dir, "to_delete_recycle.txt")
        f2 = os.path.join(self.test_dir, "to_delete_perm.txt")
        files.create_file(f1, "recycle me")
        files.create_file(f2, "perm delete me")

        # Recycle bin delete
        del1 = files.delete_item(f1, permanent=False)
        self.assertTrue(del1.get("success"), del1)
        self.assertFalse(os.path.exists(f1))

        # Permanent delete
        del2 = files.delete_item(f2, permanent=True)
        self.assertTrue(del2.get("success"), del2)
        self.assertFalse(os.path.exists(f2))
        print("[OK] Windows Recycle Bin and permanent deletion verified")

    def test_08_zip_download_and_upload(self):
        # Create folder with files
        folder_to_zip = os.path.join(self.test_dir, "MyDownloadedFolder")
        files.create_directory(folder_to_zip)
        files.create_file(os.path.join(folder_to_zip, "sample.txt"), "sample inside zip")

        # Prepare zip download
        zip_path = files.prepare_zip_download(folder_to_zip)
        self.assertTrue(os.path.exists(zip_path))
        self.assertTrue(zip_path.endswith("MyDownloadedFolder.zip"))

        # Verify zip contents
        import zipfile
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            self.assertTrue(any("sample.txt" in n for n in names))

        os.remove(zip_path)

        # Test upload save
        uploaded_target = files.save_upload(self.test_dir, "uploaded_script.py", b"print('remote upload OK')")
        self.assertTrue(os.path.exists(uploaded_target))
        with open(uploaded_target, "rb") as f:
            self.assertEqual(f.read(), b"print('remote upload OK')")

        # Test invalid filename validation
        bad_file = files.create_file(os.path.join(self.test_dir, "bad:file?.txt"), "test")
        self.assertIn("error", bad_file)

        print("[OK] Directory zip archive, safe upload, and invalid filename checks verified")


if __name__ == "__main__":
    unittest.main()
