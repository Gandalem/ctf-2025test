"""Phase 9 new tests: Godot tile font and Go path-validation bypass.

All prior test modules are discovered unchanged via unittest discovery.
"""
import unittest
from pathlib import Path
from solvers import godot_tiles, secure_email_attachments as sea

DATA = Path(__file__).resolve().parents[1] / "data"

class GodotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "godot_tile_map_layer.gd").read_text(encoding="utf-8")
        cls.pixels = godot_tiles.parse_coordinates(cls.source)

    def test_original_tile_map_recovers_official_flag(self):
        self.assertEqual(
            godot_tiles.solve(self.source),
            "ductf{the_boy_will_never_remember}",
        )

    def test_extracts_real_pixels_from_original_map(self):
        self.assertGreater(len(self.pixels), 200)
        self.assertIn((-34, -255), self.pixels)

    def test_top_bottom_two_rows(self):
        result = godot_tiles.decode_text(self.pixels)
        self.assertTrue(result.startswith("DUCTF{"))
        self.assertIn("NEVER", result)

    def test_missing_tiles_rejected(self):
        with self.assertRaisesRegex(ValueError, "coords"):
            godot_tiles.solve("extends TileMapLayer")

    def test_unrecognized_glyph_rejected(self):
        changed = set(self.pixels)
        changed.add((-35, -255))
        with self.assertRaisesRegex(ValueError, "Unknown tile glyph"):
            godot_tiles.decode_text(changed)

    def test_invalid_height_rejected(self):
        with self.assertRaises(ValueError):
            godot_tiles.glyph_rows(self.pixels, -255, height=0)


class SecureEmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "secure_email_attachments_main.go").read_text(encoding="utf-8")

    def test_original_go_source_assumptions(self):
        sea.validate_source(self.source)

    def test_local_synthetic_flag_disclosure(self):
        marker = "DUCTF{ANOTHER_SYNTHETIC_MARKER}"
        self.assertEqual(sea.local_demo(self.source, marker), marker)

    def test_generated_path_without_literal_parent(self):
        payload = sea.bypass_path()
        self.assertNotIn("..", payload)
        self.assertIn("/attachments", payload)

    def test_go_equivalent_path_escapes_base(self):
        payload = sea.bypass_path()
        resolved = sea.transform_path(payload)
        self.assertEqual(resolved, "../etc/flag.txt")
        self.assertTrue(sea.escapes_attachments(resolved))

    def test_normal_file_is_confined(self):
        self.assertFalse(sea.escapes_attachments(sea.transform_path("/photo.jpg")))
        self.assertEqual(sea.transform_path("/photo.jpg"), "attachments/photo.jpg")

    def test_simple_traversal_blocked(self):
        with self.assertRaisesRegex(ValueError, "dot-dot"):
            sea.transform_path("/../../etc/flag.txt")

    def test_source_change_rejected(self):
        mutated = self.source.replace(
            'strings.ReplaceAll(p, "/attachments", "")',
            'strings.ReplaceAll(p, "/safe", "")',
        )
        with self.assertRaisesRegex(ValueError, "sanitizer changed"):
            sea.validate_source(mutated)

    def test_bad_depth_rejected(self):
        with self.assertRaises(ValueError):
            sea.bypass_path(levels=0)

    def test_invalid_target_rejected(self):
        with self.assertRaises(ValueError):
            sea.bypass_path("../etc/passwd")

    def test_single_level_escape(self):
        path = sea.transform_path(sea.bypass_path("example.txt", levels=1))
        self.assertEqual(path, "example.txt")
        self.assertTrue(sea.escapes_attachments(path))

if __name__ == "__main__":
    unittest.main()
