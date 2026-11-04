"""Phase 18: separate Wiki (Gemini) and Sweet Treat (cookie) tests.

The previous 17 unittest modules and all earlier fixtures are untouched.
The Wiki server is a deterministic in-memory Gemini capsule; Sweet Treat
is an explicit *simulation* of legacy parser behavior, not a Tomcat test.
"""
import unittest
from pathlib import Path

from solvers import wiki, sweet_treat as sweet

ROOT = Path(__file__).resolve().parents[1] / "data"
WIKI = ROOT / "wiki"
SWEET = ROOT / "sweet_treat"


class WikiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (WIKI / "original_crawler.go").read_text(encoding="utf-8")

    def test_original_go_crawler_contract(self):
        wiki.validate_original_source(self.source)

    def test_gemini_success_status_header(self):
        page = wiki.parse_gemini_response(
            "gemini://example.invalid/", b"20 text/gemini; charset=utf-8\r\n# Welcome\n"
        )
        self.assertEqual((page.status, page.meta), (20, "text/gemini; charset=utf-8"))
        self.assertIn("Welcome", page.body)

    def test_reject_malformed_header(self):
        for text in (b"200 text/gemini\r\nbad", b"20 text/gemini\nbad", b"99 invalid\r\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                wiki.parse_gemini_response("gemini://example.invalid/", text)

    def test_relative_and_absolute_gemini_links(self):
        base = "gemini://capsule.invalid:1965/docs/index.gmi"
        links = wiki.links_from_gemtext(
            "=> child.gmi Child\n=> /root.gmi Root\n=> https://example.invalid/ No\n"
            "=> gemini://other.invalid/x Another\n", base)
        self.assertIn("gemini://capsule.invalid:1965/docs/child.gmi", links)
        self.assertIn("gemini://capsule.invalid:1965/root.gmi", links)
        self.assertIn("gemini://other.invalid:1965/x", links)
        self.assertEqual(len(links), 3)

    def test_cycle_dedup_same_origin_and_synthetic_flag(self):
        pages = {
            "gemini://capsule.invalid:1965/": (
                b"20 text/gemini\r\n# Index\n=> /a.gmi\n=> /b.gmi\n"
                b"=> gemini://other.invalid/private\n"
            ),
            "gemini://capsule.invalid:1965/a.gmi": (
                b"20 text/gemini\r\n=> /a.gmi\n=> /b.gmi\n"
            ),
            "gemini://capsule.invalid:1965/b.gmi": (
                b"20 text/gemini\r\n# CTF\nDUCTF{SYNTHETIC_WIKI_FLAG}\n=> /\n"
            ),
        }
        called = []
        def fetch(url):
            called.append(url)
            return pages[url]
        self.assertEqual(
            wiki.crawl("gemini://capsule.invalid/", fetch),
            {"gemini://capsule.invalid:1965/b.gmi": ["DUCTF{SYNTHETIC_WIKI_FLAG}"]},
        )
        self.assertEqual(len(called), 3)
        self.assertNotIn("gemini://other.invalid:1965/private", called)

    def test_non_gemtext_does_not_follow_links(self):
        pages = {
            "gemini://capsule.invalid:1965/": b"20 text/plain\r\n=> /secret.gmi\n",
        }
        self.assertEqual(wiki.crawl("gemini://capsule.invalid/", pages.__getitem__), {})

    def test_redirect_and_input_status_does_not_extract_flag(self):
        pages = {
            "gemini://capsule.invalid:1965/": b"30 /other.gmi\r\nDUCTF{FAKE}",
        }
        self.assertEqual(wiki.crawl("gemini://capsule.invalid/", pages.__getitem__), {})

    def test_max_pages_limits_work(self):
        called = []
        def fetch(url):
            called.append(url)
            return b"20 text/gemini\r\n=> /a.gmi\n"
        wiki.crawl("gemini://capsule.invalid/", fetch, max_pages=1)
        self.assertEqual(len(called), 1)
        with self.assertRaises(ValueError):
            wiki.crawl("gemini://capsule.invalid/", fetch, max_pages=0)

    def test_wrong_url_scheme_rejected(self):
        for url in ("https://example.invalid", "gemini:///no-host", "not-a-url"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                wiki.canonical_url(url)


class SweetTreatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = (SWEET / "index.jsp").read_text(encoding="utf-8")
        cls.admin = (SWEET / "admin_review.jsp").read_text(encoding="utf-8")
        cls.profile = (SWEET / "edit_profile.jsp").read_text(encoding="utf-8")
        cls.docker = (SWEET / "Dockerfile").read_text(encoding="utf-8")

    def test_original_jsp_docker_contract(self):
        sweet.validate_source(self.index, self.admin, self.profile, self.docker)

    def test_synthetic_cookie_sandwich_model(self):
        header, parsed = sweet.synthetic_sandwich()
        self.assertTrue(header.startswith("$Version=1; language="))
        self.assertIn("DUCTF{SYNTHETIC_TEST_VALUE}", parsed["language"])
        self.assertIn("JSESSIONID=LOCAL_SESSION", parsed["language"])
        self.assertNotIn("flag", parsed)

    def test_httponly_cookie_still_in_request_header(self):
        cookies = [sweet.Cookie("flag", "LOCAL_ONLY", http_only=True)]
        self.assertIn("flag=LOCAL_ONLY", sweet.cookie_header(cookies, "/index.jsp"))

    def test_cookie_path_priority(self):
        cookies = [
            sweet.Cookie("global", "second", "/", created=0),
            sweet.Cookie("specific", "first", "/index.jsp", created=10),
        ]
        self.assertEqual(
            sweet.cookie_header(cookies, "/index.jsp"),
            "specific=first; global=second",
        )
        self.assertEqual(sweet.cookie_header(cookies, "/other"), "global=second")

    def test_cookie_creation_order_tie_break(self):
        cookies = [
            sweet.Cookie("later", "2", "/", created=10),
            sweet.Cookie("earlier", "1", "/", created=2),
        ]
        self.assertEqual(
            sweet.cookie_header(cookies, "/"), "earlier=1; later=2",
        )

    def test_legacy_and_plain_parser_differ(self):
        header = '$Version=1; language="start; flag=DUCTF{SYNTHETIC}; end="'
        cookies = dict(sweet.parse_legacy_cookies(header))
        self.assertEqual(cookies["language"], "start; flag=DUCTF{SYNTHETIC}; end=")
        self.assertNotIn("flag", cookies)

    def test_original_jsp_reflects_modelled_language(self):
        result = sweet.analyse(self.index, self.admin, self.profile, self.docker)
        self.assertTrue(result["synthetic_marker_reflected"])
        self.assertIn("DUCTF{SYNTHETIC_TEST_VALUE}", result["reflected_html"])

    def test_missing_original_source_contract_rejected(self):
        with self.assertRaises(ValueError):
            sweet.validate_source(self.index.replace("<%= lang %>", "<%= escapedLang %>"),
                                  self.admin, self.profile, self.docker)

    def test_invalid_marker_and_cookie_header_rejected(self):
        for marker in ("flag", "NOT;SAFE", "DUCTF{FAKE}", "lowercase"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                sweet.synthetic_sandwich(marker)
        with self.assertRaises(ValueError):
            sweet.cookie_header([sweet.Cookie("x", "v\r\nbad")], "/")

    def test_synthetic_marker_does_not_equal_hosted_secret(self):
        _, cookies = sweet.synthetic_sandwich("OTHER_TEST_MARKER")
        self.assertIn("DUCTF{OTHER_TEST_MARKER}", cookies["language"])
        self.assertNotIn("SYNTHETIC_TEST_VALUE", cookies["language"])


if __name__ == "__main__":
    unittest.main()
