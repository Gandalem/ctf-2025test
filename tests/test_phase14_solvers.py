"""Phase 14 independent regression suite for BeepBeep and Mutant.

The previous 13 test modules are unchanged. WAV audio and original
browser sanitizer JavaScript are the actual public challenge data.
"""
import io
import os
import unittest
import wave
from pathlib import Path

from solvers import beepbeep, mutant

DATA = Path(__file__).resolve().parents[1] / "data"


def generate_tones(message: str, rate: int = 8000, tone_ms: int = 75) -> bytes:
    import numpy as np
    width = rate * tone_ms // 1000
    # Distinct synthetic alphabet frequencies, not the published CTF tones.
    freqs = [260 + n * 42 for n in range(26)]
    parts = []
    for letter in message:
        n = ord(letter) - 97
        if not 0 <= n < 26:
            raise ValueError("Synthetic encoder accepts only lowercase letters")
        time = np.arange(width, dtype=np.float64) / rate
        samples = 11000 * np.sin(2 * np.pi * freqs[n] * time)
        parts.append(samples.astype("<i2"))
    audio = np.concatenate(parts)
    output = io.BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(audio.tobytes())
    return output.getvalue()


class BeepBeepTests(unittest.TestCase):
    def test_synthetic_alphabet_decode_exactly(self):
        message = "abcdefghijklmnopqrstuvwxyzhelloworld"
        self.assertEqual(
            beepbeep.decode_tones(generate_tones(message)), message)

    def test_synthetic_complete_flag(self):
        message = "abcdefghijklmnopqrstuvwxyzductfopenbracketsampleclosebracket"
        self.assertEqual(beepbeep.solve(generate_tones(message)), "DUCTF{sample}")

    def test_works_with_a_different_sample_rate(self):
        message = "abcdefghijklmnopqrstuvwxyzmixedtones"
        self.assertEqual(
            beepbeep.decode_tones(generate_tones(message, rate=16000)),
            message,
        )

    def test_reject_missing_alphabet_preamble(self):
        message = "abcdefghijklmnopqrstuvwxyznomarker"
        with self.assertRaisesRegex(ValueError, "exactly one"):
            beepbeep.solve(generate_tones(message))

    def test_reject_truncated_input(self):
        with self.assertRaises((ValueError, EOFError, wave.Error)):
            beepbeep.decode_tones(b"bad wav")

    def test_no_27th_symbol(self):
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            beepbeep.decode_tones(generate_tones("abcdefghijklmnopqrstuvwxyz"))

    def test_actual_original_public_wav_flag(self):
        path = os.getenv("DUCTF_BEEP_WAV")
        if not path:
            self.skipTest("Original WAV is downloaded by GitHub Actions")
        result = beepbeep.solve(Path(path).read_bytes())
        self.assertEqual(result, "DUCTF{iforonewelcomeouraioverlords}")


class MutantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (DATA / "mutant/main.js").read_text(encoding="utf-8")
        cls.html = (DATA / "mutant/index.html").read_text(encoding="utf-8")

    def test_original_javascript_sanitizer_contract(self):
        mutant.validate_source(self.js)

    def test_mutation_bypass_executes_benign_alert(self):
        triggered, output = mutant.simulate_original(
            self.js, self.html, mutant.MUTATION_SAMPLE)
        self.assertTrue(triggered)
        self.assertIn("onerror", output)

    def test_normal_img_event_handler_removed(self):
        triggered, output = mutant.simulate_original(
            self.js, self.html, mutant.NEGATIVE_SAMPLE)
        self.assertFalse(triggered)
        self.assertNotIn("onerror", output)

    def test_original_filter_complete_regression(self):
        self.assertTrue(mutant.solve(self.js, self.html))

    def test_plain_text_is_safe(self):
        triggered, output = mutant.simulate_original(
            self.js, self.html, "ordinary page text")
        self.assertFalse(triggered)
        self.assertIn("ordinary page text", output)

    def test_sanitizer_changed_is_detected(self):
        changed = self.js.replace(
            "myoutput.innerHTML = t.innerHTML;",
            "myoutput.innerText = t.innerHTML;",
        )
        with self.assertRaises(ValueError):
            mutant.validate_source(changed)

    def test_external_callback_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-exfiltrating"):
            mutant.simulate_original(
                self.js, self.html,
                "<img src=1 onerror=fetch('https://external.invalid/x')>",
            )

    def test_missing_template_reference_rejected(self):
        with self.assertRaisesRegex(ValueError, "Jinja"):
            mutant.simulate_original(self.js, "<html></html>")


if __name__ == "__main__":
    unittest.main()
