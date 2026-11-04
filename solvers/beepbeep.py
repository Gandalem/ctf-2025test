"""DUCTF 2025 BeepBeep: decode alphabet-indexed audio tone messages.

The original WAV contains 75-ms 8-kHz mono PCM tones. The first 26
ascending/unique tones encode a..z, providing the frequency alphabet.
Decode every subsequent tone from the nearest learned FFT frequency and
parse "ductfopenbracket...closebracket" into the actual Flag.
No flag or original plaintext is stored in this solver.
"""
import argparse
import io
import re
import wave
from pathlib import Path


def read_wav(raw: bytes) -> tuple[int, "numpy.ndarray"]:
    import numpy as np

    with wave.open(io.BytesIO(raw), "rb") as sound:
        sample_rate = sound.getframerate()
        channels = sound.getnchannels()
        sample_width = sound.getsampwidth()
        frames = sound.getnframes()
        if channels != 1 or sample_width != 2 or sample_rate < 1000:
            raise ValueError("Expected 16-bit mono audio with normal sample rate")
        samples = np.frombuffer(sound.readframes(frames), dtype="<i2").astype(np.float64)
    if not len(samples):
        raise ValueError("Empty audio")
    return sample_rate, samples


def decode_tones(raw: bytes, tone_ms: int = 75) -> str:
    import numpy as np

    rate, samples = read_wav(raw)
    width = round(rate * tone_ms / 1000)
    if width < 64 or len(samples) < width * 27:
        raise ValueError("Insufficient audio or invalid tone size")
    # Last incomplete fragment is not a full transmitted symbol.
    count = len(samples) // width
    chunks = samples[:count * width].reshape(count, width)
    window = np.hanning(width)
    frequencies = np.fft.rfftfreq(width, d=1.0 / rate)
    spectrum = np.abs(np.fft.rfft(chunks * window, axis=1))
    spectrum[:, :2] = 0
    # Spectral peak refined by quadratic interpolation to accommodate
    # tones that fall between the FFT bins.
    peak = np.argmax(spectrum, axis=1)
    indices = np.arange(count)
    left = spectrum[indices, np.maximum(peak - 1, 0)]
    center = spectrum[indices, peak]
    right = spectrum[indices, np.minimum(peak + 1, spectrum.shape[1] - 1)]
    denominator = left - 2 * center + right
    delta = np.divide(
        .5 * (left - right), denominator,
        out=np.zeros_like(center), where=np.abs(denominator) > 1e-12,
    )
    dominant = (peak + np.clip(delta, -0.5, 0.5)) * rate / width
    alphabet = dominant[:26]
    if np.min(np.diff(np.sort(alphabet))) < rate / width * 0.5:
        raise ValueError("Initial frequency alphabet not uniquely spaced")
    # First 26 symbols must be ordered a..z, but no prior frequency
    # constants or expected Flag are needed.
    distances = np.abs(dominant[:, None] - alphabet[None, :])
    closest = np.argmin(distances, axis=1)
    if np.max(np.min(distances, axis=1)) >= rate / width * 1.2:
        raise ValueError("Encountered tone outside the trained alphabet")
    return "".join(chr(97 + int(i)) for i in closest)


def solve(raw: bytes) -> str:
    transcript = decode_tones(raw)
    if not transcript.startswith("abcdefghijklmnopqrstuvwxyz"):
        raise ValueError("WAV preamble did not decode to alphabet")
    matches = re.findall(
        r"ductfopenbracket([a-z0-9]+)closebracket",
        transcript, flags=re.IGNORECASE,
    )
    if len(matches) != 1:
        raise ValueError("Expected exactly one DUCTF flag in decoded tones")
    return "DUCTF{" + matches[0] + "}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wav", type=Path, help="Original public BeepBeep WAV")
    args = parser.parse_args()
    raw = args.wav.read_bytes()
    print("Recovered Flag:", solve(raw))


if __name__ == "__main__":
    main()
