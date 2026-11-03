# DownUnderCTF 2025 — reproducible algorithm solvers

Independent Python 3.10+ implementations of challenge-solving algorithms.
The repository includes original publicly released challenge inputs, not
answer-bearing source files. Results are derived from supplied encoded data.

Original source: https://github.com/DownUnderCTF/Challenges_2025_Public

## Run

~~~bash
python -m solvers.dtmf data/dtmf.txt
python -m solvers.caterpillar data/caterpillar_output.txt
python -m unittest discover -s tests -v
~~~

No third-party packages required.

| Challenge | Algorithm | Recovered flag |
| --- | --- | --- |
| Down To Modulate Frequencies! | DTMF frequency sums and keypad multi-tap | DUCTF{onlyninetieskidswillrememberthis} |
| hungry-hungry-caterpillar | Reused XOR keystream, equation graph, explicit cribs | DUCTF{the_hungry_little_p_smooth_caterpillar_wow_an_allegory_for_life} |

## Limits and provenance

- The DTMF decoder deterministically derives its answer from the input signal.
- Caterpillar is mathematically underdetermined from ciphertext alone.
  Prime-indexed components require externally inferred letters (cribs).
  These assumptions are listed in DEFAULT_CRIBS in solvers/caterpillar.py.
- Official expected flags appear in tests and documentation only, not in
  the solver return logic. Tests check correctness for these known examples,
  not unseen CTF problems.
- Original challenge files and problem metadata are available upstream.
