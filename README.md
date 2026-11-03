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


## Newly added non-duplicate challenges

The original solvers and fixture files remain unchanged. The next two challenges
have **separate implementations and tests** in
`tests/test_additional_solvers.py`.

| Challenge | Type | Algorithm | Input fixture |
| --- | --- | --- | --- |
| zeus | beginner/rev | Repeating-key XOR decoded from C source | `data/zeus_main.c` |
| skippy | rev/easy | Restore shifted AES key/IV and decrypt AES-128-CBC | `data/skippy_main.c` |

Run all previous and new regression tests with the same single command:

```bash
python -m unittest discover -s tests -v
python -m solvers.zeus data/zeus_main.c
python -m solvers.skippy data/skippy_main.c
```

Requirements: Python 3.10+ and the OpenSSL command for Skippy. The CI runner
provides OpenSSL. No challenge binary is executed: both new solvers parse data
from source fixtures. Accepted answers live only in regression tests and
documentation, not in the solver logic.

The project currently includes four implemented unique challenge solvers
(DTMF, caterpillar, Zeus, Skippy), with two separate Python test files.


## Phase 3: two additional non-duplicate challenge implementations

New challenge solvers are implemented independently of prior four and use
the same `data/` directory for original source fixtures. Original tests
are unchanged; new tests are isolated in `tests/test_phase3_solvers.py`.

| Challenge | Category | Reproducible operation | Result |
| --- | --- | --- | --- |
| mini-me | web | Reverse static XOR in source map to recover X-API-Key | Key recovered; remote flag not requested |
| As per my last email... (vimfu) | misc | Execute supplied Vim macro over supplied original lock and parse register z | DUCTF flag recovered |

```bash
python -m solvers.mini_me data/mini_me_sourcemap.json
python -m solvers.vimfu data/vimfu_key.txt data/vimfu_lock.txt
python -m unittest discover -s tests -v
```

**Security warning:** the Vim macro runner executes Vim commands. Only use
trusted CTF fixtures. The CI uses the original published DUCTF key/lock data,
and no third-party packages. It requires installed Vim.

The mini-me exercise proves recovery of the original admin API key from
a source map. The published flag is guarded by the server-side endpoint, which
this standalone offline algorithm does *not* request; treat recovered key as
a verified intermediate result, not proof of live flag retrieval.

Progress after this phase: six unique challenge solvers, three independent
test modules, with all tests run by the same GitHub Actions job.


## Phase 4: Rocky and SwiftPasswordManager: LoadMe

These are two *new*, non-duplicate challenge implementations. Previously
committed six challenge solvers and three test modules remain intact.
The additional tests live in `tests/test_phase4_solvers.py`.

| Challenge | Reproduced operation | Original fixture | Validation |
| --- | --- | --- | --- |
| Rocky | MD5 candidate lookup then AES-128-CBC with reversed password IV | `data/rocky_main.c` | Official flag from plaintext |
| SwiftPasswordManager: LoadMe | Parse SPM1 binary, iterate SHA-256 0xAAAA times, AES-256-GCM, deserialize login records | `data/loadme_passwords.spm.b64` | Official flag in decrypted login data |

The SPM1 fixture is the original 210-byte binary archived as base64 UTF-8 text
so it can be inspected in GitHub and decoded byte-for-byte. The password
`DUCTF2025!` comes from the challenge statement. Rocky's solver
does not contain the password: it tests an external candidate list and must
raise an error if no candidate matches the original MD5 hash.

Run using Python 3.10+, OpenSSL CLI and the `cryptography` package:

```bash
python -m pip install 'cryptography>=42,<50'
python -m solvers.rocky data/rocky_main.c data/rocky_candidates.txt
python -m solvers.loadme data/loadme_passwords.spm.b64
python -m unittest discover -s tests -v
```

The `rocky_candidates.txt` list is a small known-case regression fixture;
a general password-search attack needs a suitable dictionary and has no
guaranteed completion time. No expected flag is returned from the solver
implementations. The phase-4 CI run passed **33 of 33 tests** and printed
both recovered flags.

**Cumulative status:** eight unique challenge implementations, of which seven
have recovered official flags locally. Mini-me has verified offline key
recovery only; remote flag receipt was not asserted.
