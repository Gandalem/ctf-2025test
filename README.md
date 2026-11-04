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


## Phase 5: bilingual (reversing) and corporate-cliche (pwn)

Two **new** challenge IDs are added; the existing eight solvers and four
independent test modules remain unchanged. All phase-5 regression cases are
in `tests/test_phase5_solvers.py` and use original CTF fixtures.

| Challenge | Solver | Validation scope |
| --- | --- | --- |
| bilingual | Infer positional password constraints from C helper, recover its RC4 crib with 26^3 enumeration, search final digit candidates, decrypt original Base64/RC4 flag | Full flag output |
| corporate-cliche | Parse admin credential from original C source, craft a null-terminated overflow payload, execute the original published Linux ELF in a local temporary directory | Admin shell/session marker (not hosted flag) |

The published bilingual Python challenge contains embedded native code. Our
solver does not load or run the embedded library; it uses static data only.

The corporate challenge specifically depends on the **stack layout of the
original compiled binary**. Compiling its C code with a modern GCC can change
local-variable ordering; this is why the regression fixture
`data/corporate_email_server.elf.b64` holds the byte-identical
original upstream ELF encoded as Base64. The local replay executes only that
trusted public CTF sample. It runs a harmless shell confirmation command and
does not connect to remote hosts or claim hosted flag retrieval.

```bash
python -m solvers.bilingual data/bilingual_published.py data/bilingual_helper.cpp
python -m solvers.corporate_cliche data/corporate_email_server.c data/corporate_email_server.elf.b64
python -m unittest discover -s tests -v
```

**Requirements:** Python 3.10+, a Linux runner that can execute the original
x86-64 ELF, OpenSSL/Vim/GCC and the cryptography dependency already used in CI.
The bilingual solver itself uses only Python standard library.

## Phase 6: ClickMe and philtered

Two new, non-duplicate challenges are added. Previously implemented ten
solvers and five prior test files remain unchanged. New tests reside only in
`tests/test_phase6_solvers.py`, and the same GitHub Actions workflow runs all.

| Challenge | Algorithm | Verification |
| --- | --- | --- |
| SwiftPasswordManager: ClickMe | Parse original Swift UI source and invert index-based XOR on the disabled Flag button bytes | Official DUCTF flag recovered directly from original source |
| philtered | Execute original PHP index/layout with ordered mass-assignment query and php://filter Base64 source wrapper | Controlled local source disclosure of synthetic marker (no hosted flag claimed) |

Inputs under `data/` are copies of original public challenge source files.
The original flag.php file was NOT bundled. The philtered solver makes a
temporary synthetic flag.php fixture, tests that the vulnerable PHP app
discloses the synthetic value, then deletes the temporary files.

Commands:

```bash
python -m solvers.clickme data/clickme_app.swift
python -m solvers.philtered data/philtered
python -m unittest discover -s tests -v
```

Dependencies: Python 3.10+, PHP CLI for the philtered offline reproduction;
the existing requirements used by prior phases remain necessary. Never run
untrusted PHP challenge sources without isolation. Full cumulative count:
12 unique implemented challenges; 9 recovered flags, and 3 verified partial or
local exploit milestones (mini-me API key, corporate-cliche local admin
session, philtered synthetic secret disclosure).

## Phase 7: SwiftPasswordManager CrackMe and ECB-a-tron-9000

This phase adds two **previously unimplemented challenge IDs** while keeping
all six previous test modules and 12 solvers intact. New tests are isolated in
`tests/test_phase7_solvers.py`; the original published Swift validator and
ECB FastAPI backend are preserved in `data/`.

| Challenge | Implementation | Verified outcome |
| --- | --- | --- |
| SwiftPasswordManager: CrackMe | Reconstruct position constraints, solve 3-variable integer systems, invert character hashes by printable-domain enumeration, and verify original 64-bit custom hashes | Full official flag reconstructed directly from Swift constraints |
| ECB-a-tron-9000 | Chosen-plaintext ECB byte-at-a-time append-secret recovery; uses original batch limit of 256 candidates and detects exact secret length (including trailing spaces) | Synthetic local hidden secret fully recovered, including cross-block bytes; no hosted flag claimed |

The ECB algorithm does **not** read or embed the official challenge flag.
The published backend creates a random AES key and loads SECRET from an
environment variable. It must be run against a working oracle to retrieve
that oracle's actual SECRET. CI supplies an *independent local oracle* with
synthetic secrets to verify the attack mechanics only.

```bash
python -m pip install 'pycryptodome>=3.20,<4'
python -m solvers.crackme data/crackme.swift
python -m solvers.ecb_a_tron data/ecb_a_tron_main.py
python -m unittest discover -s tests -v
```

The extra dependency is required only for the test's local AES-ECB oracle.
The core suffix-recovery algorithm does not require an AES library and can
be wired to an authorized CTF service through a callback.

## Phase 8: yet another login and Horoscopes

Two distinct challenge IDs added without modifying any earlier 14 solver
implementations or seven existing test modules.

| Challenge | Solver | Validation boundary |
| --- | --- | --- |
| yet another login (crypto) | Paillier homomorphic bit-verification oracle, 256-bit MAC recovery, manual SHA-256 state continuation, public-key token forgery | **Original service's** locally instantiated TokenService accepted forged `user=admin` token; no hosted flag retrieved |
| Horoscopes (beginner/misc) | Gemini `20 text/gemini` parser, relative link normalization and breadth-first same-host crawl of original .gmi handouts | Official DUCTF flag extracted from original Gemini capsule page |

New tests in `tests/test_phase8_solvers.py` reuse the original fixtures in
`data/yet_another_login_chall.py` and `data/horoscopes/`. They include
positive / negative protocol cases, the original token service in a local
test, and SHA-256 length-extension digests checked against hashlib.

Commands:

```bash
python -m solvers.horoscopes data/horoscopes
python -m solvers.yet_another_login data/yet_another_login_chall.py
python -m unittest discover -s tests -v
```

Requirements: Python 3.10+ with the existing `pycryptodome` dependency
to run the original CTF service's Paillier key generation. SHA-256 state
continuation itself requires no external package. Running
`yet_another_login.local_demo` executes only the trusted original published
Python challenge fixture and uses its local verification oracle. Do not run
untrusted problem files or use this reproduction against non-CTF systems.

For Horoscopes, the original answer is visible in a distributed .gmi handout.
No remote Gemini server was queried. The Gemini parser is reusable for
other Gemini-transport CTF tasks, but the standalone CLI currently crawls
local handout pages rather than opening a live TLS socket.

Cumulative status: **16 unique implementations**. Of these, 11 derive
published flags from original inputs and 5 establish a verified local
exploit or recovered intermediate value; no hosted flags were claimed for
those five local-only cases.
