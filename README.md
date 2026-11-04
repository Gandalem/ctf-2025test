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

## Phase 9: Godot tile-font extraction and secure email attachments

Two new distinct challenge IDs, with existing 16 solver implementations and
eight previous test modules unchanged. The new independent suite is
`tests/test_phase9_solvers.py` (16 tests); all run through the original CI.

| Challenge | Algorithm | Verified result |
| --- | --- | --- |
| godot | Parse original GDScript `Vector2i(x,y)` placements; group 5-row pixel glyphs, decode visual font, parse DUCTF text | Official Flag reconstructed from original source |
| secure email attachments | Reproduce exact original Go string checks, `ReplaceAll`, Unix `Clean`/`Join` and directory traversal; read a synthetic file in an isolated temporary directory | **Local path traversal with synthetic flag verified**. Hosted flag not fetched |

Original challenge files are copied to
`data/godot_tile_map_layer.gd` and
`data/secure_email_attachments_main.go`. No answer-bearing source or actual
secret file was used for the Go challenge; the solver creates a disposable
dummy path and marker. The Godot decoder uses individual glyph templates,
rather than embedding the complete expected Flag string.

Run:

```bash
python -m solvers.godot_tiles data/godot_tile_map_layer.gd
python -m solvers.secure_email_attachments data/secure_email_attachments_main.go
python -m unittest discover -s tests -v
```

Both new solvers need only the Python standard library. The Go path model
is specific to Unix path semantics and is not a substitute for full Go/gin
HTTP-server integration; the real challenge's remote endpoint was not tested.

Cumulative status: **18 unique challenge implementations**; **12 actual
published flags recovered** and **6 partial/offline/local exploit validations**.

## Phase 10: Stonks and Speak Friend, and Enter

Two newly implemented challenges, no repetition of the existing eighteen
solver files or nine earlier test modules. The new test file
`tests/test_phase10_solvers.py` contains 16 cases and reuses the existing
`data/` fixture convention and GitHub Actions test workflow.

| Challenge | Algorithm | Precisely verified outcome |
| --- | --- | --- |
| beginner/stonks | Replay an older valid signed Flask session cookie during conversion GBP -> IDR, inflating the server-side balance | **Original Flask app** run through `test_client` with temporary synthetic FLAG: threshold exceeded after three replayed conversions and synthetic marker rendered |
| crypto/speak-friend-and-enter | AES-CMAC final-block algebra to produce a fresh 2048-bit public-key modulus with the original fixed CMAC | Original public-key CMAC and size checks bypassed offline; RSA private key factorization/signing NOT completed |

### Running

```bash
python -m pip install 'Flask==3.1.1' 'pycryptodome>=3.20,<4'
python -m solvers.stonks data/stonks/stonks.py data/stonks/templates
python -m solvers.speak_friend_enter data/speak_friend_server.py
python -m unittest discover -s tests -v
```

The original challenge files are maintained under `data/stonks/` and
`data/speak_friend_server.py`; their actual hosted flags are not stored in
the solvers. Tests are restricted to original public CTF code and synthetic
local verification. The source is executed or analyzed in a local test runner;
do not import untrusted Python challenge files.

The **Stonks algorithm is validated against the real original route handlers
and Flask session implementation**, not just a simulated formula. The CMAC
cryptographic forgery is validated against the handout's original target MAC.
A full RSA signature bypass also requires the ability to compute a private
exponent for the forged 2048-bit modulus, which this implementation does not
do. The synthetic RSA signing unit test uses a separate freshly generated
key solely to confirm signature-check semantics; it is not an attack on the
real challenge's public modulus.

Cumulative: **20 distinct challenge solver implementations** with
**12 recovered challenge flags** and **8 partial or offline/local-only
exploit validations**, based on the verification scope in each phase.

## Phase 11: Scrapbooking PNG reconstruction and Dualzip ZIP structure

This phase adds two **new challenge IDs**, retaining the 20 previous solvers
and 10 earlier test modules untouched. A separate
`tests/test_phase11_solvers.py` contains 18 new tests.

| Challenge | Original-data algorithm | Validation and limits |
| --- | --- | --- |
| Scrapbooking (misc) | Recover round-robin fixed-size blocks of multiple PNG files. Infer file count from PNG signatures, reconstruct individual streams, check all PNG chunk CRCs, trim after IEND. | Original generator contract and synthetic round-trip PNGs verified. The CI additionally downloads original public warped.png and reconstructs the original PNG images. **Reading the rendered images to report the original Flag remains a separate task**. |
| Dualzip (misc) | Construct ZIP local/central headers, CRC32, EOCD, predictable SHA256 filename, and Unix symlink metadata for a synthetic two-stage split-volume archive. | Tested with Python zipfile and the original Flask application's extraction command strings. **Does not run 7z/unzip combination or recover the hosted Flag.** |

### Run locally

```bash
python -m unittest discover -s tests -v
python -m solvers.dualzip data/dualzip_app.py /tmp/ctf-dualzip-synthetic
curl -fL https://raw.githubusercontent.com/DownUnderCTF/Challenges_2025_Public/main/misc/scrapbooking/publish/warped.png -o /tmp/ductf-warped.png
python -m solvers.scrapbooking /tmp/ductf-warped.png /tmp/ductf-scrapbooking
```

The published Scrapbooking original merged binary is ~1.6 MB; the source
algorithm is preserved as `data/scrapbooking_merge_images.py`. No expected
Flag is embedded in either solver.

The Dualzip fixture intentionally limits symlink targets to names under
`/ctf-local-`, so this regression tests ZIP format behavior without loading
privileged files. Actual exploit compatibility needs a separate authorized
local environment with the challenge's unzip and 7z versions.

Cumulative: **22 distinct challenge implementations**; **12 original Flag
recoveries** and **10 partially proven or local-only reproductions**.

## Phase 12: Gomail and Certvalidated (original implementation verified)

Two additional, non-duplicate challenge IDs, retaining the 22 previous
solvers and 11 earlier Python test modules. Both implementations reuse
original upstream source inputs under `data/`, with standalone
`tests/test_phase12_solvers.py` containing 13 new Python regression tests.

| Challenge | Reconstructed algorithm | Strongest reproducible result |
| --- | --- | --- |
| web/gomail | Exploit `uint16(len(email))` truncation in custom Go claims serialization. Write full oversized email so the first eight overflow bytes masquerade as Expiry and the ninth as IsAdmin = true. | **Real original Gin login endpoint**, original server-generated HMAC-signed token and **real original /emails endpoint** successfully disclose a synthetic local admin-mail marker. Validated by separate Go integration tests (no real hosted flag). |
| crypto/certvalidated | Build legitimate CMS SignedData with fresh RSA key; substitute public root CA certificate signature bytes into generated leaf certificate's signatureValue without actually signing its TBSCertificate with root. | Original `endesive==2.18.5` verifier invoked with original published root.crt and challenge message returns **(hashok, signatureok, certok) = (True, True, True)**. No hosted flag. |

### Run

```bash
python -m pip install 'cryptography>=42,<50' 'asn1crypto>=1.5,<2' 'endesive==2.18.5'
python -m solvers.gomail data/gomail/app/session/claims.go data/gomail/app/handlers.go
python -m solvers.certvalidated data/certvalidated/certvalidated.py data/certvalidated/root.crt
python -m unittest discover -s tests -v
cd data/gomail/app && go test -v ./...
```

The Go tests are executed directly on the original challenge's Go code:
`phase12_integration_test.go` exercises actual Gin /login, signed session
decode, and /emails with a **synthetic** admin mailbox marker; a separate
negative test establishes that an ordinary guest cannot access admin mail.
The Python Gomail solver models the vulnerable original serialization to
derive the overflowing email independent of the random HMAC secret.

The CMS forged certificate is *not* legitimately issued by the root CA.
The fact that the challenge verifier returns three true results demonstrates
the certificate-validation flaw of this particular `endesive` version; it
must not be taken as a universally trusted or valid X.509 chain.

CI validation: **149/149 Python unit tests** (old 136 + new 13), and
the independent Go integration tests passed. This brings the repository
to **24 distinct challenge implementations**: 12 published Flag recoveries
and 12 offline, local-only, or partial verifications, without claiming
the hosted flags in these last two challenges.

## Phase 13: Fishy Website and Network Disk Forensics

Two **new** challenge IDs, not duplicates of the existing 24 solvers.
Prior Python regression modules remain unchanged. New tests are isolated
in `tests/test_phase13_solvers.py`.

| Challenge | New algorithm | Validation scope |
| --- | --- | --- |
| misc/fishy-website | Parse the original public PCAPNG, reassemble TCP segments, identify simulated TLS application records, statically recover published RC4 key bytes, decrypt each independent record, extract the Base64 gzip/tar transfer and read `keys.txt`. | Original `capture.pcapng` downloaded in CI, not committed or executed; real published Flag expected directly from decrypted captured data. No C2 or PowerShell execution. |
| beginner/for-golf-beginner (Network Disk Forensics) | Inspect an already acquired **local ext4 disk image** using `debugfs`, resolve the `/flag.jpg` symbolic link, and dump the target file without root/mount. | Original Go generator source is retained for contract validation. The integration test builds a synthetic ext4 filesystem with `mkfs.ext4` and an actual link inode. **NBD remote acquisition and JPEG text interpretation are not implemented**, so no real hosted Flag is claimed. |

Original upstream source fixtures are in `data/fishy_client.py` and
`data/nbd_forensics_main.go`. The original 5.8 MB public capture is
downloaded only in CI from the same public upstream repository.

```bash
python -m pip install 'dpkt>=1.9.8,<2'
python -m solvers.fishy_website /path/to/capture.pcapng data/fishy_client.py
python -m solvers.nbd_forensics /path/to/local.ext4 /tmp/flag.jpg
python -m unittest discover -s tests -v
```

The first command performs only offline packet analysis, with no callback
connections or code execution. The second command uses the installed
`debugfs` tool (e2fsprogs) to read a local filesystem image. Test input
images are generated synthetically by the test suite; the user must obtain
the original disk image separately if they want to extract a hosted flag.

The two challenge IDs bring the project to **26 unique implementations**.
Count Flag recovery separately from locally verified puzzle mechanics.
