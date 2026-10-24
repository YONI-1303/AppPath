APPPATH — MILESTONE 3 MEGA UPGRADE
=================================

This is an overlay for your existing AppPath Electron Forge + Vite project.
It is NOT a new project, and it does not include node_modules.

BEFORE YOU REPLACE FILES
------------------------
1. Close AppPath. In the terminal running `npm start`, press Ctrl+C.
2. As a safety backup, copy your existing `C:\Users\DELL\Desktop\AppPath` folder to
   `AppPath-backup` (or another folder with enough free space).
3. Extract this ZIP.
4. Copy the ZIP contents into your existing `C:\Users\DELL\Desktop\AppPath` folder.
5. Merge `src` and `backend`, and replace the matching files when asked.
6. Keep your existing `package.json`, `package-lock.json`, `forge.config.mjs`,
   `vite.*.config.mjs`, and `node_modules` unchanged.

INSTALL / RUN
-------------
Open VS Code with the existing AppPath folder. In Terminal > New Terminal run:

  python -m pip install -r requirements.txt
  npm start

The Python dependency remains pinned to Androguard 4.1.4. No Supabase, Docker,
cloud database, or additional npm package is needed for this overlay.

FEATURES IN THIS MILESTONE
-------------------------
- Searchable and filterable scan findings (text, severity, category).
- Interactive APK -> category -> finding evidence graph; nodes open finding details.
- Evidence-linked candidate attack-path correlations with explicit limitations.
- Broad OWASP MASVS topic mapping for navigation. This is NOT a complete test suite,
  verified control result, or MASVS compliance certification.
- Additional static string / class indicators for some legacy crypto identifiers,
  digest identifiers, and general-purpose random generators. These are heuristic signals,
  not proof that a method is called or sensitive data is affected.
- CSV report export with spreadsheet-formula injection neutralization.
- JSON and SARIF 2.1.0 report exports.
- Local report history (up to 25 reports) retained under Electron's user-data directory.
- Optional local AI remediation through Ollama on 127.0.0.1:11434. AppPath sends only
  selected finding metadata and an optional snippet, not the APK. There is no cloud fallback.
- Optional JADX decompilation / keyword-based code context mapping.
- Before/after report comparison to review indicators absent, new, or persistent after a
  rebuilt APK is scanned.
- Improved Electron navigation / IPC checks and denial of web permission requests.
- Bounded JADX source file enumeration / reading to reduce repeated I/O and memory use.

OPTIONAL LOCAL AI (NOT REQUIRED TO RUN APPPATH)
-----------------------------------------------
1. Install Ollama for Windows from https://ollama.com/download
2. In Command Prompt run:

     ollama pull qwen2.5-coder:1.5b

3. Open AppPath, visit AI Fix, and click Refresh local models.

A small local model can still run slowly on an 8 GB RAM computer. If Ollama is not
installed, the rest of AppPath continues working.

OPTIONAL JADX SOURCE MAPPING (NOT REQUIRED TO SCAN)
--------------------------------------------------
1. Download JADX from the official releases page:
   https://github.com/skylot/jadx/releases
2. Extract the release archive. On Windows, select `bin\jadx.bat` when prompted.
3. In AppPath open Code mapping > Locate JADX.
4. Select the APK again on Analyze APK if AppPath asks, then run Decompile & map.

JADX output is approximate decompiled code. AppPath's mapping searches for selected terms
in decompiled files and shows contextual lines; it does not prove taint flow, reachability,
or vulnerability exploitability. Do not run unknown scripts or executables masquerading
as JADX. Only analyze APKs you own or are authorized to inspect.

IMPORTANT LIMITATIONS
---------------------
- Static analysis only: AppPath never installs or launches the APK.
- The scanner covers a limited subset of manifest and DEX-string indicators. It is not a
  substitute for a full mobile security assessment, dynamic testing, or expert review.
- Permissions, HTTP strings, crypto tokens, secret-like strings, and exported components
  may be false positives or benign. Review the evidence and surrounding code.
- Candidate paths are conservative correlations, NOT confirmed exploit chains.
- MASVS tags are broad topic mapping; “no supported indicator found” is NOT a pass.
- Local AI suggestions are advisory and are never treated as tested fixes.
- Validation compares indicators between two reports. “No longer detected” does NOT prove
  a defect is fixed; rebuild, test, and review the source code.
- JADX and Ollama are optional external local tools; neither is bundled in this ZIP.
- Packaging an installer / portable EXE is not included. This overlay is for running the
  project from VS Code using `npm start`.

OFFICIAL REFERENCES
-------------------
Electron security guidance:
https://www.electronjs.org/docs/latest/tutorial/security

OWASP Mobile Application Security Verification Standard (MASVS):
https://mas.owasp.org/MASVS/

Ollama local API docs:
https://github.com/ollama/ollama/blob/main/docs/api.md

Androguard docs:
https://androguard.readthedocs.io/en/latest/

AppPath is a student prototype. Keep the analysis scope and limitations visible in reports
and presentations; do not claim a vulnerability or remediation has been proven unless it
has been independently verified.
