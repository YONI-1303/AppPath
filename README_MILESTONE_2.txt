APPPATH MILESTONE 2 — FINDING DETAILS, CANDIDATE PATHS, CSV EXPORT, PERSISTENT HISTORY

IMPORTANT: This is an overlay for your existing Electron project. Do not create a new app.

BEFORE REPLACING FILES
Make a quick backup by copying your current AppPath folder or at least the src and backend folders somewhere safe.

INSTALL
1. Close AppPath. In the terminal running it, press Ctrl+C.
2. Extract this ZIP.
3. Copy the contents of the extracted folder into C:\Users\DELL\Desktop\AppPath.
4. Allow matching files to be replaced. This overlay replaces:
   - src\main.js
   - src\preload.js
   - src\renderer.js
   - src\index.css
   - backend\analyze_apk.py
5. Do NOT replace package.json, package-lock.json, forge.config.mjs, node_modules, or other Vite/Electron configuration files.
6. No new Python package is required; keep using the installed Androguard dependency.
7. Start the app from the existing project folder with: npm start

NEW FEATURES
- Click a finding title to inspect its description, exact evidence, recommendation, and related candidate correlations.
- The graph now links to individual findings and shows candidate relationships.
- Attack Paths contains a few conservative evidence-correlation rules, only where their trigger evidence exists.
- Reports support JSON and CSV export.
- The last 25 unique scan reports are saved locally in Electron's application user-data folder and restored on startup.
- Reports lets you reopen an earlier scan.

SAFETY / LIMITATIONS
- APKs are parsed statically; they are never installed or launched.
- Permission and string matches may be false positives and are not proof of maliciousness or exploitability.
- Candidate relationships are hypotheses, not verified exploit chains. They do not establish runtime reachability.
- Local AI remediation, decompiled-code mapping, dynamic analysis, and automatic patching are not included in this milestone.
- Scan reports may contain app metadata or indicators; keep exported files private.
