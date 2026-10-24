APPPATH — MILESTONE 4: ANALYST REVIEW DESK + HTML REPORTS
========================================================

WHAT THIS ADDS
--------------
- A Review Desk page for the latest scan with triage counters.
- Manual review states per finding:
    * Needs review
    * Confirmed issue
    * False positive
    * Accepted risk
    * Fix applied — retest needed
    * Resolved — manually verified
- Up to 3,000 characters of reviewer notes per finding.
- Review state, note, and timestamp persist with the local saved scan history.
- Existing finding search/filter now includes review status and review note text.
- Review status shown beside findings in tables and the finding detail modal.
- CSV and SARIF exports include analyst review metadata; JSON already exports the entire report.
- New standalone HTML assessment report export with print-friendly CSS. Open the HTML file in a browser and use Print > Save as PDF if a PDF is needed.
- Re-scanning the same APK hash preserves prior review fields when matching finding IDs remain the same.
- Ollama Cloud option and Markdown/DOMPurify AI response formatting are retained in the included files.

INSTALL IN THE EXISTING PROJECT
-------------------------------
1. Stop AppPath with Ctrl+C in the terminal running npm start.
2. Back up C:\Users\DELL\Desktop\AppPath before replacing files.
3. Extract this ZIP.
4. Copy its `src` folder into C:\Users\DELL\Desktop\AppPath and merge/replace files.
5. Keep package.json, package-lock.json, node_modules, Electron Forge config, and Vite config as they are.
6. The included src files are:
     src/main.js       (retains Ollama Cloud routing and adds HTML export)
     src/renderer.js   (adds Review Desk and per-finding review)
     src/index.css     (styles new controls)
     src/preload.js    (same narrow API as Milestone 3)
7. No new npm or Python dependency is needed by this overlay.
8. Run `npm start`.

HOW TO USE
----------
- Run an APK scan.
- Open Review desk from the sidebar.
- Click a finding, select a review outcome, add a note, and click Save review.
- Go to Reports and export HTML, CSV, JSON, or SARIF.
- Open the standalone HTML report in a browser; use Print > Save as PDF if desired.

NOTES AND LIMITATIONS
---------------------
- Review outcomes are reviewer-entered labels, not decisions made by the scanner or AI.
- “Resolved — manually verified” is an explicit manual declaration and should only be used after validating the fix outside AppPath.
- A finding not detected in a new scan is not proof that a vulnerability was fixed.
- HTML report content is escaped and the report is script-free; it includes a restrictive content security policy.
- This is a source overlay for the existing VS Code project, not a Windows installer.
- The source was checked for JavaScript syntax. Runtime behavior still needs to be verified on the user's computer.
