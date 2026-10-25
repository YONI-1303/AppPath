# AppPath

## Advancing Mobile Security Frameworks with Graph Intelligence and Local AI Remediation

**AppPath** is a desktop prototype for static security analysis of Android application packages (APK files). It helps reviewers inspect application metadata and security-relevant indicators, understand findings, explore possible relationships between findings, and prepare reports for further review.

> **Project status:** Working prototype. Static-analysis indicators are not proof of exploitability or malicious behavior. Findings and suggested attack paths require human validation.

## Project Presentation

**Five-minute demonstration:** [Watch the AppPath presentation on YouTube](https://youtu.be/b1873esCeIA)

**GitHub repository:** [YONI-1303/AppPath](https://github.com/YONI-1303/AppPath)

## Main Features

- **APK Static Analysis:** Select an APK and inspect package information, manifest settings, declared permissions, components, and selected security indicators.
- **Findings Dashboard:** Review findings and their severity, evidence, and remediation guidance.
- **Security Graph and Candidate Attack Paths:** Explore possible relationships between findings. Candidate paths are hypotheses for investigation, not confirmed exploits.
- **Review Desk:** Record review outcomes and notes for findings, where enabled in the current build.
- **Reports:** Export analysis results in supported formats, including JSON, CSV, SARIF, and HTML.
- **AI-Assisted Remediation:** Optionally use Ollama Cloud to explain a selected finding and suggest remediation. AI recommendations must be reviewed before use.
- **MASVS-Aligned Categorization:** Organize selected findings under relevant OWASP Mobile Application Security Verification Standard (MASVS) topics. This is not a complete MASVS assessment or certification.

## Technology Stack

- **Electron Forge and Vite:** Windows desktop application shell and development tooling.
- **HTML, CSS, and JavaScript:** User interface and application interactions.
- **Python and Androguard:** APK parsing and static-analysis support.
- **Ollama:** Optional AI assistance for selected finding details.

## Run Locally on Windows

### Requirements

- Windows 10 or Windows 11
- Node.js and npm
- Python
- Internet access to install dependencies
- Ollama sign-in and an internet connection for Ollama Cloud features

### Installation and Launch

Open a terminal in the AppPath project directory and run:

```powershell
npm install
python -m pip install -r requirements.txt
npm start
```

If the project is already set up on your computer, you may not need to reinstall dependencies every time. Run `npm start` to launch the development version.

### Optional: Ollama Cloud AI Assistance

1. Install Ollama from [ollama.com/download](https://ollama.com/download).
2. Sign in using `ollama signin`.
3. Confirm the desired cloud model is available in Ollama, then select it in AppPath's AI Fix interface if the feature is configured in your build.

Ollama Cloud requires internet access. When using cloud AI, send only the finding details or code snippets necessary for the explanation. Do not share private keys, passwords, tokens, or confidential source code.

## Typical Workflow

1. Open AppPath.
2. Select an APK that you own or are authorized to assess.
3. Run the static analysis.
4. Review the finding evidence and remediation suggestions.
5. Explore graph relationships and candidate attack paths where available.
6. Record review decisions and export a report where those features are enabled.
7. Validate important findings manually or with additional testing before deciding that a vulnerability is confirmed or resolved.

## Important Limitations

- AppPath is a prototype and does not replace a professional mobile application security assessment.
- Static analysis cannot determine every runtime behavior, exploitability condition, authentication issue, or backend vulnerability.
- Exported components, permissions, strings, and configuration patterns may be indicators rather than confirmed vulnerabilities.
- Graph connections and attack paths are candidates for investigation unless independently validated.
- AI-generated explanations and remediation advice may be incorrect or incomplete and must be reviewed by a developer.
- Automatic source-code repair and full remediation validation are not guaranteed features of this prototype.
- MASVS topic mapping is partial and must not be presented as OWASP certification or full compliance.

## Team Information

The official project-review roster lists the following team members:

| Team Member | CTC ID |
|---|---|
| Matiyas Masho | CTC-4771-26 |
| Yonathan Mitiku | CTC-1216-26 |
| Naod Tsega | CTC-2465-26 |
| Wamisha Lemma | CTC-7350-26 |
| Yanet Dagne | CTC-3160-26 |
| Yanet Belete | CTC-627-26 |

## Acknowledgment

Prepared as a graduation project for review by the INSA Cyber Talent Center mentors.