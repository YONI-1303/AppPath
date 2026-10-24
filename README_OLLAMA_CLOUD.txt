APPPATH — OLLAMA CLOUD CONNECTION OVERLAY
========================================

This overlay updates the AI Fix page in an existing AppPath Milestone 3 project.
It does not replace Electron configuration or add npm packages.

INSTALL
-------
1. Stop AppPath with Ctrl+C in the terminal running npm start.
2. Back up your current AppPath folder.
3. Extract this ZIP.
4. Copy the `src` folder into C:\Users\DELL\Desktop\AppPath and merge/replace matching files.
5. Keep package.json, package-lock.json, forge.config.mjs, Vite config files, preload.js, backend, and node_modules unchanged.
6. Run `npm start`.

USE
---
- The AI Fix page now offers `gemma4:cloud` as a model choice in addition to models exposed by the local Ollama service.
- This uses AppPath's existing localhost Ollama endpoint. Since you have already signed in with `ollama signin`, the local Ollama service can route cloud-model calls. Internet must be available.
- Cloud requests send the selected finding metadata, app package/version, and any optional code snippet to Ollama Cloud; AppPath does not send the whole APK. Remove credentials, tokens, or sensitive snippets first.
- The direct Ollama hosted API requires an API key, but this overlay deliberately does not embed or request one: it uses the signed-in local Ollama service instead.
- If the cloud call fails, open a fresh Command Prompt and confirm `ollama run gemma4:cloud` still works, then use AI Fix > Refresh Ollama models.

LIMITATIONS
-----------
AI suggestions are advisory, not proof a finding is exploitable or that a fix works. Review recommendations, apply changes in the original source project, test them, rebuild, and re-scan.
