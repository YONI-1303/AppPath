APPPATH — AI RESPONSE FORMATTING FIX

What it fixes
- AI responses are rendered as Markdown instead of placing the entire answer in a plain <pre> block.
- Headings, paragraphs, lists, inline code, and fenced XML/Java/Kotlin snippets render with separate styling.
- AI output is sanitized with DOMPurify before it is inserted into the UI.

Install
1. Stop AppPath in its terminal with Ctrl+C.
2. Back up C:\Users\DELL\Desktop\AppPath first.
3. Extract this ZIP.
4. Copy the included src folder into C:\Users\DELL\Desktop\AppPath and merge it.
5. Replace src\renderer.js and src\index.css when asked.
6. In a VS Code terminal opened at the AppPath project root, run:

   npm install marked dompurify
   npm start

Do NOT replace package.json, package-lock.json, main.js, preload.js, Electron/Vite configuration, backend, or node_modules manually. The npm install command will update package.json and package-lock.json normally.

Safety note
AI responses are untrusted content. This patch uses DOMPurify to sanitize generated HTML.
