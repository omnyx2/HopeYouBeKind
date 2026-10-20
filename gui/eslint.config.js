// Flat ESLint config for the GUI frontend (vanilla ES modules, no framework).
// Scope is deliberately small: catch the bug classes a browser-only codebase ships
// silently — a typo'd identifier (`no-undef`) and dead code (`no-unused-vars`).
// CI runs `npm run lint`; a Vite build does NOT type- or lint-check anything.
import globals from "globals";

export default [
  {
    files: ["src/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser },
    },
    rules: {
      "no-undef": "error",
      // `catch (e)` with an unused binding is idiomatic here; unused args are
      // common in callbacks — only flag genuinely dead variables/functions.
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
    },
  },
];
