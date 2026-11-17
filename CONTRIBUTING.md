# Contributing

Issues labelled `good first issue` are a place to start.

## Build and test

CI uses Node 20 and runs:

```sh
npm ci
npm run typecheck
npm test
npm run build
```

The package scripts run `tsc --noEmit`, `vitest run`, and
`tsc -p tsconfig.build.json`, respectively. The pack-install workflow also
builds, packs, installs and smoke-runs the package on Node 18, 20 and 22, on
Linux, macOS and Windows.

## Add a rule

1. Explain why the SQL pattern leaves data open. Add the rule ID to `RuleId`
   in `src/types.ts` and its metadata to `RULES` in `src/rules.ts`.
2. Implement the check in `src/analyze.ts`. `analyzeSources` parses the SQL,
   `Analyzer.apply` tracks statements, and `Analyzer.findings` produces findings.
   Add state or helpers where the check needs them.
3. Add a failing SQL example and a passing SQL example under `tests/fixtures/`,
   like `r8-bad/001.sql` and `r8-good/001.sql`. In `tests/rules.test.ts`, use
   `scan` to assert that the bad example reports the rule and the good example
   does not. Add tests for migration ordering where relevant.
4. Update the rule table in `README.md` and the top (unreleased) version
   section of `CHANGELOG.md`.
5. Run the CI commands above.

Write commit messages in plain English, with no trailers.
