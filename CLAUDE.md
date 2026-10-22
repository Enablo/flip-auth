# @enablo/flip-auth

A public npm package: Flip (Keycloak OIDC) sign-in. Read the README first.

- Keep it generic: no Enablo tenant, issuer, domain or customer details in code, tests or docs.
- `pnpm check && pnpm typecheck && pnpm test && pnpm build` before every commit.
- Behaviour changes need a test against `test/fake-flip.ts` and a `CHANGELOG.md` entry.
- Don't publish by hand or create releases unless asked; releases go through `release.yml`.
- Pin GitHub Actions to commit SHAs (with the version in a comment).
