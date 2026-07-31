# Contributing to schloss-server-kit

Thanks for considering a contribution. This package is consumed by every
backend service on the Schloss Platform, so a breaking change here has a
wide blast radius — please keep changes focused and in scope.

## Before opening a PR

- Run `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build` — CI runs all
  four and will block merges that don't pass.
- Add or update tests for any behavior change.
- Keep commits focused; one logical change per PR is easier to review than
  several bundled together.
- Write commit messages that explain *why*, not just *what* — the diff
  already shows what changed.
- If you're changing a function's config shape or return type, call that
  out explicitly in the PR description — consuming repos will need a
  matching update.

## Opening a PR

- Branch from `main`.
- Reference the issue you're addressing if one exists (`Closes #123`).

## Reporting bugs / security issues

Open a regular issue for bugs. For anything that looks like a security
vulnerability, please use GitHub's private "Report a vulnerability" flow
under this repo's Security tab instead of a public issue.
