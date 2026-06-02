## What & why

<!--
One or two paragraphs:
- What's changing (the user-visible / wire-visible effect)
- Why (the constraint or bug driving it — not "I added X" but "the bug
  that X fixes was Y")
-->

## Wire / CT / KAT verdict

<!-- Fill in or write "n/a" — leaving blank fails review.

- Wire-format: unchanged | changed (and why a bump isn't needed) |
  changed (and which version bumps)
- CT review: unchanged | new secret-dependent path documented in
  CT-REVIEW.md | existing path tightened
- KAT vectors: unchanged | new vector frozen in KAT.md | existing
  vector explicitly re-justified
-->

## Test plan

<!-- Bulleted checklist of what you ran / observed:
- [ ] `cargo test --workspace` green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean
- [ ] manual smoke (`gnet status` / `gnet doctor` on a deploy host) — if applicable
- [ ] fuzz target re-run — if applicable
-->

## Risk / rollout

<!-- One line on blast radius:
- Local refactor → "low; reverting the PR is sufficient"
- Daemon behavior change → "fleet deploy after merge; rollback = previous binary"
- Wire change → "needs all peers on new version before old peers can leave"
-->
