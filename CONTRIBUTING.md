# Contributing to tess

Thanks for your interest. This project is built in phases — the roadmap is in
[`PLAN.md`](./PLAN.md), and **the actual working rules (commits, branching, the review loop,
worktrees, security invariants) live in [`AGENTS.md`](./AGENTS.md)**. Read AGENTS.md before
opening a PR; it is the source of truth for how we work.

## How to propose a change

- **Non-trivial change?** File an issue first so the design can be discussed, then open a PR that
  references it (`Closes #N`).
- **Small fix against an existing issue?** Open a PR directly, referencing the issue.
- Every PR references exactly one issue. PRs with no linked issue are "side-quests" — allowed but
  must be labeled `chore: side-quest` and kept small (see AGENTS.md).

## Get to a passing test

```sh
rustup toolchain install stable           # toolchain is pinned in rust-toolchain.toml
cargo build --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                    # uses swtpm + the libfprint virtual driver
cargo audit && cargo deny check           # supply-chain gates
```

Tests never touch real hardware or real secrets — TPM tests use **swtpm**, fingerprint tests use the
libfprint **virtual driver** + `python-dbusmock`. Never run the project against your own
TPM/keyring/PAM.

## AI agents

AI agents are welcome and contribute like any other contributor — follow [`AGENTS.md`](./AGENTS.md)
exactly, the same as a human would.
