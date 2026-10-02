# crowsi-rescue-console

Review emergency containment and recovery through a path independent of normal management.

## What you can do

- Check rescue-path readiness.
- Represent explicitly approved emergency operations.

## Current scope

An independently provisioned rescue path and recovery proof are required. The command does not grant emergency authority by itself.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
