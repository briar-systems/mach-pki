# mach-pki

## Build

```sh
mach dep pull .
mach build .
mach run .
mach test . --timeout 5m
```

## Workflow

`dev` is the default branch. Work branches from it as `feat/<issue>` or
`fix/<issue>` and merges back through a pull request. `main` only takes release
merges from `dev`. A `hotfix/<issue>` branches from `main` and merges into both.

Both branches require a pull request and a passing `gate` check. Neither can be
deleted or force-pushed, and pull requests merge with a merge commit. Repository
admins can bypass these rules to cut a release. Once a `v*` tag is pushed, only
an admin can move or delete it.

Commits follow [Conventional Commits](https://www.conventionalcommits.org), with
the issue number as the scope: `fix(#12): reject a negative length`.

Issues are labeled on independent axes:

| axis | labels |
| --- | --- |
| semver magnitude | `patch`, `minor`, `major` |
| kind of work | `feature`, `fix`, `removal`, `chore`, `performance` |
| where, omitted for core code | `testing`, `tooling`, `doc` |
| severity and state | `critical`, `blocked`, `parked`, `security` |
| discussion | `discussion` |

## CI

`.github/workflows/ci.yml` runs on pull requests, on Linux. It checks formatting,
builds every artifact for every target in `mach.toml`, and runs the unit tests of
the targets the runner can execute. Targets no runner executes, such as riscv, are
built, never tested. Nothing runs under emulation.

To test on other hosts before merging, such as a darwin-specific change, dispatch
it on the branch: `gh workflow run CI --ref <branch> -f runners='["macos-15"]'`.
A project whose primary host is not Linux changes the default runner list in the
`test` job's matrix.

CI checks that the project builds and its unit tests pass. Integration, load or
demo suites are not CI jobs. Run them locally.

`gate` is the check the branch rules require. It fails if any job it needs
failed or was cancelled.

The compiler version is `MACH_VERSION`, an exact release, in `ci.yml` and
`cd.yml`. Change it together with the `mach` range in `mach.toml`.

## Releases

1. Set `version` in `mach.toml` and merge that into `dev`.
2. Merge `dev` into `main`.
3. Tag `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

`.github/workflows/cd.yml` checks that the tag matches the manifest version,
runs CI in the release profile on every host the project ships to (the
`runners` list in `cd.yml`, trimmed to the targets it declares), cross-builds
every artifact for every target in release, and publishes a GitHub release. Each artifact is packaged per target
(`.zip` for Windows, `.tar.gz` elsewhere) with `SHA256SUMS`. Names and paths come
from `mach build --plan`, so a new target or artifact needs no workflow change.
The notes are the version's `CHANGELOG.md` section, or generated from merged pull
requests when there is none. A tag with a prerelease part, such as `v1.0.0-rc.1`,
is published as a prerelease.

## License

MIT. See [LICENSE](LICENSE).
