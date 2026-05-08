# Release Process

Releases are automated from merges to `main` in `oaslananka-lab/fovux`.

1. A maintainer merges a normal pull request with Conventional Commits.
2. `release-please` evaluates commit history and updates the package version files and changelog in a release pull request.
3. A maintainer reviews and merges the release pull request.
4. The release workflow creates the GitHub Release from release-please outputs.
5. Publish jobs build artifacts on GitHub-hosted runners, generate SBOMs and SHA256 checksums, attest provenance, attach assets, publish to registries, and verify the release.

Version numbers are never supplied manually. Release tags are component-specific for the monorepo packages.
