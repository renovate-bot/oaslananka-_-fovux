# Release Process

Fovux uses a protected release model.

| Repo | Role |
|---|---|
| `oaslananka/fovux` | Public developer-facing repository |
| `oaslananka-lab/fovux` | CI/CD, security gates, and publishing |

## Release Tracks

### fovux-mcp to PyPI

- Versioned from Conventional Commits through release-please on the org repository.
- Release artifacts are built from the tagged source.
- Publishing uses PyPI trusted publishing through GitHub OIDC.

### fovux-studio to VS Marketplace and Open VSX

- Versioned independently from `fovux-studio/package.json`.
- The release workflow packages the extension with the VS Code extension CLI.
- Publishing uses `VSCE_PAT` and `OVSX_PAT` from the org repo secrets.

## Normal Release

1. Merge changes to `main` through a reviewed pull request.
2. CI, CodeQL, security scans, and review gates pass on the org repository.
3. release-please opens a release PR with version and changelog updates.
4. A maintainer reviews and merges the release PR.
5. Publish jobs run for the package that received a release.
6. SBOM, SHA256 checksum, and provenance assets are attached to the GitHub Release.

## Emergency Hotfix

```bash
git checkout main
git pull
git checkout -b hotfix/critical-fix
# make changes
git commit -m "fix(mcp): critical bug description"
git push origin hotfix/critical-fix
gh pr create --base main --title "fix(mcp): critical bug description"
```

## Version Strategy

Both packages use independent semantic versioning. The root `mcp.json`,
`fovux-mcp/server.json`, and `fovux-mcp/pyproject.toml` versions must match
after an MCP server release.
