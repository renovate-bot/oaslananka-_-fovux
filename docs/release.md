# Release Process

Fovux uses a dual-repo release model.

| Repo | Role |
|---|---|
| `oaslananka/fovux` | Canonical public repository and developer-facing source of truth |
| `oaslananka-lab/fovux` | CI/CD runner mirror for release gates and publishing |

## Release Tracks

### fovux-mcp to PyPI

- Versioned from Conventional Commits through release-please on the org mirror.
- Release artifacts are built from the tagged source.
- Publishing uses PyPI trusted publishing through GitHub OIDC.

### fovux-studio to VS Marketplace and Open VSX

- Versioned independently from `fovux-studio/package.json`.
- The release workflow packages the extension with `vsce`.
- Publishing uses `VSCE_PAT` and `OVSX_PAT` from the org repo secrets.

## Normal Release

1. Merge changes to `main` in `oaslananka/fovux`.
2. The org mirror syncs `main` into `oaslananka-lab/fovux`.
3. CI, CodeQL, security scans, and review gates pass on the org mirror.
4. release-please opens a release PR with version and changelog updates.
5. A maintainer reviews and merges the release PR.
6. Publish jobs run for the package that received a release.

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
