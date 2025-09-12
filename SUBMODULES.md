# Submodule Dependencies

This file documents the exact commit hashes for all Git submodules used in this project.

## cpp/secp256k1

- **Repository**: https://github.com/bitcoin-core/secp256k1.git
- **Pinned Commit**: `a660a4976efe880bae7982ee410b9e0dc59ac983`
- **Version**: v0.7.0
- **Date Pinned**: 2025-09-12
- **Reason**: Latest stable commit with security fixes
- **⚠️ WARNING**: Do not update without security review - affects cryptographic operations

## Updating Submodules

To update a submodule:

1. Navigate to the submodule directory: `cd cpp/secp256k1`
2. Fetch latest changes: `git fetch origin`
3. Check out desired commit: `git checkout <new-commit-hash>`
4. Return to root: `cd ../..`
5. Update this documentation file
6. Commit the changes: `git add . && git commit -m "Update secp256k1 to <new-commit-hash>"`

## Verification

To verify current pinned commits:

```bash
git submodule status
```
