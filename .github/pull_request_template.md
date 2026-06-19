<!--
Keep PRs scoped to one concern. Link the issue this resolves.
Run `task all` before pushing.
-->

## Summary

What this changes and why.

## Related issue

Closes #

## Checklist

- [ ] Linked to an issue
- [ ] `task all` passes (build + lint + vulncheck + test)
- [ ] Tests added/updated for behavioral changes
- [ ] No new uid/gid in merged config, and no daemon importing `auth`/`msgstore`
      directly (the depguard boundaries)
- [ ] Docs updated if behavior or config changed
