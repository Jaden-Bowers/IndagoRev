# Default branch: master

The repository uses `master` as its default development branch. The former remote
`main` was consolidated into `master`, including the newer local harness and
investigation fixes, before removal. Feature branches are unaffected.

For an existing clone, first commit or stash any uncommitted work, then:

```sh
git fetch origin --prune
git switch master
git branch --set-upstream-to=origin/master master
git pull --ff-only
git remote set-head origin -a
```

If no local `master` exists, use `git switch --track origin/master` instead of
`git switch master`. If the fast-forward pull fails, preserve and review the local
commits rather than resetting the branch.

Keep a local `main` if it contains unpublished work. Check for unique commits with
`git log origin/master..main`; merge or cherry-pick any needed work before deleting
it. Use `git branch -d main`, not forced deletion, once the work is integrated.

Target new pull requests at `master`. Update any personal automation that explicitly
checks out `main`; upstream dependency branches do not need to be renamed.
