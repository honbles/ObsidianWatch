#!/usr/bin/env bash
# ObsidianWatch — clean the git history of AI-assistant attribution and a stray work email.
#
# What it does (on a FRESH BARE CLONE, never on your working repo):
#   * re-attributes commits whose author/committer email matches OW_PATTERNS
#     (default: noreply@anthropic.com, ithorizons) to your identity
#   * strips "Co-Authored-By: Claude ...", "Claude-Session: ..." and
#     "Generated with [Claude Code]" lines from commit messages
#   * proves the CONTENT is unchanged (every branch/tag tip has the identical
#     tree before and after), prints before/after author tables
#   * pushes only if you say so (type PUSH, or pass --push)
#
# Run it from Git Bash / any bash with git, awk and sed:
#     bash rewrite_git_history.sh https://github.com/honbles/ObsidianWatch.git
#     bash rewrite_git_history.sh                  # uses "origin" of the repo you are standing in
# Options:   --push   push after verification without asking
#            --no-push   verify only (default prompts)
# Env:       OW_NAME  OW_EMAIL        identity to use (default: honbles + GitHub noreply)
#            OW_PATTERNS              comma list of email fragments to replace
#            OW_WORKDIR               where to make the clones (default: ./ow_history_work)
#
# AFTER a force-push, every other clone must be reset, not pulled:
#     git fetch origin && git checkout main && git reset --hard origin/main
# (pulling/merging the old history back would undo this). Branch protection on
# main may block the force-push: allow it temporarily in GitHub Settings -> Rules.
set -euo pipefail

PUSH=ask
URL=""
for a in "$@"; do
  case "$a" in
    --push) PUSH=yes ;;
    --no-push) PUSH=no ;;
    -h|--help) sed -n 2,28p "$0"; exit 0 ;;
    *) URL="$a" ;;
  esac
done
if [ -z "$URL" ]; then
  URL="$(git remote get-url origin 2>/dev/null || true)"
  [ -n "$URL" ] || { echo "Give the repository URL, or run this inside your repo (needs an 'origin' remote)."; exit 1; }
fi

export OW_NAME="${OW_NAME:-honbles}"
export OW_EMAIL="${OW_EMAIL:-118677497+honbles@users.noreply.github.com}"
export OW_PATTERNS="${OW_PATTERNS:-noreply@anthropic.com,ithorizons}"
WORK="${OW_WORKDIR:-./ow_history_work}"
STAMP="$(date +%Y%m%d_%H%M%S)"

echo "Repository : $URL"
echo "New identity: $OW_NAME <$OW_EMAIL>"
echo "Replacing   : any author/committer email containing: $OW_PATTERNS (and the name 'Claude')"
echo "Work dir    : $WORK"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"   # absolute: the script changes directory later
BACKUP="$WORK/backup_$STAMP.git"
REWRITE="$WORK/rewrite_$STAMP.git"

echo; echo "1/5 Cloning (bare, branches + tags only) ..."
git clone --bare --quiet "$URL" "$BACKUP"
cp -R "$BACKUP" "$REWRITE"
echo "    backup kept at: $BACKUP   (restore with: git push --force <url> 'refs/heads/*' 'refs/tags/*' from it)"

cd "$REWRITE"
authors() { git log --all --format='%an <%ae>' | sort | uniq -c | sort -rn; }
echo; echo "Authors BEFORE:"; authors
BEFORE_CLAUDE=$(git log --all --format=%B | grep -ciE '^(co-authored-by:.*(claude|anthropic)|claude-session:|.*generated with \[?claude)' || true)
echo "Commit-message lines to strip: $BEFORE_CLAUDE"

# remember every tip's tree so we can prove nothing about the code changed
git for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags | while read -r ref sha; do
  echo "$ref $(git rev-parse "$sha^{tree}" 2>/dev/null || echo none)"
done | sort > "$WORK/trees_before_$STAMP.txt"

echo; echo "2/5 Rewriting history (this can take a minute) ..."
ENVF='
swap() { # $1=email $2=name -> echoes 1 if it must be replaced
  IFS=,
  for p in $OW_PATTERNS; do case "$1" in *"$p"*) echo 1; return;; esac; done
  [ "$2" = "Claude" ] && { echo 1; return; }
  echo 0
}
if [ "$(swap "$GIT_AUTHOR_EMAIL" "$GIT_AUTHOR_NAME")" = 1 ]; then
  export GIT_AUTHOR_NAME="$OW_NAME"; export GIT_AUTHOR_EMAIL="$OW_EMAIL"
fi
if [ "$(swap "$GIT_COMMITTER_EMAIL" "$GIT_COMMITTER_NAME")" = 1 ]; then
  export GIT_COMMITTER_NAME="$OW_NAME"; export GIT_COMMITTER_EMAIL="$OW_EMAIL"
fi
'
# portable: awk drops the attribution lines and trailing blank lines
MSGF='awk '"'"'
  BEGIN{IGNORECASE=0}
  { l=tolower($0)
    if (l ~ /^co-authored-by:.*(claude|anthropic)/) next
    if (l ~ /^claude-session:/) next
    if (l ~ /generated with \[?claude/) next
    if (l ~ /^https:\/\/claude\.ai\/code\/session_/) next
    a[++n]=$0 }
  END{ while (n>0 && a[n]=="") n--; for(i=1;i<=n;i++) print a[i] }'"'"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --env-filter "$ENVF" --msg-filter "$MSGF" --tag-name-filter cat -- --all >/dev/null 2>&1 \
  || { echo "filter-branch failed; nothing was pushed. Backup is at $BACKUP"; exit 1; }
# drop filter-branch's safety refs so the old commits are not pushed or kept
git for-each-ref --format='%(refname)' refs/original | while read -r r; do git update-ref -d "$r"; done
git reflog expire --expire=now --all && git gc --prune=now --quiet

echo; echo "3/5 Verifying ..."
echo "Authors AFTER:"; authors
git for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags | while read -r ref sha; do
  echo "$ref $(git rev-parse "$sha^{tree}" 2>/dev/null || echo none)"
done | sort > "$WORK/trees_after_$STAMP.txt"
if ! diff -q "$WORK/trees_before_$STAMP.txt" "$WORK/trees_after_$STAMP.txt" >/dev/null; then
  echo "FAIL: file contents differ at a branch/tag tip. Not pushing. Compare:"
  echo "  $WORK/trees_before_$STAMP.txt  vs  trees_after_$STAMP.txt"; exit 1
fi
echo "OK: every branch/tag tip has an identical file tree to before (only authorship and messages changed)."
LEFT=$(git log --all --format='%an <%ae>%n%cn <%ce>%n%B' | grep -ciE 'noreply@anthropic|ithorizons|co-authored-by:.*(claude|anthropic)|claude-session:' || true)
if [ "$LEFT" != "0" ]; then echo "FAIL: $LEFT attribution lines/emails remain in history. Not pushing."; exit 1; fi
echo "OK: no Claude/Anthropic/ithorizons attribution remains in authors, committers or messages."
CONTENT=$(git grep -il 'ithorizons' $(git rev-list --all | head -50) -- . ':!rewrite_git_history.sh' ':!tools/rewrite_git_history.sh' 2>/dev/null | head -3 || true)
[ -n "$CONTENT" ] && echo "NOTE: the text 'ithorizons' also appears inside FILES (not just authorship): $CONTENT" || true
echo "Commits: $(git rev-list --all --count)   Branches: $(git for-each-ref refs/heads | wc -l | tr -d ' ')   Tags: $(git for-each-ref refs/tags | wc -l | tr -d ' ')"

echo; echo "4/5 Push"
if [ "$PUSH" = ask ]; then
  echo "This FORCE-PUSHES the rewritten branches and tags to: $URL"
  echo "Everyone else must reset their clones afterwards. Type PUSH to continue, anything else to stop."
  read -r ans < /dev/tty || ans=""
  [ "$ans" = "PUSH" ] && PUSH=yes || PUSH=no
fi
if [ "$PUSH" = yes ]; then
  git push --force "$URL" 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'
  echo "Pushed."
else
  echo "Not pushed. The rewritten repo is at: $REWRITE"
  echo "To push later:  cd $REWRITE && git push --force \"$URL\" 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'"
fi

echo; echo "5/5 Next steps"
cat <<'NEXT'
 * In your normal working copy:  git fetch origin && git checkout main && git reset --hard origin/main
   (do NOT pull or merge: that would bring the old history back)
 * If the push was rejected by branch protection: allow force pushes on main temporarily, re-run with --push.
 * GitHub keeps old commits reachable by SHA for a while and the Contributors list can lag; if "claude"
   still shows after a day, open a GitHub Support request to run garbage collection on the repo.
NEXT
