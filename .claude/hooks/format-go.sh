#!/usr/bin/env bash
# PostToolUse hook: format the single Go file Claude just edited. Never blocks.
f=$(jq -r '.tool_input.file_path // empty')
[[ "$f" == *.go && -f "$f" ]] || exit 0
cd "$CLAUDE_PROJECT_DIR" || exit 0
mise exec -- gofmt -s -w "$f" && mise exec -- goimports -w "$f"
exit 0
