#!/bin/sh
# Print the digest goreleaser recorded for one image reference in dist/artifacts.json.
# Used by release.yml (attestation subject) and checked against snapshots by image-smoke.sh,
# so a goreleaser schema change fails CI instead of the first tagged release.
set -eu
ref=${1:?usage: image-digest.sh <image:tag>}
digest=$(jq -r --arg ref "$ref" '[.[] | select(.type == "Docker Image" and .name == $ref) | .extra.Digest] | unique | .[]' dist/artifacts.json)
[ -n "$digest" ] || { echo "image-digest: no digest for $ref in dist/artifacts.json" >&2; exit 1; }
[ "$(printf '%s\n' "$digest" | wc -l | tr -d ' ')" = 1 ] \
  || { echo "image-digest: $ref has more than one digest: $digest" >&2; exit 1; }
printf '%s' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' \
  || { echo "image-digest: malformed digest for $ref: $digest" >&2; exit 1; }
printf '%s\n' "$digest"
