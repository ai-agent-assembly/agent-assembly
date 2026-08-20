#!/usr/bin/env sh
# Render a policy template into a concrete policy for one run.
#
# Usage: render.sh <scratch_root> <out_path> [template_name]
#
# template_name defaults to confined-arm.yaml.tmpl (AAASM-5713), so every
# existing caller keeps rendering the same two-arm policy unchanged. Pass
# three-arm.yaml.tmpl (AAASM-5805) to render the policy the native arm can
# actually run under — see that template for why it differs.
#
# The scratch root must be an absolute, already-created directory — sandlock's
# filesystem grant is a path, not a pattern with shell-style expansion, so a
# relative or not-yet-existing path would silently grant the wrong thing (or
# nothing) rather than fail loudly.
set -eu

scratch_root="${1:?usage: render.sh <scratch_root> <out_path> [template_name]}"
out_path="${2:?usage: render.sh <scratch_root> <out_path> [template_name]}"
template_name="${3:-confined-arm.yaml.tmpl}"

case "$scratch_root" in
    /*) ;;
    *)
        echo "render.sh: scratch_root must be absolute, got: $scratch_root" >&2
        exit 1
        ;;
esac
if [ ! -d "$scratch_root" ]; then
    echo "render.sh: scratch_root does not exist: $scratch_root" >&2
    exit 1
fi

template_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
sed "s|__SCRATCH_ROOT__|${scratch_root}|g" "$template_dir/$template_name" > "$out_path"
