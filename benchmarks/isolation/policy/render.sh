#!/usr/bin/env sh
# Render confined-arm.yaml.tmpl into a concrete policy for one run.
#
# Usage: render.sh <scratch_root> <out_path>
#
# The scratch root must be an absolute, already-created directory — sandlock's
# filesystem grant is a path, not a pattern with shell-style expansion, so a
# relative or not-yet-existing path would silently grant the wrong thing (or
# nothing) rather than fail loudly.
set -eu

scratch_root="${1:?usage: render.sh <scratch_root> <out_path>}"
out_path="${2:?usage: render.sh <scratch_root> <out_path>}"

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
sed "s|__SCRATCH_ROOT__|${scratch_root}|g" "$template_dir/confined-arm.yaml.tmpl" > "$out_path"
