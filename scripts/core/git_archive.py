"""Git object ids of the paths in an archive of one commit (#1573).

GitHub serves `/archive/<commit>.tar.gz` as `git archive` output under one
top-level directory, built on request: the bytes of the archive are not
promised, while what the commit holds cannot change. So a fetch is pinned by
git's own ids, a tree's for a directory and a blob's for a file, recomputed
here from the archive's members before anything in it is used. Anyone can
read the expected ids for a commit from GitHub's API (`git/trees/<commit>`).

An archive whose repository has `export-ignore` or `export-subst` attributes
differs from its commit, and so does one with submodules: their ids would not
match, and the fetch fails closed.
"""

from __future__ import annotations

import hashlib
import tarfile
from collections.abc import Collection
from pathlib import Path

# name -> (git mode, object id) for a file; name -> subtree for a directory
_Tree = dict[str, "tuple[str, str] | _Tree"]


def _object_id(kind: bytes, body: bytes) -> str:
    # SHA-1 because git's ids are SHA-1, not by choice. Matching a pinned id
    # needs a second preimage, which is not practical for SHA-1.
    header = kind + b" %d\0" % len(body)
    return hashlib.sha1(header + body, usedforsecurity=False).hexdigest()


def _tree_id(tree: _Tree) -> str:
    entries = []
    for name, node in tree.items():
        if isinstance(node, dict):
            mode, oid = "40000", _tree_id(node)
        else:
            mode, oid = node
        entries.append((name, mode, oid))
    # git orders a tree's entries by name, a directory's as if it ended in "/".
    entries.sort(key=lambda e: e[0].encode() + (b"/" if e[1] == "40000" else b""))
    body = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
        for name, mode, oid in entries
    )
    return _object_id(b"tree", body)


def object_ids(archive: Path, paths: Collection[str]) -> dict[str, str]:
    """Git's id for each of `paths` (relative to the archive's top-level
    directory) that the gzipped tar `archive` holds; a path it lacks is left
    out. Raises ValueError for an archive not under one top-level directory,
    or a member git cannot hold."""
    root: _Tree = {}
    tops: set[str] = set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            top, _, rel = member.name.partition("/")
            tops.add(top)
            if member.isdir() or not rel:
                continue  # git holds no directory of its own, only its files
            if member.issym():
                mode, body = "120000", member.linkname.encode()
            elif member.isfile():
                handle = tar.extractfile(member)
                body = handle.read() if handle else b""
                mode = "100755" if member.mode & 0o111 else "100644"
            else:
                raise ValueError(f"{member.name}: not a file, directory or symlink")
            *dirs, name = rel.split("/")
            node = root
            for part in dirs:
                child = node.setdefault(part, {})
                if not isinstance(child, dict):
                    raise ValueError(
                        f"{member.name}: a file and a directory share a path"
                    )
                node = child
            node[name] = (mode, _object_id(b"blob", body))
    if len(tops) != 1:
        raise ValueError(f"expected one top-level directory, found {len(tops)}")

    ids: dict[str, str] = {}
    for path in paths:
        found: tuple[str, str] | _Tree = root
        for part in path.split("/"):
            if not isinstance(found, dict) or part not in found:
                break
            found = found[part]
        else:
            ids[path] = _tree_id(found) if isinstance(found, dict) else found[1]
    return ids
