"""A tiny note store. Contains a real path-traversal vulnerability (CWE-22)."""

import os


class NoteStore:
    def __init__(self, base_dir):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def write_note(self, name, text):
        path = os.path.join(self.base_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def read_note(self, name):
        # The caller-supplied name is joined straight onto the base directory
        # with no containment check.
        path = os.path.join(self.base_dir, name)
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    def list_notes(self):
        out = []
        for root, _dirs, files in os.walk(self.base_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), self.base_dir)
                out.append(rel.replace(os.sep, "/"))
        return sorted(out)
