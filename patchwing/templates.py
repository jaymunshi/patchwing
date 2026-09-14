"""Pod template library — constants + dataclass.

Templates are cached provision outputs: a bare pod that's been run through
the standard provision tools (exec_in_pod, write_file_to_pod,
install_package, http_probe) to install a common stack, with the ordered
tool calls captured as a `recipe_json` on the row and the resulting
container committed to a `patchwing-template:<name>` image.

The persistence lives in the `pod_templates` table (see store.py). This
module holds the small public surface — constants + a dataclass — so
future modules (template_builder, and Pass 4's reproduce integration)
can import from one place.

Storage design: templates are GLOBAL, not per-finding. That is why they
live in their own table with no finding_id (the artifacts table's
finding_id NOT NULL cascade rule would either need a sentinel finding
or the cascade guarantee dropped — both wrong).
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Optional
import sqlite3


# --- constants ------------------------------------------------------------

TEMPLATE_TAG_PREFIX = "patchwing-template"
"""Container image tag prefix — full tag is
   TEMPLATE_TAG_PREFIX + ':' + name."""


TEMPLATE_RECIPE_KIND = "template_recipe"
"""Reserved artifact-kind name. Templates themselves live in the
`pod_templates` table, but when a FINDING uses a template at reproduce
time (Pass 4+), the finding gets a `template_recipe` artifact recording
which template + which image_digest was attached. Reserving the name now
so downstream code can import from one place."""


BUILDER_VERSION_CURRENT = "template_builder-1"
"""Bumped on any change to the recipe capture format. Templates with an
older builder_version can still be READ, but a rebuild is required
before their recipe can be REPLAYED by the current builder."""


def image_tag_for(name: str) -> str:
    """`patchwing-template:tomcat-jdk8` from `tomcat-jdk8`."""
    if not name or ":" in name or "/" in name or " " in name:
        raise ValueError(
            f"template name {name!r} must be non-empty and cannot contain "
            f"':', '/', or whitespace — it becomes part of a Docker tag")
    return f"{TEMPLATE_TAG_PREFIX}:{name}"


# --- dataclass ------------------------------------------------------------

@dataclass
class PodTemplate:
    """One row from the pod_templates table. Fields mirror the schema
    exactly; the `from_row` classmethod copes with future schema
    additions the same way Finding.from_row does."""
    id: str
    name: str
    description: str
    base_image: str
    image_tag: str
    recipe_json: str
    recipe_turn_count: int
    verification_cmd: str
    verification_expect: str
    builder_version: str
    created_at: float
    image_size_bytes: Optional[int] = None
    image_digest: Optional[str] = None
    cve_class_hint: Optional[str] = None
    last_verified_at: Optional[float] = None
    last_verified_ok: Optional[int] = None
    last_verified_note: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "PodTemplate":
        cols = set(row.keys())
        known = {f.name for f in fields(cls)}
        return cls(**{k: row[k] for k in cols if k in known})
