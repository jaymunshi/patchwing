"""Build ONE template by name. Runs on the VM; talks to the local podman
via patchwing.template_builder.

Usage:
    python3 scripts/build_one_template.py tomcat-jdk8

Prints the BuildResult on success (image tag, size, digest, turn count,
verification tail). Prints the BuildFailed with stage + stdout_tail on
failure. Exit code 0 on success, 1 on failure — so a wrapping script
can gate on it."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Make patchwing importable when run from repo root
sys.path.insert(0, "/home/ubuntu")

from patchwing import template_builder as tb            # noqa: E402
from patchwing import template_recipes                  # noqa: E402
from patchwing.config import SandboxConfig              # noqa: E402
from patchwing.store import Store                       # noqa: E402


# Map template name → (recipe_fn, description, base_image, cve_class_hint)
#
# Two flavors:
#   *-recipe   — machine-derived from ubuntu:22.04 via provision tools;
#                the ideal case, requires healthy outbound network for
#                apt-get to complete in reasonable time
#   *-official — verify-only over a ported docker.io Hub image; recipe
#                body is empty, base_image field records provenance
TEMPLATES = {
    "tomcat-jdk8": (
        template_recipes.tomcat_jdk8,
        "JDK 8 (Temurin) + Maven + Tomcat 9 on Ubuntu 22.04",
        "ubuntu:22.04",
        "java-servlet-web-rce",
    ),
    "apache-httpd-24": (
        template_recipes.apache_httpd_24,
        "Apache HTTPD 2.4 + PHP 7.4 (ondrej PPA) on Ubuntu 22.04",
        "ubuntu:22.04",
        "php-web-rce",
    ),
    "nodejs-18": (
        template_recipes.nodejs_18,
        "Node.js 18 LTS + npm (Nodesource) on Ubuntu 22.04",
        "ubuntu:22.04",
        "nodejs-rce",
    ),
    # Verify-only over ported Docker Hub images. base_image is the local
    # image tag loaded via `podman load -i <tarball>` after the tarball
    # was assembled on the laptop (fast outbound) via
    # scripts/pull_docker_image.py.
    "tomcat-jdk8-official": (
        template_recipes.tomcat_jdk8_from_official,
        "Tomcat 9 + JDK 8 Temurin (imported from "
        "docker.io/library/tomcat:9.0-jdk8-temurin)",
        "localhost/tomcat:9.0-jdk8-temurin",
        "java-servlet-web-rce",
    ),
    "apache-httpd-24-official": (
        template_recipes.apache_httpd_24_from_official,
        "Apache HTTPD 2.4 + PHP 7.4 (imported from "
        "docker.io/library/php:7.4-apache)",
        "localhost/php:7.4-apache",
        "php-web-rce",
    ),
    "nodejs-18-official": (
        template_recipes.nodejs_18_from_official,
        "Node.js 18 LTS + npm (imported from "
        "docker.io/library/node:18-bullseye)",
        "localhost/node:18-bullseye",
        "nodejs-rce",
    ),
}


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <template-name>", file=sys.stderr)
        print(f"available: {', '.join(TEMPLATES)}", file=sys.stderr)
        return 2
    name = argv[1]
    if name not in TEMPLATES:
        print(f"unknown template {name!r}; available: {list(TEMPLATES)}",
              file=sys.stderr)
        return 2

    recipe_fn, description, base_image, hint = TEMPLATES[name]
    store = Store("/home/ubuntu/patchwing.db")
    sbx_cfg = SandboxConfig(
        backend="podman",
        image="",
        network="bridge",   # templates need network for apt-get, wget, PPAs
        cpus=2.0,
        memory="4g",
        timeout_s=1800)

    print(f"[{time.strftime('%H:%M:%S')}] building template {name!r}", flush=True)
    print(f"  base_image      = {base_image}", flush=True)
    print(f"  description     = {description}", flush=True)
    print(f"  cve_class_hint  = {hint}", flush=True)
    print(f"", flush=True)

    started = time.time()
    try:
        result = tb.build_template(
            store=store,
            sandbox_config=sbx_cfg,
            name=name,
            description=description,
            base_image=base_image,
            cve_class_hint=hint,
            recipe_fn=recipe_fn)
    except tb.BuildFailed as e:
        elapsed = int(time.time() - started)
        print(f"[{time.strftime('%H:%M:%S')}] BUILD FAILED after {elapsed}s",
              flush=True)
        print(f"  stage   : {e.stage}", flush=True)
        print(f"  message : {e.message}", flush=True)
        print(f"  --- stdout_tail (last 4KB) ---", flush=True)
        print(e.stdout_tail or "(empty)", flush=True)
        return 1

    elapsed = int(time.time() - started)
    t = result.template
    tail = result.verification_stdout or ""
    tail_show = tail if len(tail) <= 2000 else (
        tail[:1000] + f"\n...\n[stdout tail truncated for report - full "
                     f"{len(tail)}B in template.last_verified_note]\n..."
        + tail[-1000:])

    print(f"[{time.strftime('%H:%M:%S')}] BUILD OK after {elapsed}s", flush=True)
    print(f"", flush=True)
    print(f"  image_tag        : {t.image_tag}", flush=True)
    print(f"  image_size_bytes : {t.image_size_bytes:,}"
          f" (~{t.image_size_bytes//(1024*1024)} MB)"
          if t.image_size_bytes else "  image_size_bytes : (unknown)",
          flush=True)
    print(f"  image_digest     : {t.image_digest}", flush=True)
    print(f"  digest[:12]      : {(t.image_digest or '')[:19]}", flush=True)
    print(f"  recipe_turn_count: {t.recipe_turn_count}", flush=True)
    print(f"  builder_version  : {t.builder_version}", flush=True)
    print(f"  last_verified_ok : {t.last_verified_ok}", flush=True)
    print(f"", flush=True)
    print(f"  --- verification stdout tail ---", flush=True)
    print(tail_show, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
