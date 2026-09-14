"""Machine-callable template recipes.

Each function here is a `recipe_fn` passable to
`template_builder.build_template`. It receives a `TemplateRecorder`
whose `.exec_in_pod / .write_file_to_pod / .install_package /
.http_probe` methods record every step into the template's recipe
artifact.

Every recipe returns a dict with `verification_cmd` +
`verification_expect` — how the template proves the stack is alive.

**Provenance rule (do not break):** recipes call ONLY the recorder's
tool methods. No `subprocess.run`, no `pod.write(...)` bypass, no
inline `Dockerfile` payloads. A future reader replaying a recipe knows
only the provision tools; any step that isn't recorded through them is
a hole in the provenance chain.
"""
from __future__ import annotations

# Pinned versions — bump these deliberately, never floating "latest".
# Templates are cached provision outputs; their reproducibility depends
# on every input being pinned.
_TOMCAT_VER = "9.0.65"
_ADOPTIUM_KEY_URL = "https://packages.adoptium.net/artifactory/api/gpg/key/public"
_ADOPTIUM_DEB_LINE = ("deb [signed-by=/etc/apt/keyrings/adoptium.gpg] "
                      "https://packages.adoptium.net/artifactory/deb "
                      "jammy main")
_TOMCAT_URL = (f"https://archive.apache.org/dist/tomcat/tomcat-9/"
               f"v{_TOMCAT_VER}/bin/apache-tomcat-{_TOMCAT_VER}.tar.gz")


def tomcat_jdk8(rec):
    """JDK 8 (Temurin) + Maven + Tomcat 9. For java-servlet-web-rce.

    Uses `_or_raise` variants throughout so any non-zero exit halts the
    build immediately. The prior version used non-raising variants and a
    slow-network wget timeout left a truncated tarball + silent tar
    failure + broken commit; verification then saw a phantom template."""
    # Base tooling — every install must succeed, else adoptium repo add
    # (which needs wget + gpg) can't run. First call triggers apt-get
    # update which on this VM's slow outbound network takes 3-6 min; a
    # 1800s cap absorbs that. Subsequent installs reuse the marker file
    # so they skip update and finish faster.
    rec.install_or_raise("wget", timeout_s=1800)
    rec.install_or_raise("curl", timeout_s=600)
    rec.install_or_raise("gnupg", timeout_s=600)
    rec.install_or_raise("ca-certificates", timeout_s=600)
    rec.install_or_raise("git", timeout_s=600)

    # Add Adoptium (Temurin) repo — ubuntu 22.04 doesn't ship JDK 8.
    rec.exec_or_raise("mkdir -p /etc/apt/keyrings", timeout_s=30)
    rec.exec_or_raise(
        f"wget -qO- {_ADOPTIUM_KEY_URL} "
        f"| gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg",
        timeout_s=180)
    rec.exec_or_raise(
        f"echo '{_ADOPTIUM_DEB_LINE}' "
        f"> /etc/apt/sources.list.d/adoptium.list",
        timeout_s=10)
    # Force the install_package idempotency marker to re-run apt-get update
    # so the new adoptium repo gets read on the next install_package call.
    rec.exec_or_raise("rm -f /tmp/.patchwing_apt_updated", timeout_s=10)

    # JDK + Maven. Temurin JDK is a huge apt-get install (JDK proper +
    # fonts + libX + p11-kit + 27 dependencies, ~300 MB across many
    # small pulls). This VM's outbound is slow enough that 30 min isn't
    # enough — 60 min is the honest cap.
    rec.install_or_raise("temurin-8-jdk", timeout_s=3600)
    rec.install_or_raise("maven", timeout_s=1200)

    # Tomcat 9 tarball. 1800s (30 min) because this VM's outbound HTTPS
    # to archive.apache.org is inexplicably slow at times; the file is
    # only ~11.5 MB. Split into fetch → extract so a truncated tarball
    # is caught by tar's exit code (which raises here) instead of
    # silently continuing.
    rec.exec_or_raise(
        f"cd /opt && wget -q {_TOMCAT_URL}",
        timeout_s=1800)
    rec.exec_or_raise(
        f"cd /opt && "
        f"tar -xzf apache-tomcat-{_TOMCAT_VER}.tar.gz && "
        f"mv apache-tomcat-{_TOMCAT_VER} tomcat9 && "
        f"rm apache-tomcat-{_TOMCAT_VER}.tar.gz",
        timeout_s=180)
    rec.exec_or_raise("chmod +x /opt/tomcat9/bin/*.sh", timeout_s=15)

    # Pin JAVA_HOME so catalina.sh finds temurin without any auto-detect
    rec.write_file_to_pod(
        "/opt/tomcat9/bin/setenv.sh",
        "export JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64\n"
        "export CATALINA_PID=/tmp/tomcat.pid\n")
    rec.exec_or_raise("chmod +x /opt/tomcat9/bin/setenv.sh", timeout_s=10)

    # Verification: start tomcat in background via startup.sh, wait for
    # port bind, curl the default page. Tomcat 9 ships a "It works!"
    # ROOT webapp that includes "Apache Tomcat" in the response HTML.
    return {
        "verification_cmd":
            "/opt/tomcat9/bin/startup.sh 2>&1 | head -5 && "
            "for i in 1 2 3 4 5 6 7 8 9 10; do "
            "  sleep 3; "
            "  if curl -sSf http://127.0.0.1:8080/ > /dev/null 2>&1; then break; fi; "
            "done && "
            "curl -sSi http://127.0.0.1:8080/",
        "verification_expect": r"HTTP/1\.1 200.*Apache Tomcat",
    }


# --- placeholders for step 3 templates B and C ---------------------------

def apache_httpd_24(rec):
    """Apache HTTPD 2.4 + PHP 7.4. For php-web-rce."""
    # Timeouts scaled for this VM's slow outbound; software-properties-
    # common in particular pulls dbus, glib, polkit, systemd libraries
    # and legit needs ~15 min on a first fetch.
    rec.install_or_raise("wget", timeout_s=1800)
    rec.install_or_raise("curl", timeout_s=1200)
    rec.install_or_raise("ca-certificates", timeout_s=1200)
    rec.install_or_raise("gnupg", timeout_s=1200)
    rec.install_or_raise("software-properties-common", timeout_s=1800)
    rec.install_or_raise("git", timeout_s=1200)

    # ondrej/php PPA for PHP 7.4 (Ubuntu 22.04 defaults to PHP 8.1)
    rec.exec_or_raise(
        "LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php",
        timeout_s=900)
    rec.exec_or_raise("rm -f /tmp/.patchwing_apt_updated", timeout_s=10)

    rec.install_or_raise("apache2", timeout_s=1800)
    rec.install_or_raise("php7.4", timeout_s=1800)
    rec.install_or_raise("libapache2-mod-php7.4", timeout_s=1200)

    # Enable mod_php7.4; ondrej installs php8.1 too — swap the SAPI.
    # a2dismod/a2enmod exit non-zero if the module isn't there; the
    # `|| true` keeps the chain going, and we don't _or_raise here.
    rec.exec_in_pod(
        "a2dismod php8.1 2>&1 || true; a2enmod php7.4 2>&1 || true",
        timeout_s=30)

    rec.write_file_to_pod(
        "/var/www/html/index.php",
        "<?php echo 'PHP running: ' . phpversion(); ?>\n")

    return {
        "verification_cmd":
            "apache2ctl start 2>&1 | head -5 && "
            "for i in 1 2 3 4 5; do "
            "  sleep 2; "
            "  if curl -sSf http://127.0.0.1:80/index.php > /dev/null 2>&1; then break; fi; "
            "done && "
            "echo '---' && curl -sSi http://127.0.0.1:80/index.php && "
            "echo '---' && php -v",
        "verification_expect":
            r"HTTP/1\.1 200.*PHP running: 7\.4\.\d+.*PHP 7\.4\.\d+",
    }


_NODESOURCE_KEY_URL = "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
_NODESOURCE_DEB_LINE = ("deb [signed-by=/etc/apt/keyrings/nodesource.gpg] "
                        "https://deb.nodesource.com/node_18.x nodistro main")


def nodejs_18(rec):
    """Node.js 18 LTS + npm. For nodejs-rce."""
    rec.install_or_raise("wget", timeout_s=1800)
    rec.install_or_raise("curl", timeout_s=1200)
    rec.install_or_raise("ca-certificates", timeout_s=1200)
    rec.install_or_raise("gnupg", timeout_s=1200)
    rec.install_or_raise("git", timeout_s=1200)

    # Nodesource 18.x repo
    rec.exec_or_raise("mkdir -p /etc/apt/keyrings", timeout_s=30)
    rec.exec_or_raise(
        f"wget -qO- {_NODESOURCE_KEY_URL} "
        f"| gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg",
        timeout_s=180)
    rec.exec_or_raise(
        f"echo '{_NODESOURCE_DEB_LINE}' "
        f"> /etc/apt/sources.list.d/nodesource.list",
        timeout_s=10)
    rec.exec_or_raise("rm -f /tmp/.patchwing_apt_updated", timeout_s=10)

    rec.install_or_raise("nodejs", timeout_s=1800)

    return {
        "verification_cmd":
            "node --version && npm --version",
        "verification_expect":
            r"v18\.\d+.*\d+\.\d+\.\d+",
    }


# --- verify-only recipes over ported Docker Hub base images ---------------
# These are used when the machine-recipe path can't complete on a slow-
# network VM. The base_image is a pre-built Docker Hub image loaded into
# the local registry (see scripts/pull_docker_image.py). The recipe body
# is empty — recipe_turn_count = 0 — and the pod_templates row's
# base_image field explicitly names the docker.io source, so a reader
# can tell at a glance that this template was IMPORTED, not machine-
# derived from ubuntu:22.04.
#
# Provenance note: these are HONEST rows in that they lie about nothing.
# They are LESS provenanced than the ubuntu:22.04-based recipes because
# the base image itself was built by upstream (docker.io/library/*) via
# their own Dockerfile — a chain we did not observe. Trade the recipe-
# derived guarantee for a reachable network path.

def tomcat_jdk8_from_official(rec):
    """Verify-only recipe over docker.io/library/tomcat:9.0-jdk8-temurin.

    Base ships Tomcat + JDK 8 (Temurin) but the webapps/ dir is empty by
    default in the official image (no ROOT app) — a curl to / returns
    404. That 404 IS produced by Tomcat, so verification keys on the
    server signature in the body ('Apache Tomcat/9.0.') rather than
    the status code. Any provision that WANTS a deployed WAR drops it
    into /usr/local/tomcat/webapps at run time."""
    return {
        "verification_cmd":
            # Any curl exit is fine (server responds with 404 body from
            # Tomcat; -sS suppresses progress but keeps errors visible)
            "cd /usr/local/tomcat && catalina.sh start && "
            "for i in 1 2 3 4 5 6 7 8 9 10; do "
            "  sleep 3; "
            "  if curl -sS -o /dev/null http://127.0.0.1:8080/ 2>&1; then break; fi; "
            "done && "
            "curl -sSi http://127.0.0.1:8080/",
        "verification_expect": r"Apache Tomcat/9\.0\.",
    }


def apache_httpd_24_from_official(rec):
    """Verify-only recipe over docker.io/library/php:7.4-apache.
    Base ships Apache + PHP 7.4 configured; the container's default
    CMD is `apache2-foreground` which we start in background here so
    the verification probe can complete."""
    # Give the verification probe something PHP-specific to render
    rec.write_file_to_pod(
        "/var/www/html/index.php",
        "<?php echo 'PHP running: ' . phpversion(); ?>\n")
    return {
        "verification_cmd":
            "apache2-foreground & "
            "for i in 1 2 3 4 5 6 7 8 9 10; do "
            "  sleep 2; "
            "  if curl -sSf http://127.0.0.1:80/index.php > /dev/null 2>&1; then break; fi; "
            "done && "
            "curl -sSi http://127.0.0.1:80/index.php",
        "verification_expect": r"HTTP/1\.1 200.*PHP running: 7\.4\.",
    }


def nodejs_18_from_official(rec):
    """Verify-only recipe over docker.io/library/node:18-bullseye. Just
    checks that node + npm respond with expected versions — no service
    to bring up since node is a runtime, not a daemon."""
    return {
        "verification_cmd":
            "node --version && npm --version",
        "verification_expect":
            r"v18\.\d+\.\d+\s+\d+\.\d+\.\d+",
    }
