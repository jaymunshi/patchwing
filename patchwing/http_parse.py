# Additive helper — parses curl -i-shape reproducer output into an
# HttpEvidence object. Also extracts trailing 'key: value' lines the
# reproducer echoes AFTER the HTTP body as side_channel entries
# (this is how reproduce.sh emits 'side_channel_marker: pwned').
# JSON body key/value pairs are also lifted into side_channel so
# rules like side_channel_flag name='zipslip_pwned' pattern='True'
# fire when the response body contains "zipslip_pwned":"True".
import json, re
from patchwing.states import HttpEvidence

_HTTP_STATUS_RE = re.compile(r'^HTTP/[\d.]+\s+(\d{3})', re.M)
_KV_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*(.+?)\s*$')
# Fix 2A: canonical patchwing side-channel protocol — preferred by PROVISION_SYSTEM
_PW_SC_RE = re.compile(r'^#PW_SC\s+([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+?)\s*$')
# Fix 2B: fallback for reproducers using ---NAME--- separators + value on next line
_SEPARATOR_MARKER_RE = re.compile(r'^---([A-Za-z_][A-Za-z0-9_-]+)---\s*$')

def parse_http_from_output(output: str, method: str = 'POST',
                           endpoint_path: str = '/') -> HttpEvidence:
    text = output or ''
    # Status
    m = _HTTP_STATUS_RE.search(text)
    status = int(m.group(1)) if m else 0
    # Split into segments: headers, body, trailer
    # Simple heuristic: find HTTP status line, then next blank line = end of headers
    lines = text.splitlines()
    hdr_start = None
    for i, ln in enumerate(lines):
        if ln.startswith('HTTP/'):
            hdr_start = i
            break
    headers, body_lines, trailer_lines = (), [], []
    if hdr_start is not None:
        # Consume headers until blank line
        hdrs = []
        j = hdr_start + 1
        while j < len(lines) and lines[j].strip():
            kv = lines[j].split(':', 1)
            if len(kv) == 2:
                hdrs.append((kv[0].strip().lower(), kv[1].strip()))
            j += 1
        headers = tuple(hdrs)
        # Body starts after blank line
        while j < len(lines) and not lines[j].strip():
            j += 1
        # Body ends when we hit ANY trailer-marker line (#PW_SC, ---NAME---, or key:value).
        # Without this, #PW_SC lines stay in body and never reach the trailer parser.
        b_start = j
        while j < len(lines):
            ln = lines[j]
            if _PW_SC_RE.match(ln):
                break
            if _SEPARATOR_MARKER_RE.match(ln):
                break
            if _KV_RE.match(ln) and not ln.startswith('{') and not ln.startswith('<'):
                break
            j += 1
        body_lines = lines[b_start:j]
        trailer_lines = lines[j:]
    body = '\n'.join(body_lines).strip()
    # Extract side channels from JSON body keys (str->str values only)
    channels = []
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, str):
                    channels.append((k, v))
    except Exception:
        pass
    # Fix 2: trailer lines parsed by 3 parsers in preference order.
    # Canonical #PW_SC first, then ---NAME---/value fallback, then existing
    # key:value form. Additive — all three coexist for backward compat.
    _i = 0
    while _i < len(trailer_lines):
        _ln = trailer_lines[_i]
        _mpw = _PW_SC_RE.match(_ln)
        if _mpw:
            channels.append((_mpw.group(1), _mpw.group(2)))
            _i += 1
            continue
        _msep = _SEPARATOR_MARKER_RE.match(_ln)
        if _msep:
            _name = _msep.group(1).lower()
            _j = _i + 1
            while _j < len(trailer_lines) and not trailer_lines[_j].strip():
                _j += 1
            if _j < len(trailer_lines):
                _val = trailer_lines[_j].strip()
                if _val:
                    channels.append((_name, _val))
                _i = _j + 1
                continue
            _i += 1
            continue
        _mkv = _KV_RE.match(_ln)
        if _mkv:
            channels.append((_mkv.group(1), _mkv.group(2)))
        _i += 1
    return HttpEvidence(
        method=method, endpoint_path=endpoint_path,
        status=status, response_headers=headers,
        response_body=body[:32768], response_body_bytes=len(body),
        side_channel=tuple(channels),
    )
