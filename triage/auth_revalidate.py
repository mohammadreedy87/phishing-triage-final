"""Phase 2 (extension): best-effort re-validation of SPF / DKIM / DMARC on an EXPORTED email.

What this can and cannot prove (shown in the UI as well):
- DKIM: cryptographic check of the signature against the public key in DNS *today*.
  Valid only if the exported file is byte-identical to what was received. Keys rotated or
  removed since delivery give "fail/unavailable" even for a legitimate old mail.
- SPF: evaluated against the IP of the first public hop found in the Received chain and the
  CURRENT SPF record. The true connecting IP is only known to the receiving server, so this is
  an assumption. Result can differ from what the receiver saw at delivery time.
- DMARC: current policy record plus identifier alignment of the two results above.
Set TRIAGE_DNS=0 to disable all network lookups (offline mode: results are 'unavailable').
"""
import ipaddress
import os
import re
from email.utils import parseaddr

try:
    import dns.resolver
    import dkim
    import spf
except ImportError:  # optional deps: without them every check reports "unavailable"
    dns = dkim = spf = None


def dns_enabled():
    return os.getenv("TRIAGE_DNS", "1") != "0" and dkim is not None


def _res(result, source, note=""):
    return {"result": result, "source": source, "note": note}


def txt_lookup(name):
    try:
        return ["".join(s.decode() for s in r.strings) for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []


def dkim_validate(raw: bytes, dnsfunc=None):
    if not dns_enabled() and dnsfunc is None:
        return _res("unavailable", "offline", "DNS lookups disabled"), []
    n = len(re.findall(rb"(?im)^dkim-signature:", raw))
    if n == 0:
        return _res("none", "revalidated", "No DKIM-Signature header in the file"), []
    passed, details = [], []
    for i in range(n):
        try:
            ok = dkim.DKIM(raw).verify(i, dnsfunc=dnsfunc) if dnsfunc else dkim.DKIM(raw).verify(i)
            dom = _sig_domain(raw, i)
            details.append((dom, ok))
            if ok:
                passed.append(dom)
        except Exception as e:  # malformed signature, DNS error, etc.
            details.append((_sig_domain(raw, i), False))
    if passed:
        return _res("pass", "revalidated", "Valid signature for d=" + ", ".join(passed)
                    + ". Only trustworthy if the exported file was not altered."), passed
    return _res("fail", "revalidated", "No signature verified (altered file, rotated key or forgery)"), []


def _sig_domain(raw, idx):
    ms = re.findall(rb"(?im)^dkim-signature:(.*?)(?=^\S)", raw + b"\nX:", re.S)
    if idx < len(ms):
        m = re.search(rb"\bd=([^;\s]+)", ms[idx])
        if m:
            return m.group(1).decode().lower()
    return "?"


def _public(ip):
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_private or o.is_loopback or o.is_reserved or o.is_multicast or o.is_link_local)
    except ValueError:
        return False


def first_public_ip(hops):
    """hops are oldest-first; the receiving server's view is the newest hop with a public IP."""
    for h in reversed(hops):
        for ip in h.get("ips", []):
            if _public(ip):
                return ip
    return None


def spf_validate(ip, mailfrom, helo, check=None):
    if not dns_enabled() and check is None:
        return _res("unavailable", "offline", "DNS lookups disabled")
    if not ip or not mailfrom or "@" not in mailfrom:
        return _res("unavailable", "revalidated", "No public hop IP or envelope sender in the file")
    try:
        r = (check or spf.check2)(i=ip, s=mailfrom, h=helo or "unknown")
        out = _res(r[0], "revalidated",
                   f"CONDITIONAL: evaluated for IP {ip}, inferred from the Received chain (untrusted: only the "
                   "receiving server knows the real connecting IP), against today's SPF record")
        out["conditional"] = True
        return out
    except Exception as e:
        return _res("unavailable", "revalidated", f"SPF lookup failed: {type(e).__name__}")


try:
    from publicsuffix2 import get_sld
except ImportError:  # without the list, org-domain alignment can be inconclusive
    get_sld = None


def _org(domain):
    """Organizational domain via the Public Suffix List; None if it cannot be determined."""
    domain = domain.lower().strip(".")
    if get_sld is None:
        return None
    return get_sld(domain)


def _aligned(a, b, strict):
    """True / False, or None when relaxed alignment cannot be decided."""
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    if strict:
        return False
    oa, ob = _org(a), _org(b)
    if oa is None or ob is None:
        return None
    return oa == ob


def dmarc_validate(from_domain, spf_res, spf_domain, dkim_pass_domains, lookup=None):
    if not dns_enabled() and lookup is None:
        return _res("unavailable", "offline", "DNS lookups disabled")
    lookup = lookup or txt_lookup
    rec = None
    for dom in (from_domain, _org(from_domain)):
        for t in lookup("_dmarc." + dom):
            if t.lower().startswith("v=dmarc1"):
                rec = t
                break
        if rec:
            break
    if not rec:
        return _res("none", "revalidated", "No DMARC record published for " + from_domain)
    tags = dict(x.strip().split("=", 1) for x in rec.split(";") if "=" in x)
    policy = tags.get("p", "none")
    spf_al = _aligned(spf_domain, from_domain, tags.get("aspf") == "s") if (spf_res == "pass" and spf_domain) else False
    dk_al = [_aligned(d, from_domain, tags.get("adkim") == "s") for d in dkim_pass_domains]
    if spf_al is True or True in dk_al:
        res = "pass"
    elif spf_al is None or None in dk_al:
        res = "inconclusive"
    else:
        res = "fail"
    cond = spf_res in ("pass", "fail", "softfail", "neutral") and res != "inconclusive"
    note = f"Policy p={policy}; SPF aligned={spf_al}, DKIM aligned={dk_al or 'n/a'}"
    if res == "inconclusive":
        note += ". Organizational domain could not be determined, so alignment is undecided."
    r = _res(res, "revalidated", note)
    r["conditional"] = True  # depends on the SPF result, which depends on an inferred IP
    return r


def revalidate(raw, msg, hops, from_addr):
    if not from_addr or "@" not in from_addr:
        u = _res("unavailable", "revalidated", "No usable From address")
        return {"spf": u, "dkim": u, "dmarc": u}
    from_domain = from_addr.split("@")[-1]
    dk, dk_domains = dkim_validate(raw)
    rp = parseaddr(str(msg.get("Return-Path", "")))[1] or from_addr
    helo_m = re.search(r"from\s+(\S+)", hops[0]["raw"]) if hops else None
    ip = first_public_ip(hops)
    sp = spf_validate(ip, rp, helo_m.group(1) if helo_m else None)
    dm = dmarc_validate(from_domain, sp["result"], rp.split("@")[-1], dk_domains)
    return {"spf": sp, "dkim": dk, "dmarc": dm}
