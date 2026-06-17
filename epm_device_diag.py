#!/usr/bin/env python3
"""EPM (Endpoint Privilege Manager) device diagnostic gatherer -- READ ONLY.

Tenant-side diagnostics for an EPM agent/device, gathered through the Keeper
Commander library. Built to run on Windows (also works on macOS/Linux). It
performs NO delete or modify operations -- it only reads.

It answers two common EPM elevation symptoms:
  * "Applications not appearing in the Admin Console"
        -> are there application collections? does an ENFORCE elevation policy
           actually reach this device, and does its ApplicationCheck cover it?
  * "Agent history shows no requests"
        -> is the agent registered and online? are there ANY approvals or
           approval_request_status_changed audit events for it?

What it gathers (all server-side, safe to run from your workstation):
  1. Agent / device record + properties + online/offline state
  2. Deployment the device belongs to
  3. Policies and whether each one REACHES this device (collection-link math)
  4. Collections the device belongs to + tenant application-collection inventory
  5. Approval requests for the device (or explicit "none found")
  6. Recent EPM audit events (via Commander's own ARAM report engine)
  7. An endpoint-side checklist the API cannot reach (run ON the Windows box)

What it CANNOT gather (lives on the endpoint, not the backend):
  * KeeperLogger log files, localhost:6889 health checks, Task Scheduler tasks,
    plugin-bin binaries, DNS/port reachability. Those are in the footer
    checklist for whoever has hands on the device.

Sanitization: identities (emails / usernames / SIDs / domains), justification
text, and all cryptographic key material are REDACTED by default so the report
is safe to attach to a case. Pass --no-redact for a full internal view.

Usage (Windows PowerShell or cmd; run `keeper login` first):
  python epm_device_diag.py                          # summary of all agents
  python epm_device_diag.py --machine RP-LAPTOP-01   # focus one machine (substring)
  python epm_device_diag.py --agent <AGENT_UID>      # focus one agent UID
  python epm_device_diag.py --days 14                # audit lookback (default 7)
  python epm_device_diag.py --output report.txt      # also write to a utf-8 file
  python epm_device_diag.py --format json            # machine-readable dump
  python epm_device_diag.py --no-redact              # show identities + keys (internal)

NOTE: built against the installed keepercommander library source, but the
audit-event section in particular should be confirmed against a live tenant the
first time you run it -- Commander API shapes are only truly verified live.
"""

import os
import sys
import json
import argparse
import datetime
import contextlib
import io

from keepercommander import api, utils
from keepercommander.__main__ import get_params_from_config
from keepercommander.auth.login_steps import LoginUi
from keepercommander.enterprise import query_enterprise
from keepercommander.pedm import admin_plugin, pedm_shared
from keepercommander.proto import pedm_pb2

CONFIG = os.path.expanduser(os.path.join("~", ".keeper", "config.json"))

# ----- toggles set from argv in main() -----
REDACT = True

# Application-ish collection types (the "apps not appearing" universe)
APP_COLLECTION_TYPES = {
    int(pedm_shared.CollectionType.Application),         # 2
    int(pedm_shared.CollectionType.ApplicationName),     # 5
    int(pedm_shared.CollectionType.CustomAppCollection), # 102
}
# Collection types whose values can carry user identity (mask their values)
IDENTITY_COLLECTION_TYPES = {
    int(pedm_shared.CollectionType.UserAccount),
    int(pedm_shared.CollectionType.GroupAccount),
    int(pedm_shared.CollectionType.UserName),
    int(pedm_shared.CollectionType.CustomUserCollection),
}


# --------------------------------------------------------------------------- #
# Fail-closed login (never auto-submit an empty password on a stale session)
# --------------------------------------------------------------------------- #
class _I(Exception):
    pass


class FailClosedUi(LoginUi):
    def on_device_approval(self, s): raise _I("session expired -- run 'keeper login' first")
    def on_password(self, s):        raise _I("session expired -- run 'keeper login' first")
    def on_two_factor(self, s):      raise _I("session expired -- run 'keeper login' first")
    def on_sso_data_key(self, s):    raise _I("session expired -- run 'keeper login' first")
    def on_sso_redirect(self, s):    raise _I("session expired -- run 'keeper login' first")


# --------------------------------------------------------------------------- #
# Output: write to stdout and (optionally) buffer for --output
# --------------------------------------------------------------------------- #
_BUF = []


def emit(line=""):
    print(line)
    _BUF.append(line)


def section(title):
    emit()
    emit("=" * 78)
    emit("  " + title)
    emit("=" * 78)


def sub(title):
    emit()
    emit("--- " + title + " " + "-" * max(0, 70 - len(title)))


# --------------------------------------------------------------------------- #
# Sanitization
# --------------------------------------------------------------------------- #
def _looks_email(s):
    return isinstance(s, str) and "@" in s and "." in s.split("@")[-1]


def _looks_sid(s):
    return isinstance(s, str) and s.upper().startswith("S-1-")


_KEYISH = ("key", "secret", "token", "password", "passwd", "private", "cert", "seed")


def mask_str(s):
    """Mask a single identity-bearing string, preserving just enough to correlate."""
    if not REDACT or not isinstance(s, str) or not s:
        return s
    if _looks_email(s):
        local, _, dom = s.partition("@")
        dparts = dom.split(".")
        dmask = (dparts[0][:1] + "***") if dparts and dparts[0] else "***"
        tld = ("." + dparts[-1]) if len(dparts) > 1 else ""
        return (local[:1] + "***@" + dmask + tld)
    if _looks_sid(s):
        return "S-1-***"
    if len(s) <= 3:
        return "***"
    return s[:2] + "***" + s[-1:]


def mask_field(key, value):
    """Redact a (key, value) pair based on the key name and value shape."""
    if not REDACT:
        return value
    k = str(key).lower()
    if any(h in k for h in _KEYISH):
        if isinstance(value, (bytes, bytearray)):
            return "<%d bytes redacted>" % len(value)
        return "<redacted>"
    if isinstance(value, (bytes, bytearray)):
        return "<%d bytes>" % len(value)
    if any(h in k for h in ("user", "email", "account", "owner", "sid", "upn", "login")):
        return mask_str(value) if isinstance(value, str) else value
    return value


def mask_keybytes(b):
    if b is None:
        return "(none)"
    if not REDACT:
        return utils.base64_url_encode(b) if isinstance(b, (bytes, bytearray)) else str(b)
    if isinstance(b, (bytes, bytearray)):
        return "<%d bytes redacted>" % len(b)
    return "<redacted>"


def fmt_ts(value):
    """Best-effort timestamp formatting for ms-int / s-int / datetime / None."""
    if value is None or value == 0:
        return ""
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:   # milliseconds
            v /= 1000.0
        try:
            return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(value)
    return str(value)


def props_lines(properties, indent="    "):
    out = []
    if isinstance(properties, dict):
        for k in sorted(properties.keys()):
            out.append("%s%-22s %s" % (indent, str(k) + ":", mask_field(k, properties[k])))
    return out


# --------------------------------------------------------------------------- #
# Core gather
# --------------------------------------------------------------------------- #
def online_agent_uids(p):
    try:
        rq = pedm_pb2.PolicyAgentRequest()
        rq.summaryOnly = False
        rs = api.execute_router(p, "pedm/get_policy_agents", rq, rs_type=pedm_pb2.PolicyAgentResponse)
        return {utils.base64_url_encode(x) for x in rs.agentUid} if rs else set()
    except Exception as e:
        emit("  WARNING: could not query online agents: %s" % e)
        return set()


def select_agents(plugin, machine, agent_uid):
    agents = list(plugin.agents.get_all_entities())
    if agent_uid:
        return [a for a in agents if a.agent_uid == agent_uid]
    if machine:
        m = machine.lower()
        return [a for a in agents
                if m in str((a.properties or {}).get("MachineName", "")).lower()]
    return agents


def linked_collection_uids(plugin, object_uid):
    try:
        links = plugin.storage.collection_links.get_links_for_object(object_uid)
        return {ln.collection_uid for ln in links}
    except Exception:
        return set()


def report_agent(p, plugin, agent, online, all_collections, policies, all_agents_uid):
    machine = (agent.properties or {}).get("MachineName", "") if agent.properties else ""
    deployment = plugin.deployments.get_entity(agent.deployment_uid)
    dep_name = deployment.name if deployment else agent.deployment_uid
    is_online = agent.agent_uid in online

    section("DEVICE: %s" % (machine or agent.agent_uid))
    emit("  agent_uid    : %s" % agent.agent_uid)
    emit("  machine_name : %s" % (machine or "(unknown)"))
    emit("  deployment   : %s" % dep_name)
    emit("  registered   : yes (present in tenant)")
    emit("  online now   : %s" % ("YES" if is_online else "NO  <-- offline: no live requests will arrive"))
    emit("  disabled     : %s%s" % (agent.disabled, "   <-- DISABLED: agent will not enforce" if agent.disabled else ""))
    emit("  created      : %s" % fmt_ts(agent.created))
    emit("  public_key   : %s" % mask_keybytes(getattr(agent, "public_key", None)))
    if agent.properties:
        sub("agent properties (OS / version / reported metadata)")
        for ln in props_lines(agent.properties):
            emit(ln)

    # ----- deployment detail -----
    if deployment:
        sub("deployment")
        emit("    name     : %s" % deployment.name)
        emit("    disabled : %s" % getattr(deployment, "disabled", ""))
        emit("    created  : %s" % fmt_ts(getattr(deployment, "created", None)))
        emit("    updated  : %s" % fmt_ts(getattr(deployment, "updated", None)))

    # ----- collections this device belongs to -----
    agent_cols = linked_collection_uids(plugin, agent.agent_uid)
    sub("collections this device belongs to (%d)" % len(agent_cols))
    if not agent_cols:
        emit("    (none) -- device is in no collections; most policies will not target it")
    for cu in sorted(agent_cols):
        col = all_collections.get(cu)
        if col:
            tname = pedm_shared.collection_type_to_name(col.collection_type)
            emit("    %-26s %-18s" % (cu, tname))
    machine_cols = {cu for cu in agent_cols
                    if all_collections.get(cu) and
                    all_collections[cu].collection_type == int(pedm_shared.CollectionType.CustomMachineCollection)}

    # ----- which policies REACH this device -----
    sub("policies that reach this device")
    reaching = []
    for pol in policies:
        pol_cols = linked_collection_uids(plugin, pol.policy_uid)
        applies = (all_agents_uid in pol_cols) or bool(pol_cols & agent_cols)
        if applies:
            reaching.append((pol, all_agents_uid in pol_cols))
    if not reaching:
        emit("    (none) -- NO policy targets this device.")
        emit("    This alone explains 'no elevation prompt / apps not appearing'.")
    enforce_elev = 0
    for pol, via_all in reaching:
        data = pol.data or {}
        status = "off" if pol.disabled else data.get("Status")
        ptype = data.get("PolicyType")
        appchk = data.get("ApplicationCheck")
        emit("    - %s" % (data.get("PolicyName") or pol.policy_uid))
        emit("        uid    : %s" % pol.policy_uid)
        emit("        type   : %s" % ptype)
        emit("        status : %s%s" % (status, "   <-- not enforcing" if status not in ("enforce",) else ""))
        emit("        scope  : %s" % ("ALL AGENTS (*)" if via_all else "via shared collection"))
        emit("        apps   : %s" % appchk)
        if str(ptype) in ("PrivilegeElevation", "1") and status == "enforce":
            enforce_elev += 1

    sub("verdict for this device")
    emit("    online .................. %s" % ("YES" if is_online else "NO"))
    emit("    in a machine collection . %s" % ("YES" if machine_cols else "NO"))
    emit("    reached by any policy ... %s" % ("YES" if reaching else "NO"))
    emit("    enforce elevation policy  %s" % ("YES" if enforce_elev else "NO  <-- likely root cause"))

    # ----- approvals for this device -----
    report_approvals(plugin, agent.agent_uid)


def report_approvals(plugin, agent_uid):
    sub("approval requests for this device")
    try:
        approvals = [a for a in plugin.approvals.get_all_entities() if a.agent_uid == agent_uid]
    except Exception as e:
        emit("    WARNING: could not read approvals: %s" % e)
        return
    if not approvals:
        emit("    (none) -- no approval requests recorded for this agent.")
        emit("    Consistent with the 'no requests in history' symptom: the request")
        emit("    chain is not reaching the backend (endpoint-side -- see checklist).")
        return
    for ap in approvals:
        appinfo = {k: mask_field(k, v) for k, v in (ap.application_info or {}).items()}
        acctinfo = {k: mask_str(v) for k, v in (ap.account_info or {}).items()}
        emit("    - approval_uid : %s" % ap.approval_uid)
        emit("        type        : %s" % ap.approval_type)
        emit("        application : %s" % appinfo)
        emit("        account     : %s" % acctinfo)
        just = ap.justification or ""
        emit("        justification: %s" % ("<%d chars redacted>" % len(just) if (REDACT and just) else just))
        emit("        created     : %s" % fmt_ts(ap.created))
        emit("        expires_in  : %s" % ap.expire_in)


def report_tenant_collections(plugin, all_collections):
    section("TENANT COLLECTION INVENTORY (context for 'apps not appearing')")
    by_type = {}
    for col in all_collections.values():
        by_type.setdefault(col.collection_type, []).append(col)
    if not all_collections:
        emit("  (no collections at all -- nothing for policies to target)")
        return
    for ctype in sorted(by_type.keys()):
        tname = pedm_shared.collection_type_to_name(ctype)
        emit("  %-22s (type %-3s): %d" % (tname, ctype, len(by_type[ctype])))
    # detail the application collections specifically
    app_cols = [c for c in all_collections.values() if c.collection_type in APP_COLLECTION_TYPES]
    sub("application collections (%d) -- if empty, KeeperFullInventory may be off" % len(app_cols))
    if not app_cols:
        emit("    (none) -- no application collections exist. File inventory is disabled")
        emit("    by default in recent agents; enable it on a test machine to populate.")
    for c in app_cols:
        mask_vals = c.collection_type in IDENTITY_COLLECTION_TYPES
        data = {k: (mask_str(v) if mask_vals else v) for k, v in (c.collection_data or {}).items()}
        emit("    %-26s %-12s %s" % (c.collection_uid,
                                     pedm_shared.collection_type_to_name(c.collection_type), data))


def report_audit_events(p, scope_agents, days):
    section("RECENT EPM AUDIT EVENTS (elevation request history)")
    emit("  Source: Commander ARAM engine (pedm/get_audit_events). Verify live the")
    emit("  first time. Showing most recent events that mention an in-scope device.")
    try:
        from keepercommander.commands.pedm.pedm_aram import PedmEventReportCommand
    except Exception as e:
        emit("  SKIPPED: ARAM module unavailable: %s" % e)
        emit("  Fallback: run `epm report event` and `epm report summary` in Commander.")
        return

    # build the set of strings that identify our in-scope devices
    needles = set()
    for a in scope_agents:
        needles.add(a.agent_uid)
        mn = (a.properties or {}).get("MachineName") if a.properties else None
        if mn:
            needles.add(str(mn))
    needles_lc = {n.lower() for n in needles}

    try:
        cmd = PedmEventReportCommand()
        with contextlib.redirect_stdout(io.StringIO()):
            out = cmd.execute(p, format="json", limit=1000, order="desc",
                              report_format="message", filter=[])
        events = json.loads(out) if isinstance(out, str) else (out or [])
    except Exception as e:
        emit("  SKIPPED: live audit query failed: %s" % e)
        emit("  Fallback: run `epm report event` in Commander (interactive session).")
        return

    if not isinstance(events, list):
        emit("  No event rows returned.")
        return

    cutoff = None
    try:
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).timestamp()
    except Exception:
        pass

    def _matches(ev):
        for v in ev.values():
            if isinstance(v, str) and v.lower() in needles_lc:
                return True
            if isinstance(v, str):
                for n in needles_lc:
                    if n and n in v.lower():
                        return True
        return False

    def _within(ev):
        if cutoff is None:
            return True
        t = ev.get("event_time")
        if isinstance(t, (int, float)):
            tv = float(t)
            if tv > 1e12:
                tv /= 1000.0
            return tv >= cutoff
        return True

    matched = [e for e in events if _matches(e) and _within(e)]
    sub("events touching in-scope device(s) in the last %d days: %d" % (days, len(matched)))
    if not matched:
        emit("    (none) -- no audit events reference this device in the window.")
        emit("    Combined with zero approvals, this points at the endpoint-side")
        emit("    request chain (Task Scheduler / plugins / DNS) -- see checklist.")
    shown = 0
    for ev in matched:
        if shown >= 60:
            emit("    ... (%d more; use --format json or `epm report event`)" % (len(matched) - shown))
            break
        et = ev.get("audit_event_type", "?")
        when = fmt_ts(ev.get("event_time"))
        # mask any identity-looking values for display
        extra = {}
        for k, v in ev.items():
            if k in ("event_time", "audit_event_type"):
                continue
            extra[k] = mask_field(k, v) if isinstance(v, (str, bytes, bytearray)) else v
        emit("    [%s] %s" % (when, et))
        emit("        %s" % {k: extra[k] for k in list(extra)[:8]})
        shown += 1


def endpoint_checklist():
    section("ENDPOINT-SIDE CHECKLIST (run ON the Windows test box -- API cannot reach these)")
    emit("""  Health (elevated / Run as Administrator terminal; non-elevated returns 401/403):
    curl -sk https://localhost:6889/health                      -> {"status":"running"}
    curl -sk https://localhost:6889/api/Keeper/registration     -> "IsRegistered": true
    curl -sk https://localhost:6889/api/plugins                 -> KeeperAPI + KeeperPolicy "Running"

  Local ports must be free/listening:
    netstat -an | findstr :6888     (HTTP)
    netstat -an | findstr :6889     (HTTPS)
    netstat -an | findstr :8675     (internal MQTT broker)

  Runtime + policy sync:
    dotnet --list-runtimes          -> .NET 8.0 must be present
    check timestamp of currentPolicies.json in the KeeperPolicy plugin dir
    search logs for: "Local policy merge complete: N server + N local = N total policies"
    watch logs for:  "Plugin failed security validation"

  Force re-registration (recreates tasks if missing):
    curl -X POST "https://localhost:6889/api/Keeper/register?token=<token>&force=true" --insecure

  Task Scheduler -> tasks live under  \\Keeper Security\\  (must exist, not disabled).
  User-session binaries must exist (corrupt install if missing -> clean reinstall):
    ...\\Plugins\\bin\\KeeperClient\\KeeperClient.exe
    ...\\Plugins\\bin\\keeperAgent\\keeperAgent.exe
    ...\\Plugins\\bin\\KeeperMessage\\KeeperMessage.exe
    ...\\Plugins\\bin\\KeeperApproval\\KeeperApproval.exe

  Log file (new file daily, kept 15 days -- grab the day the issue happened):
    Windows: C:\\Program Files\\Keeper Security\\Endpoint Privilege Management\\Plugins\\bin\\KeeperLogger\\Log
    NOTE: docs say "Endpoint Privilege Management"; some notes say "...Manager".
          Verify the ACTUAL folder name on this build -- a wrong path wastes hours.
    Linux:   /opt/keeper/sbin/Plugins/bin/KeeperLogger/Log
    macOS:   /Library/Keeper/sbin/Plugins/bin/KeeperLogger/Log

  Connectivity (a common root-cause pattern -- DNS/egress to the Keeper router):
    (use your region's host: keepersecurity.com / .eu / .us / .com.au / .jp)
    nslookup connect.keepersecurity.com
    Test-NetConnection connect.keepersecurity.com -Port 443
    Restart KeeperEndpointService, then log the affected user out and back in.

  EDR (CrowdStrike / SentinelOne / Sophos) can block process launch from the
  install dir -> exclude  C:\\Program Files\\Keeper Security\\Endpoint Privilege Management\\""")


# --------------------------------------------------------------------------- #
def main():
    global REDACT
    ap = argparse.ArgumentParser(
        description="EPM device diagnostic gatherer (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--machine", help="focus device(s) by MachineName substring")
    ap.add_argument("--agent", help="focus a single agent UID")
    ap.add_argument("--days", type=int, default=7, help="audit-event lookback window (default 7)")
    ap.add_argument("--output", help="also write the report to this file (utf-8)")
    ap.add_argument("--format", choices=["text", "json"], default="text",
                    help="text report (default) or json dump")
    ap.add_argument("--no-redact", dest="redact", action="store_false",
                    help="show identities and key material (INTERNAL use only)")
    args = ap.parse_args()
    REDACT = args.redact

    # be friendly to the Windows console / file redirection
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    p = get_params_from_config(CONFIG)
    p.batch_mode = True
    try:
        api.login(p, login_ui=FailClosedUi())
    except _I as e:
        print("ERROR: %s" % e, file=sys.stderr)
        sys.exit(1)
    if not p.session_token:
        print("ERROR: no session token -- run 'keeper login' first", file=sys.stderr)
        sys.exit(1)

    query_enterprise(p)
    plugin = admin_plugin.get_pedm_plugin(p, skip_sync=True)
    plugin.sync_down(reload=True)

    online = online_agent_uids(p)
    all_collections = {c.collection_uid: c for c in plugin.collections.get_all_entities()}
    policies = list(plugin.policies.get_all_entities())
    all_agents_uid = utils.base64_url_encode(plugin.all_agents)
    scope = select_agents(plugin, args.machine, args.agent)

    if args.format == "json":
        # compact machine-readable dump (still honours --no-redact via mask_field)
        data = {
            "generated": datetime.datetime.now().isoformat(timespec="seconds"),
            "redacted": REDACT,
            "online_count": len(online),
            "agent_count": len(list(plugin.agents.get_all_entities())),
            "policy_count": len(policies),
            "collection_count": len(all_collections),
            "scope": [],
        }
        for a in scope:
            acols = sorted(linked_collection_uids(plugin, a.agent_uid))
            reach = []
            for pol in policies:
                pcols = linked_collection_uids(plugin, pol.policy_uid)
                if all_agents_uid in pcols or (pcols & set(acols)):
                    d = pol.data or {}
                    reach.append({"uid": pol.policy_uid, "name": d.get("PolicyName"),
                                  "type": d.get("PolicyType"),
                                  "status": "off" if pol.disabled else d.get("Status")})
            data["scope"].append({
                "agent_uid": a.agent_uid,
                "machine": (a.properties or {}).get("MachineName") if a.properties else None,
                "online": a.agent_uid in online,
                "disabled": a.disabled,
                "collections": acols,
                "reached_by_policies": reach,
                "approvals": sum(1 for ap in plugin.approvals.get_all_entities() if ap.agent_uid == a.agent_uid),
            })
        out = json.dumps(data, indent=2, default=str)
        print(out)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        return

    # ----- text report -----
    section("EPM DEVICE DIAGNOSTIC  (read-only%s)" % ("" if REDACT else " -- UNREDACTED"))
    emit("  generated : %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    emit("  tenant    : %d agents (%d online), %d policies, %d collections"
         % (len(list(plugin.agents.get_all_entities())), len(online), len(policies), len(all_collections)))
    emit("  scope     : %s" % (args.agent or args.machine or "ALL agents"))
    if not scope:
        emit("  WARNING: no agents matched the filter.")

    report_tenant_collections(plugin, all_collections)
    for a in scope:
        report_agent(p, plugin, a, online, all_collections, policies, all_agents_uid)
    report_audit_events(p, scope, args.days)
    endpoint_checklist()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(_BUF) + "\n")
        if not REDACT:
            print("\nWARNING: %s contains UNREDACTED identities/keys." % args.output, file=sys.stderr)
        else:
            print("\nWrote report to %s" % args.output, file=sys.stderr)


if __name__ == "__main__":
    main()
