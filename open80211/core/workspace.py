"""
Workspace engine - named, resumable engagements.

A professional keeps multiple engagements. This layer lets you:
  * create a named workspace (client/campaign), 
  * switch between workspaces,
  * resume a previous one with all its targets, captures and notes,
  * list everything on disk.

Workspaces live under `results/workspaces/<name>/`; the active one also
mirrors into the per-run session dir for compatibility with older
reporting code.
"""
import datetime
import json
import re
from pathlib import Path

from open80211.core import ui
from open80211.core.config import RESULTS_DIR, CONFIG

WORKSPACE_ROOT = RESULTS_DIR / "workspaces"


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "default"


def list_workspaces() -> list:
    """Return [{'name','path','created','last_seen'}] sorted by recency."""
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    out = []
    for d in sorted(WORKSPACE_ROOT.iterdir()):
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        out.append({
            "name": d.name,
            "path": d,
            "created": meta.get("created", "?"),
            "last_seen": meta.get("last_seen", "?"),
            "aps": meta.get("aps", 0),
            "hosts": meta.get("hosts", 0),
            "creds": meta.get("creds", 0),
        })
    return sorted(out, key=lambda w: w.get("last_seen", ""), reverse=True)


def create_workspace(name: str) -> Path:
    """Create + activate a named workspace directory."""
    safe = _safe_name(name)
    path = WORKSPACE_ROOT / safe
    path.mkdir(parents=True, exist_ok=True)
    _write_meta(path, name=safe, created=True)
    activate_workspace(safe)
    ui.ok(f"Workspace '{safe}' created at {path}")
    return path


def activate_workspace(name: str) -> Path:
    """Point CONFIG.session_dir at a workspace; rebind the target store."""
    safe = _safe_name(name)
    path = WORKSPACE_ROOT / safe
    path.mkdir(parents=True, exist_ok=True)
    CONFIG.session_dir = path
    CONFIG.run_id = safe
    _write_meta(path, name=safe)
    from open80211.core.targets import TARGETS, bind_targets
    bind_targets()
    TARGETS.log("workspace", f"activated '{safe}'")
    ui.ok(f"Active workspace: {safe}")
    return path


def switch_workspace() -> None:
    """Interactive pick from saved workspaces."""
    ws = list_workspaces()
    if not ws:
        ui.warn("No workspaces yet. Create one.")
        return
    names = [w["name"] for w in ws]
    idx = ui.menu("Select workspace", names)
    if not idx:
        return
    activate_workspace(names[idx - 1])


def rename_workspace(old: str, new: str) -> None:
    safe_old = _safe_name(old)
    safe_new = _safe_name(new)
    if safe_old == safe_new:
        return
    old_path = WORKSPACE_ROOT / safe_old
    new_path = WORKSPACE_ROOT / safe_new
    if old_path.exists() and not new_path.exists():
        old_path.rename(new_path)
        ui.ok(f"Renamed workspace -> {safe_new}")


def delete_workspace(name: str) -> None:
    safe = _safe_name(name)
    path = WORKSPACE_ROOT / safe
    if not path.exists():
        ui.warn("No such workspace.")
        return
    if ui.confirm(f"Delete workspace '{safe}' and ALL its data? (irreversible)",
                  default=False):
        import shutil
        shutil.rmtree(path)
        ui.ok("Workspace deleted.")


def _write_meta(path: Path, name: str, created: bool = False):
    now = datetime.datetime.now().isoformat(timespec="seconds")
    meta_path = path / "meta.json"
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if created:
        meta["created"] = now
    meta["last_seen"] = now
    meta["name"] = name
    from open80211.core.targets import TARGETS
    meta["aps"] = len(TARGETS.aps)
    meta["hosts"] = len(TARGETS.hosts)
    meta["creds"] = len(TARGETS.creds)
    try:
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass


def workspace_menu() -> None:
    while True:
        choice = ui.menu("Workspaces", [
            "List workspaces",
            "Create new workspace",
            "Switch workspace (resume)",
            "Rename workspace",
            "Delete workspace",
            "Show active workspace status",
        ])
        if choice == 0:
            return
        if choice == 1:
            ws = list_workspaces()
            if ws:
                ui.show_table("Workspaces", ["Name", "Created", "Last seen",
                                             "APs", "Hosts", "Creds"],
                              [[w["name"], w["created"], w["last_seen"],
                                w["aps"], w["hosts"], w["creds"]] for w in ws])
            else:
                ui.info("No workspaces yet.")
        elif choice == 2:
            name = ui.ask("Workspace name (client/campaign)")
            if name:
                create_workspace(name)
        elif choice == 3:
            switch_workspace()
        elif choice == 4:
            ws = list_workspaces()
            if not ws:
                ui.info("Nothing to rename.")
                continue
            names = [w["name"] for w in ws]
            idx = ui.menu("Rename which", names)
            if not idx:
                continue
            new = ui.ask("New name")
            if new:
                rename_workspace(names[idx - 1], new)
        elif choice == 5:
            ws = list_workspaces()
            if not ws:
                ui.info("Nothing to delete.")
                continue
            names = [w["name"] for w in ws]
            idx = ui.menu("Delete which", names)
            if idx:
                delete_workspace(names[idx - 1])
        elif choice == 6:
            from open80211.core.targets import TARGETS
            ui.show_table(f"Active: {CONFIG.run_id}", ["Item", "Count"],
                          TARGETS.summary())
            ui.info(f"Session dir: {CONFIG.session_dir}")