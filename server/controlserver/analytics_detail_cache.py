"""Private, indexed point-in-time inventory projection for management queries."""
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .analytics import agent_family, project
from .security import timestamp
from .validation import ApiProblem

MAX_BYTES = 2 * 1024 * 1024 * 1024


def create_search_index(db):
    """Use a contentless trigram index when this SQLite supports it."""
    try:
        db.execute("CREATE VIRTUAL TABLE search_fts USING fts5(value, content='', tokenize='trigram case_sensitive 1')")
        return True
    except sqlite3.OperationalError as error:
        if str(error) in ("no such module: fts5", "no such tokenizer: trigram"):
            return False
        raise


def use_search_index(db, expression):
    # When a term matches a large fraction of the snapshot, reading the FTS
    # candidate list and then every row is slower than scanning once. This is
    # only a plan choice; the original per-field predicate remains authoritative.
    total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    threshold = max(1024, total // 4)
    return db.execute("SELECT rowid FROM search_fts WHERE search_fts MATCH ? LIMIT 1 OFFSET ?",
                      (expression, threshold)).fetchone() is None


class DetailCacheWriter:
    def __init__(self, cfg, now, database, generation=None):
        cfg.DATA_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, self.path = tempfile.mkstemp(dir=cfg.DATA_ROOT, prefix=".analytics-detail-")
        os.close(fd)
        self.target = cfg.DATA_ROOT / "analytics-detail.sqlite3"
        self.now = now
        self.db = None
        try:
            self.db = sqlite3.connect(self.path)
            self.db.executescript("""
                PRAGMA journal_mode=OFF;
                PRAGMA synchronous=OFF;
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE devices (id TEXT PRIMARY KEY, seen TEXT NOT NULL, os TEXT NOT NULL,
                    state TEXT NOT NULL, legacy INTEGER NOT NULL, searchable TEXT NOT NULL, view TEXT NOT NULL);
                CREATE TABLE tags (kind TEXT NOT NULL, value TEXT NOT NULL, device_id TEXT NOT NULL,
                    PRIMARY KEY(kind,value,device_id)) WITHOUT ROWID;
                CREATE INDEX device_order ON devices(seen DESC,id);
                CREATE INDEX device_state_order ON devices(state,seen DESC,id);
                CREATE INDEX device_legacy_order ON devices(legacy,seen DESC,id);
            """)
            self.search_index = create_search_index(self.db)
            self.db.executemany("INSERT INTO meta VALUES (?,?)", (("format", "3"),
                ("database", database), ("updatedAtUtc", timestamp(now))))
            if self.search_index:
                self.db.execute("INSERT INTO meta VALUES (?,?)", ("searchIndex", "fts5-trigram-v1"))
            if generation:
                self.db.execute("INSERT INTO meta VALUES (?,?)", ("generation", generation))

        except BaseException:
            self.close()
            raise

    def add(self, rows, policy):
        self.add_projected((detail, project(detail, self.now, policy)) for detail in rows)

    def add_projected(self, pairs):
        devices, tags = [], []
        for detail, view in pairs:
            device = view["device"]
            ident = device["deviceId"]
            searchable = [str(v or "").lower() for v in
                          (device.get("hostname"), ident, *(device.get("employeeIds") or []))]
            devices.append((ident, device["lastSeenAtUtc"], (device.get("osVersion") or "").lower(),
                view["onlineState"], int((device.get("schemaVersion") or 1) < 2),
                json.dumps(searchable, ensure_ascii=False), json.dumps(view, ensure_ascii=False)))
            items = set()
            def tag(kind, value=""):
                if value is not None:
                    items.add((kind, value, ident))
            for employee in device.get("employeeIds") or []: tag("employee", employee.lower())
            if view["runningAgents"]: tag("running")
            for value in view["runningAgents"]: tag("agent", value)
            for agent in detail.get("agents") or []:
                if agent.get("running"):
                    family = agent_family(agent.get("agentType"))
                    tag("tool-null" if family is None else "tool", "" if family is None else family)
            for value in view["providers"]: tag("provider", value)
            for request in view["requests"]:
                if request["currentAnomaly"]: tag("error", request["state"].lower())
                if request["observed"]: tag("observed")
            if view["hasAnomaly"]: tag("anomaly")
            if view["everAnomaly"]: tag("everAnomaly")
            if view["allowlist"]: tag("allowlist-any")
            for value in view["allowlist"]: tag("allowlist", value)
            if view["otherUnproxied"]: tag("otherUnproxied")
            if view["dataInsufficient"]: tag("unknown")
            tags.extend(items)
        self.db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", devices)
        if self.search_index:
            # Use device rowids as FTS rowids; verify candidates against each
            # original field at read time so matches never cross field boundaries.
            for start in range(0, len(devices), 500):
                ids = [device[0] for device in devices[start:start + 500]]
                placeholders = ",".join("?" for _ in ids)
                self.db.execute("INSERT INTO search_fts(rowid,value) SELECT d.rowid, "
                    "(SELECT group_concat(value,char(10)) FROM json_each(d.searchable)) "
                    "FROM devices d WHERE d.id IN (" + placeholders + ")", ids)
        self.db.executemany("INSERT INTO tags VALUES (?,?,?)", tags)
        if Path(self.path).stat().st_size > MAX_BYTES:
            raise RuntimeError("Analytics detail cache exceeds size limit")

    def publish(self):
        self.db.commit()
        self.db.close()
        self.db = None
        if Path(self.path).stat().st_size > MAX_BYTES:
            raise RuntimeError("Analytics detail cache exceeds size limit")
        with open(self.path, "r+b") as data:
            os.fsync(data.fileno())
        os.replace(self.path, self.target)

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if os.path.exists(self.path):
            os.unlink(self.path)


def read_detail_cache(cfg, now, database, scope="online", os=None, skip=0, take=50,
                      kind=None, key=None, search=None, agent=None, provider=None, anomaly=None, allowlist=None, employeeExact=None):
    db = None
    try:
        path = cfg.DATA_ROOT / "analytics-detail.sqlite3"
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("oversized")
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        db.execute("PRAGMA temp_store=MEMORY")
        meta = dict(db.execute("SELECT key,value FROM meta"))
        if meta["format"] != "3" or meta["database"] != database:
            raise ValueError("invalid identity")
        from .analytics_cache import check_generation
        check_generation(cfg, database, meta.get('generation'))
        created = datetime.fromisoformat(meta["updatedAtUtc"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError("invalid timestamp")
        age = (now - created.astimezone(timezone.utc)).total_seconds()
        if age < -60:
            raise ValueError("future timestamp")
        where, params = [], []
        def tag(k, v="", negate=False):
            where.append(("NOT " if negate else "") +
                "EXISTS (SELECT 1 FROM tags t WHERE t.kind=? AND t.value=? AND t.device_id=d.id)")
            params.extend((k, v))
        if scope in ("online", "offline", "stale"):
            where.append("d.state=?"); params.append(scope)
        elif scope == "legacyclient":
            where.append("d.legacy=1")
        if os:
            where.append("instr(d.os,?)>0"); params.append(os.lower())
        if kind == "online":
            where.append("d.state='online'")
        elif kind in ("running", "anomaly", "everAnomaly", "otherUnproxied", "unknown"):
            tag(kind)
        elif kind == "tool" and key is None:
            tag("tool-null")
        elif kind in ("agent", "tool", "provider"):
            tag(kind, key or "")
        elif kind == "error":
            tag("error", (key or "").lower())
        elif kind == "allowlist":
            tag("allowlist-any" if key is None else "allowlist", "" if key is None else key)
        if search:
            needle = search.lower()
            if meta.get("searchIndex") == "fts5-trigram-v1" and len(needle) >= 3 and "\x00" not in needle:
                expression = '"' + needle.replace('"', '""') + '"'
                if use_search_index(db, expression):
                    where.append("d.rowid IN (SELECT rowid FROM search_fts WHERE search_fts MATCH ?)")
                    params.append(expression)
            where.append("EXISTS (SELECT 1 FROM json_each(d.searchable) WHERE instr(value,?)>0)")
            params.append(needle)
        if employeeExact:
            where.append("d.id IN (SELECT device_id FROM tags WHERE kind=? AND value=?)")
            params.extend(("employee", employeeExact.lower()))
        if agent: tag("agent", agent)
        if provider: tag("provider", provider)
        if anomaly == "latest": tag("anomaly")
        elif anomaly == "ever": tag("everAnomaly")
        elif anomaly == "none":
            tag("anomaly", negate=True); tag("observed")
        if allowlist: tag("allowlist-any" if allowlist == "any" else "allowlist", "" if allowlist == "any" else allowlist)
        clause = " WHERE " + " AND ".join(where) if where else ""
        skip, take = max(0, skip), min(500, max(1, take))
        if search:
            # Search can match most of the inventory. Count and page the small
            # rowids together, then load only the selected JSON views.
            page = db.execute("SELECT d.rowid,COUNT(*) OVER() FROM devices d" + clause +
                              " ORDER BY d.seen DESC,d.id LIMIT ? OFFSET ?", (*params, take, skip)).fetchall()
            if page:
                total = page[0][1]
                placeholders = ",".join("?" for _ in page)
                views = dict(db.execute("SELECT rowid,view FROM devices WHERE rowid IN (" + placeholders + ")",
                                        [row[0] for row in page]))
                rows = [(views[row[0]],) for row in page]
            else:
                total = db.execute("SELECT COUNT(*) FROM devices d" + clause, params).fetchone()[0]
                rows = []
        else:
            total = db.execute("SELECT COUNT(*) FROM devices d" + clause, params).fetchone()[0]
            rows = db.execute("SELECT d.view FROM devices d" + clause + " ORDER BY d.seen DESC,d.id LIMIT ? OFFSET ?",
                              (*params, take, skip)).fetchall()
        return dict(total=total, skip=skip, take=take, updatedAtUtc=timestamp(created),
                    cacheAgeSeconds=max(0, int(age)), cacheStale=age > 300,
                    devices=[json.loads(row[0]) for row in rows])
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ApiProblem("ANALYTICS_CACHE_UNAVAILABLE", "Analytics snapshot unavailable; run the refresh job.", 503) from None
    finally:
        if db is not None:
            db.close()
