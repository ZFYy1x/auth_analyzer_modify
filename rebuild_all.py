# -*- coding: utf-8 -*-
"""Full clean recompile of both branches + rebuild 4 jars (thin & with-dependencies)."""
import os, subprocess, glob, zipfile, shutil, sys

PYTHON_DIR = r"E:\git\auth_analyzer_modify"
BRANCHES = {
    "main":    {"dir": r"E:\git\auth_analyzer_modify",         "prefix": "auth_analyzer_modify"},
    "longfor": {"dir": r"E:\auth_analyzer_modify_longfor",     "prefix": "auth_analyzer_modify_longfor"},
}
JAVAC = r"D:\tools\BurpSuitepro\jdk-21.0.8\bin\javac"
JAVAP = r"D:\tools\BurpSuitepro\jdk-21.0.8\bin\javap"
M2 = r"C:\Users\w_zhangfeifei20\.m2\repository"
CP = ";".join([
    M2 + r"\com\google\code\gson\gson\2.8.6\gson-2.8.6.jar",
    M2 + r"\org\jsoup\jsoup\1.13.1\jsoup-1.13.1.jar",
    M2 + r"\net\portswigger\burp\extensions\montoya-api\2026.4\montoya-api-2026.4.jar",
])

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True)
    out = p.stdout.decode('gbk', errors='ignore') + p.stderr.decode('gbk', errors='ignore')
    return p.returncode, out

def recompile(tag, b):
    d = b["dir"]
    classes = os.path.join(d, "target", "classes")
    if os.path.exists(classes):
        shutil.rmtree(classes)
    os.makedirs(classes)
    srcs = glob.glob(os.path.join(d, "src", "**", "*.java"), recursive=True)
    slist = os.path.join(d, "target", "sources.txt")
    with open(slist, "w", encoding="utf-8") as f:
        f.write("\n".join(srcs))
    cmd = [JAVAC, "--release", "8", "-encoding", "UTF-8", "-cp", CP, "-d", classes, "@" + slist]
    rc, out = run(cmd, cwd=d)
    newcls = glob.glob(os.path.join(classes, "com", "protect7", "**", "*.class"), recursive=True)
    print("[%s] javac rc=%d sources=%d classes=%d" % (tag, rc, len(srcs), len(newcls)))
    if rc != 0 or not newcls:
        print(out[-4000:])
        sys.exit(1)
    return classes, len(srcs), len(newcls)

def rebuild_jars(tag, b, classes):
    d = b["dir"]
    tgt = os.path.join(d, "target")
    jars = {
        "thin": os.path.join(tgt, b["prefix"] + "-1.9.jar"),
        "deps": os.path.join(tgt, b["prefix"] + "-1.9-jar-with-dependencies.jar"),
    }
    report = {}
    for kind, jpath in jars.items():
        if not os.path.exists(jpath):
            print("[%s][%s] MISSING JAR %s" % (tag, kind, jpath)); sys.exit(1)
        tmp = jpath + ".new"
        old_protect7, old_other = [], []
        with zipfile.ZipFile(jpath) as z:
            for n in z.namelist():
                (old_protect7 if n.startswith("com/protect7/") else old_other).append(n)
            old_read = {n: z.read(n) for n in z.namelist()}
        # new compiled protect7 classes -> zip paths
        newcls = {}
        cbase = os.path.join(classes, "com", "protect7")
        for fp in glob.glob(os.path.join(cbase, "**", "*.class"), recursive=True):
            arc = "com/protect7/" + os.path.relpath(fp, cbase).replace("\\", "/")
            with open(fp, "rb") as f:
                newcls[arc] = f.read()
        dropped = sorted(set(old_protect7) - set(newcls))
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            # keep all non-protect7 entries verbatim (resources, MANIFEST, maven metadata, dep classes)
            for n in old_other:
                z.writestr(n, old_read[n])
            for arc in sorted(newcls):
                z.writestr(arc, newcls[arc])
        # verify
        with zipfile.ZipFile(tmp) as z:
            bad = z.testzip()
            names = set(z.namelist())
            assert bad is None, "bad entry %s" % bad
            assert names == (set(old_other) | set(newcls)), "entry set mismatch"
            for arc, data in newcls.items():
                assert z.read(arc) == data, "CRC mismatch %s" % arc
        shutil.move(tmp, jpath)
        report[kind] = dict(total=len(old_other) + len(newcls),
                            non_class=len(old_other),
                            protect7=len(newcls),
                            dropped_orphans=len(dropped))
        print("[%s][%s] rebuilt: total=%d keep=%d protect7=%d dropped_orphans=%d" %
              (tag, kind, report[kind]["total"], report[kind]["non_class"],
               report[kind]["protect7"], report[kind]["dropped_orphans"]))
        if dropped:
            print("    dropped:", ", ".join(dropped[:20]) + (" ..." if len(dropped) > 20 else ""))
    return report

def javap_check(tag, b):
    classes = os.path.join(b["dir"], "target", "classes")
    checks = [
        ("com.protect7.authanalyzer.util.DataImporter", ["prepare", "restoreRows", "ParsedSnapshot"]),
        ("com.protect7.authanalyzer.util.DataExporter", ["createSnapshot"]),
        ("com.protect7.authanalyzer.gui.main.ConfigurationPanel", ["restoreSessionsFromSnapshot", "markSessionListSynced", "applySessionConfigToPanel"]),
        ("com.protect7.authanalyzer.gui.main.CenterPanel", ["importBoardBackupAsync"]),
    ]
    ok = True
    for cls, syms in checks:
        rc, out = run([JAVAP, "-cp", classes, cls])
        if rc != 0:
            print("[%s] javap FAIL %s: %s" % (tag, cls, out[:300])); ok = False; continue
        for s in syms:
            found = s in out
            print("[%s] javap %-55s %-30s %s" % (tag, cls.split(".")[-1], s, "OK" if found else "MISSING"))
            if not found: ok = False
    return ok

if __name__ == "__main__":
    for tag, b in BRANCHES.items():
        classes, nsrc, ncls = recompile(tag, b)
        rebuild_jars(tag, b, classes)
        print()
    print("=== javap verification ===")
    allok = True
    for tag, b in BRANCHES.items():
        allok &= javap_check(tag, b)
    print("=== DONE, all checks:", "PASS" if allok else "FAIL", "===")
