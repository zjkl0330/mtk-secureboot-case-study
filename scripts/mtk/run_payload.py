import subprocess, sys, time, os
import serial.tools.list_ports as lp

ADB = r"F:\root\platform-tools\adb.exe"
MTK_DIR = r"F:\root\mtkclient-2.1.4.1"
LOG = r"F:\root\k9pro\Temp\payload_run.log"
TRACE = r"F:\root\k9pro\Temp\payload_trace.log"


def trace(msg):
    line = time.strftime("%H:%M:%S") + " " + msg
    print(line, flush=True)
    with open(TRACE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


open(TRACE, "w", encoding="utf-8").close()

baseline = {p.device for p in lp.comports()}
trace("baseline ports: %s" % (sorted(baseline) or "none"))

r = subprocess.run([ADB, "reboot", "edl"], capture_output=True, text=True)
trace("adb reboot edl rc=%d out=%r err=%r" % (r.returncode, r.stdout.strip(), r.stderr.strip()))

deadline = time.time() + 120
found = None
scans = 0
while time.time() < deadline:
    cur = list(lp.comports())
    new = [p for p in cur if p.device not in baseline]
    if new:
        found = new[0]
        trace("NEW PORT %s | %s | %s" % (found.device, found.description, found.hwid))
        break
    scans += 1
    if scans % 50 == 0:
        trace("scanning... %d (ports=%s)" % (scans, [p.device for p in cur] or "none"))
    time.sleep(0.08)

if not found:
    trace("RESULT: no new port within 120s")
    sys.exit(2)

port = found.device
trace("launching: mtk.py payload --serialport %s" % port)

with open(LOG, "w", encoding="utf-8", errors="replace") as f:
    try:
        p = subprocess.run(
            [sys.executable, "mtk.py", "payload", "--serialport", port],
            cwd=MTK_DIR, capture_output=True, text=True, errors="replace", timeout=240,
        )
        f.write("=== STDOUT ===\n" + p.stdout)
        f.write("\n=== STDERR ===\n" + p.stderr)
        f.write("\n=== RC=%d ===\n" % p.returncode)
        trace("mtk.py finished rc=%d" % p.returncode)
        tail = (p.stdout or "").strip().splitlines()[-8:]
        for t in tail:
            trace("  | " + t)
    except subprocess.TimeoutExpired:
        f.write("TIMEOUT after 240s\n")
        trace("mtk.py TIMEOUT")

trace("DONE, full log: %s" % LOG)
