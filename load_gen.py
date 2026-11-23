"""Background load: appends real Zeek conn records (new uid each) at a fixed rate. Supplementary run only."""
import json, random, sys, time
src, dst, rate, dur = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
base = [json.loads(l) for l in open(src)]
n, t_end = 0, time.time() + dur
with open(dst, "a") as f:
    while time.time() < t_end:
        t = time.time()
        for _ in range(rate // 10):
            r = dict(random.choice(base)); r["uid"] = f"Cload{n:08d}"; r["ts"] = time.time(); n += 1
            f.write(json.dumps(r) + "\n")
        f.flush()
        time.sleep(max(0, 0.1 - (time.time() - t)))
print(f"load_gen wrote {n} records in {dur}s (~{n//dur}/s)")
