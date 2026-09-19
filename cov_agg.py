#!/usr/bin/env python3
import glob, os, gzip, json, subprocess, collections

ROOT = '/home/rick/cqie_auth'
os.chdir(ROOT)
for f in glob.glob('*.gcov.json.gz'):
    os.remove(f)

agg = collections.defaultdict(dict)
n = 0
for d in sorted(glob.glob('/tmp/tmp.*')):
    for gno in sorted(glob.glob(d + '/*.gcno')):
        r = subprocess.run(['gcov', '-j', '-o', d, gno], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        n += 1
        jz = os.path.basename(gno)[:-5] + '.gcov.json.gz'  # 生成在 cwd
        if not os.path.exists(jz):
            print('缺失 json:', jz)
            continue
        with gzip.open(jz) as f:
            data = json.load(f)
        for fe in data.get('files', []):
            src = fe.get('file', '')
            if not src.startswith(ROOT + '/src/'):
                continue
            for line in fe.get('lines', []):
                ln = line.get('line_number')
                cnt = line.get('count', 0)
                if ln is None:
                    continue
                if cnt > agg[src].get(ln, 0):
                    agg[src][ln] = cnt
        os.remove(jz)

print(f'处理 gcno: {n}')
os.makedirs('/tmp/covreport', exist_ok=True)
total = covered = 0
for src in sorted(agg):
    rel = os.path.relpath(src, ROOT)
    lines = sorted(agg[src])
    cov = [l for l in lines if agg[src][l] > 0]
    miss = [l for l in lines if agg[src][l] == 0]
    total += len(lines); covered += len(cov)
    pct = len(cov) * 100 // len(lines) if lines else 100
    print(f'{rel}: {len(cov)}/{len(lines)} = {pct}%')
    with open(f'/tmp/covreport/{os.path.basename(src)}.missed', 'w') as f:
        f.write('\n'.join(map(str, miss)))
print(f'==== 总计: {covered}/{total} = {covered*100//total}% ====')
