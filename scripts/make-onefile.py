#!/usr/bin/env python3
"""Generate a source-complete Dockerfile; no credentials or runtime data."""
from pathlib import Path
import base64,hashlib,io,shlex,tarfile
root=Path(__file__).resolve().parent.parent
bundle=io.BytesIO()
with tarfile.open(fileobj=bundle,mode='w:gz',compresslevel=9) as archive:
 for p in sorted(root.rglob('*')):
  if not p.is_file():continue
  rel=p.relative_to(root)
  if any(s.startswith('.') for s in rel.parts) or rel.parts[0]=='github-single':continue
  if str(rel).startswith(('web/game-agent/game-route-agent-','web/edge-scan/aria-edge-scan-')):continue
  if p.suffix in ['.db','.sqlite','.pem','.key','.log']:raise RuntimeError('Unexpected private runtime file: '+str(rel))
  info=archive.gettarinfo(str(p),arcname=str(rel));info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
  with p.open('rb') as f:archive.addfile(info,f)
data=bundle.getvalue();encoded=base64.b64encode(data).decode();encoded='\n'.join(encoded[i:i+76] for i in range(0,len(encoded),76))
header='# syntax=docker/dockerfile:1.7\n# ariaatashin 4.11.0 — upload this file as Dockerfile at repository root.\n# Embedded source SHA256: '+hashlib.sha256(data).hexdigest()+'\nFROM alpine:3.22 AS source-bundle\nCOPY <<\'ARIA_SOURCE_411\' /bundle.b64\n'+encoded+'\nARIA_SOURCE_411\nRUN mkdir -p /src && base64 -d /bundle.b64 | tar -xzf - -C /src\n'
lines=[]
for line in (root/'Dockerfile').read_text().splitlines():
 if line.startswith('COPY ') and '--from=' not in line:
  args=shlex.split(line)[1:];line='COPY --from=source-bundle '+' '.join('/src/'+s for s in args[:-1])+' '+args[-1]
 lines.append(line)
out=root/'github-single'/'Dockerfile';out.parent.mkdir(exist_ok=True);out.write_text(header+'\n'+'\n'.join(lines)+'\n')
print(out,len(data),out.stat().st_size)
