import json, sys, os
os.chdir(os.path.expanduser('~/dev/tmp/die-macos-work/evidence'))
for fn in ['cli-matrix-candidate.json','cli-baseline-candidate.json','cli-database-candidate.json','cli-filesystem-candidate.json','cli-large-directory-candidate.json','cli-path-nested-candidate.json','cli-remaining-candidate.json','cli-toctou-candidate.json','long-path-fixture-candidate.json']:
    try:
        d = json.load(open(fn))
    except Exception as e:
        print(f'{fn}: ERROR {e}'); continue
    adm = d.get('admission', {})
    cases = d.get('cases', {})
    print(f'{fn}: platform_admitted={adm.get("platform_admitted")} reason={adm.get("reason","")[:80]} rows={len(cases)}')