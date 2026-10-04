#!/usr/bin/env python3
"""Read-only structural audit; never serialize proxy objects or credentials."""
import hashlib,json,pathlib,re,subprocess,sys
import yaml
HERE=pathlib.Path(__file__).parent
SOURCE=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
EXPECTED='6d11128415287b191dff62c1d28095e01b4d559ef57847c78f188077b9c411a1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert not (HERE/'AUDIT.json').exists()
 x=yaml.safe_load(SOURCE.read_bytes())
 pids=subprocess.check_output(['pgrep','-x','verge-mihomo'],text=True).split()
 process_matches=[]
 for pid in pids:
  raw=subprocess.check_output(['ps','-p',pid,'-o','command='],text=True).strip()
  d=re.search(r' -d (.*?) -f ',raw);f=re.search(r' -f (.*?) -ext-ctl-unix ',raw)
  process_matches.append(bool(d and f and d.group(1)==str(SOURCE.parent) and f.group(1)==str(SOURCE)))
 groups=x.get('proxy-groups') or []
 proxy_group=[g for g in groups if g.get('name')=='PROXY']
 proxies=x.get('proxies') or []
 names=[p.get('name') for p in proxies]
 rules=x.get('rules') or []
 checks={'source_sha_locked':sha(SOURCE)==EXPECTED,'active_process_uses_source':len(process_matches)==1 and process_matches[0],'rule_mode':x.get('mode')=='rule','source_has_local_proxy_objects':len(proxies)>0 and all(p.get('name') and p.get('server') and p.get('port') and p.get('type') for p in proxies),'proxy_names_unique':len(names)==len(set(names)),'no_external_proxy_providers':not x.get('proxy-providers'),'no_proxy_external_file_references':not any(any('file' in k.lower() or 'path' in k.lower() or 'certificate' in k.lower() or 'private-key' in k.lower() for k in p) for p in proxies),'select_group_present':len(proxy_group)==1 and proxy_group[0].get('type')=='select','current_geoip_before_match':len(rules)>=2 and rules[-2]=='GEOIP,CN,DIRECT' and rules[-1]=='MATCH,PROXY','no_existing_gz02_exact_rule':not any('1.95.90.207' in r for r in rules),'source_has_prepend_rules':bool(x.get('prepend-rules')),'source_has_healthcheck_groups':any(g.get('type') in ('url-test','fallback','load-balance') for g in groups),'source_has_global_controller_unix':bool(x.get('external-controller-unix')),'source_has_dns_enabled':bool((x.get('dns') or {}).get('enable'))}
 required=['source_sha_locked','active_process_uses_source','rule_mode','source_has_local_proxy_objects','proxy_names_unique','no_external_proxy_providers','no_proxy_external_file_references','select_group_present','current_geoip_before_match','no_existing_gz02_exact_rule']
 out={'schema':'g279-private-mihomo-source-audit-v1','source_sha256':sha(SOURCE),'source_size':SOURCE.stat().st_size,'binary_sha256':'c15a8c12c461404f3f09368146538c5d32b1b728cd5e1b28885c103ffd7ed9d0','rules_count':len(rules),'proxy_object_count':len(proxies),'proxy_group_count':len(groups),'checks':checks,'required_checks_pass':all(checks[k] for k in required),'source_contains_sensitive_credentials':True,'credentials_serialized':False,'network_probe':False,'gz02_connection':False,'proxy_instance_started':False}
 with (HERE/'AUDIT.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'required_checks_pass':out['required_checks_pass'],'checks':checks,'source_sha256':out['source_sha256']}))
 return 0 if out['required_checks_pass'] else 2
if __name__=='__main__':sys.exit(main())
