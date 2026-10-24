"""Operator commands. Approval and execution run outside scanning containers."""
import argparse
import json
import os
from pathlib import Path
import secrets
from .security import load_key, safe_read
from .response import approve, execute
from .benchmark import benchmark
from .demo import demo


def read_json(path):
    path=Path(path).absolute()
    return json.loads(safe_read(path.parent,path.name,32_000_000))


def main():
    parser=argparse.ArgumentParser(prog='seere-control')
    commands=parser.add_subparsers(dest='command',required=True)
    init=commands.add_parser('init');init.add_argument('directory')
    bench=commands.add_parser('benchmark');bench.add_argument('--output',required=True)
    demonstration=commands.add_parser('demo');demonstration.add_argument('directory')
    approval=commands.add_parser('approve');approval.add_argument('--plan',required=True);approval.add_argument('--approver',required=True)
    approval.add_argument('--approval-key',required=True);approval.add_argument('--output',required=True)
    apply=commands.add_parser('apply');apply.add_argument('--plan',required=True);apply.add_argument('--approval',required=True)
    apply.add_argument('--approval-key',required=True);apply.add_argument('--fingerprint-key',required=True)
    apply.add_argument('--authorized-root',required=True);apply.add_argument('--audit-dir',required=True)
    args=parser.parse_args()
    if args.command=='init':
        base=Path(args.directory).absolute()
        base.mkdir(parents=True,exist_ok=True)
        for folder in ['reports/code','reports/local','reports/rag','reports/runtime','plan','scope/code','scope/local','scope/rag','scope/runtime']:
            (base/folder).mkdir(parents=True,exist_ok=True)
        load_key(base/'.seere/fingerprint.key')
        manifest={'schema_version':1,'run_id':secrets.token_hex(16),'expected_modules':['code','local','rag','runtime']}
        with (base/'manifest.json').open('x') as out:json.dump(manifest,out,indent=2)
        print('Created a fresh run manifest and fingerprint key. Keep human approval keys outside this directory.')
    elif args.command=='benchmark':
        Path(args.output).write_text(json.dumps(benchmark(secrets.token_bytes(32)),indent=2))
    elif args.command=='demo':
        result=demo(args.directory)
        print(json.dumps(result['verification'],indent=2))
    elif args.command=='approve':
        plan=read_json(args.plan)
        # Human invokes this exact command after reviewing the plan. Agents have no access to this key.
        signature=approve(plan,args.approver,load_key(args.approval_key))
        Path(args.output).write_text(json.dumps(signature,indent=2))
    else:
        result=execute(read_json(args.plan),read_json(args.approval),load_key(args.approval_key),
            load_key(args.fingerprint_key),args.authorized_root,args.audit_dir)
        print(json.dumps(result,indent=2))

if __name__=='__main__':main()
