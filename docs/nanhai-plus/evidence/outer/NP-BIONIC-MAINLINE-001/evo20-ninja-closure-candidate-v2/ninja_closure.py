#!/usr/bin/env python3
"""Read-only lexical Ninja include/subninja closure screen; never executes actions."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import errno

FORBIDDEN = re.compile(r'(?<![A-Za-z0-9_])(?:docker|podman|nerdctl|buildah|runc|crun|nsjail|proot|chroot|unshare|bwrap|bubblewrap|firejail|systemd-nspawn|lxc-[A-Za-z0-9_-]+)(?![A-Za-z0-9_])', re.I)
EDGE = re.compile(r'^\s*(include|subninja)(?:\s+(.*))?$')
COMMAND = re.compile(r'^\s*command\s*=\s*(.*)$')
MAX_FILES = 100000
MAX_BYTES = 512 * 1024 * 1024
UNSAFE_SHELL = re.compile(r"['\"\\`?*;|&()<>\[\]{}]")

class Refusal(Exception):
    def __init__(self, reason, path, line=None):
        self.reason,self.path,self.line=reason,str(path),line

def sha_bytes(raw):return hashlib.sha256(raw).hexdigest()

def identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def read_confined(root_fd, root, path, remaining):
    """Open every component from a pinned OUT fd with NOFOLLOW, then recheck identity."""
    parts=path.relative_to(root).parts
    if not parts:raise Refusal('NOT_REGULAR_FILE',path)
    opened=[];parent_fd=root_fd
    try:
        for part in parts[:-1]:
            try:
                before=os.stat(part,dir_fd=parent_fd,follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):raise Refusal('SYMLINK_PATH',path)
                fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
                if identity(before)!=identity(os.fstat(fd)):raise Refusal('PATH_CHANGED',path)
            except FileNotFoundError:raise Refusal('MISSING_INCLUDE',path)
            except OSError as exc:raise Refusal('OPEN_REFUSED_'+str(exc.errno),path)
            opened.append((parent_fd,part,fd));parent_fd=fd
        try:
            before=os.stat(parts[-1],dir_fd=parent_fd,follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):raise Refusal('SYMLINK_PATH',path)
            if not stat.S_ISREG(before.st_mode):raise Refusal('NOT_REGULAR_FILE',path)
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent_fd)
        except FileNotFoundError:raise Refusal('MISSING_INCLUDE',path)
        except OSError as exc:raise Refusal('OPEN_REFUSED_'+str(exc.errno),path)
        try:
            initial=os.fstat(fd)
            if identity(before)!=identity(initial):raise Refusal('PATH_CHANGED',path)
            if initial.st_size>remaining:raise Refusal('BYTE_LIMIT',path)
            raw=bytearray()
            while True:
                block=os.read(fd,min(1048576,remaining+1-len(raw)))
                if not block:break
                raw.extend(block)
                if len(raw)>remaining:raise Refusal('BYTE_LIMIT',path)
            after=os.fstat(fd)
            try:named=os.stat(parts[-1],dir_fd=parent_fd,follow_symlinks=False)
            except OSError:raise Refusal('FILE_CHANGED_DURING_READ',path)
            if identity(initial)!=identity(after) or identity(after)!=identity(named) or len(raw)!=after.st_size:
                raise Refusal('FILE_CHANGED_DURING_READ',path)
            for parent,part,directory_fd in opened:
                try:named_directory=os.stat(part,dir_fd=parent,follow_symlinks=False)
                except OSError:raise Refusal('DIRECTORY_CHANGED_DURING_READ',path)
                if identity(named_directory)!=identity(os.fstat(directory_fd)):
                    raise Refusal('DIRECTORY_CHANGED_DURING_READ',path)
            return bytes(raw)
        finally:os.close(fd)
    finally:
        for _,_,fd in reversed(opened):os.close(fd)

def audit(out_root, top):
    root=pathlib.Path(out_root)
    if not root.is_absolute() or not root.is_dir():
        return {'status':'FAIL_CLOSED','rc':2,'failure':{'reason':'OUT_ROOT_INVALID','path':str(root),'line':None},'files':[],'file_count':0,'target_execution_authorized':False}
    root=pathlib.Path(os.path.normpath(root))
    try:root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except OSError:
        return {'status':'FAIL_CLOSED','rc':2,'failure':{'reason':'OUT_ROOT_OPEN_REFUSED','path':str(root),'line':None},'files':[],'file_count':0,'target_execution_authorized':False}
    root_initial=identity(os.fstat(root_fd))
    top=pathlib.Path(top)
    if not top.is_absolute():top=root/top
    top=pathlib.Path(os.path.normpath(top))
    files=[];seen=set();active=[];total=0;first=None

    def inside(path):
        try:path.relative_to(root);return True
        except ValueError:return False

    def visit(path):
        nonlocal total,first
        path=pathlib.Path(path)
        if not inside(path):raise Refusal('OUT_ESCAPE',path)
        if path in active:raise Refusal('INCLUDE_CYCLE',path)
        if path in seen:return
        if len(seen)>=MAX_FILES:raise Refusal('FILE_LIMIT',path)
        raw=read_confined(root_fd,root,path,MAX_BYTES-total);total+=len(raw)
        try:content=raw.decode('utf-8')
        except UnicodeDecodeError:raise Refusal('NON_UTF8_NINJA',path)
        seen.add(path);active.append(path)
        files.append({'path':str(path.relative_to(root)),'sha256':sha_bytes(raw),'bytes':len(raw)})
        lines=content.splitlines()
        i=0
        while i<len(lines):
            line=lines[i];number=i+1
            if line.lstrip().startswith('#'):
                i+=1;continue
            edge=EDGE.match(line)
            if edge:
                value=(edge.group(2) or '').strip()
                if not value or '$' in value:raise Refusal('VARIABLE_OR_EMPTY_INCLUDE',path,number)
                if any(c.isspace() for c in value) or '#' in value or '\x00' in value:raise Refusal('AMBIGUOUS_INCLUDE',path,number)
                child=path.parent/value
                if child.is_absolute() and not inside(child):raise Refusal('OUT_ESCAPE',path,number)
                # Lexical normalization only. The component loop then rejects symlinks.
                child=pathlib.Path(os.path.normpath(child))
                if not inside(child):raise Refusal('OUT_ESCAPE',path,number)
                visit(child)
                i+=1;continue
            if re.match(r'^\s*(?:include|subninja)\b',line):raise Refusal('MALFORMED_INCLUDE',path,number)
            command=COMMAND.match(line)
            if command:
                fragment=command.group(1);start=number
                while fragment.endswith('$') and (len(fragment)-len(fragment.rstrip('$')))%2 and i+1<len(lines):
                    fragment=fragment[:-1]+lines[i+1].lstrip();i+=1
                hit=FORBIDDEN.search(fragment)
                if hit and first is None:
                    first={'path':str(path.relative_to(root)),'line':start,'fragment':fragment[:500],'token':hit.group(0)}
                if '$' in fragment or UNSAFE_SHELL.search(fragment):
                    raise Refusal('DYNAMIC_OR_SHELL_COMPOSITION_COMMAND',path,start)
            i+=1
        active.pop()

    try:
        visit(top)
        try:root_named=os.stat(root,follow_symlinks=False)
        except OSError:raise Refusal('OUT_ROOT_CHANGED_DURING_READ',root)
        if identity(os.fstat(root_fd))!=root_initial or identity(root_named)!=root_initial:
            raise Refusal('OUT_ROOT_CHANGED_DURING_READ',root)
        status='FORBIDDEN_COMMAND' if first else 'PASS_LITERAL_CLOSURE_ONLY'
        return {'status':status,'rc':2 if first else 0,'out_root':str(root),'top':str(top),'files':files,'file_count':len(files),'total_file_bytes':total,'first_forbidden':first,'failure':None,'target_execution_authorized':False,'scope':'read-only lexical command screen only; dynamic Ninja variables and target reachability not proven'}
    except Refusal as exc:
        return {'status':'FAIL_CLOSED','rc':2,'out_root':str(root),'top':str(top),'files':files,'file_count':len(files),'total_file_bytes':total,'first_forbidden':first,'failure':{'reason':exc.reason,'path':exc.path,'line':exc.line},'target_execution_authorized':False,'scope':'read-only lexical command screen only; dynamic Ninja variables and target reachability not proven'}
    finally:os.close(root_fd)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--top',required=True)
    args=parser.parse_args()
    root=os.environ.get('NANHAI_OUT_ROOT')
    if not root:
        print(json.dumps({'status':'FAIL_CLOSED','rc':2,'failure':{'reason':'NANHAI_OUT_ROOT_MISSING'}}));return 2
    result=audit(root,args.top)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    return result['rc']
if __name__=='__main__':sys.exit(main())
