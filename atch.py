import os.path as path
import os
import sys
import pdb
import re
import pickle
import subprocess

signal_str = re.compile(r"^.*\|----->(.*)$") 
atch_root = os.path.dirname(os.path.abspath(__file__))

IGNORE_EXTENSIONS = ['.swp']
VERBOSITY = 1

def scan_file(filepath):
    atchcmds = dict()
    with open(filepath) as f:
        for line in f:
            match = signal_str.match(line)
            if match:
                (cmd, params) = match.group(1).split(':', 1)
                atchcmds[cmd.strip()] = params.strip()
    return atchcmds


def vprint(string, level=1):
    if VERBOSITY >= level:
        print string


def sep_commas(str_list):
    return [x.strip() for x in str_list.split(',')]
   

def build_index(dirpath, atch_type):
    index = dict()
    for relpath in os.listdir(dirpath):
        abspath = path.join(dirpath, relpath)
        if path.isfile(abspath):
            (_, ext) = path.splitext(abspath)
            if ext in IGNORE_EXTENSIONS:
                continue

            atchcmds = scan_file(abspath)
            atchcmds['abspath'] = abspath

            if 'invoke' in atchcmds:
                atchcmds['invoke'] = run_inv_subs(atchcmds)

            if atch_type in sep_commas(atchcmds['atch']):
                for name in sep_commas(atchcmds['names']):
                    index[name] = atchcmds

        elif path.isdir(abspath):
            subindex = build_index(abspath, atch_type)
            if subindex:
                index[path.basename(abspath)] = build_index(abspath, atch_type)
    return index


def traverse_hooktree(hook, hooktree, cmd):

    if ' ' in cmd:
        (head, tail) = cmd.split(None, 1)
    else:
        head = cmd
        tail = False
    
    if tail:
        if head in hooktree:
            traverse_hooktree(hook, hooktree[0][head], tail)
        else:
            hooktree[0][head] = traverse_hooktree(hook, (dict(), []), tail)
    else:
        if head in hooktree:
            hooktree[0][head].append(hook)
        else:
            hooktree[0][head] = (None, [hook])
    return hooktree 


def build_hooktree(hookindex, when):
    for hook in hookindex:
        try:
            hook_to = sep_commas(hookindex[hook][when])
        except KeyError:
            continue
        for cmd in hook_to:
           hooktree =  traverse_hooktree(hookindex[hook], (dict(), []) , cmd)
    return hooktree



def update_hooks(when, hooks_file=path.join(atch_root, 'atchhooks')):
    vprint("updating atch hooks...", 1)
    with open(hooks_file, 'wb') as f:
        hook_index = build_index(path.join(atch_root, 'scripts') \
                , atch_type = 'hook')
        hooks = build_hooktree(hook_index, when)
        pickle.dump(hooks, f)
        return hooks


def update_index(index_file=path.join(atch_root, 'atchindex')):
    vprint("updating atch index...", 1)
    with open(index_file, 'wb') as f:
        index = build_index(path.join(atch_root, 'scripts',) \
                , atch_type = 'script')
        pickle.dump(index, f)
        return index


def get_source_path():
    filepath = __file__

    if filepath.endswith('.pyc') and os.path.exists(filepath[:-1]):
        filepath = filepath[:-1]

    return filepath

def run_inv_subs(cmd):
    inv_str = cmd['invoke']
    inv_str = re.sub(r'\$atch_fcn "(.*)"', \
            """python -c "import imp; """
            """atch = imp.load_source('atch', '"""  
               + get_source_path() + "'); " + r'\1' + '"', inv_str)   
    inv_str = re.sub(r"\$this", cmd['abspath'], inv_str)
    inv_str = re.sub(r" \./", ' ' + path.dirname(cmd['abspath']) + '/', inv_str)
    inv_str = re.sub(r"\$atch_root", atch_root, inv_str)
    vprint(inv_str, 2)
    return inv_str


def load_index(index_file=path.join(atch_root, 'atchindex')):
    try:
        with open(index_file, 'r') as f:
            return pickle.load(f)
    except (EOFError, IOError):
        return update_index(index_file)


def load_hooks(hooks_file=path.join(atch_root, 'atchhooks')):
    return load_index(hooks_file)


def usage():
    print("usage info goes here")


def cmd_not_found(cmd):
    print("deal with missing commands here")


def invoke(cmd):
    inv_str = cmd['invoke']
    vprint(inv_str, 2)
    subprocess.call(inv_str, shell=True)


def main():
    if len(sys.argv) == 0:
        usage()
        exit(1)

    cmd = load_index()
    try:
        for arg in sys.argv[1:]:
            cmd = cmd[arg]
    except KeyError:
        pass

    try:
        atch_type = cmd['atch']
    except (KeyError, IndexError) as e:
        cmd_not_found(cmd)
        exit(1)

    if atch_type == 'script':
        invoke(cmd)
        exit(0)
    
    cmd_not_found(cmd)
    exit(1)

if __name__ == '__main__':
    main()
