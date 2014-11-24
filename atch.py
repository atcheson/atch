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
VERBOSITY = 0
ARG_DELIMITER = ':'

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
        if head in hooktree[0]:
            traverse_hooktree(hook, hooktree[0][head], tail)
        else:
            hooktree[0][head] = traverse_hooktree(hook, (dict(), []), tail)
    else:
        if head in hooktree[0]:
            hooktree[0][head].append(hook)
        else:
            hooktree[0][head] = (None, [hook])

    return hooktree


def build_hooktree(hookindex, when):
    hooktree = (dict(), [])
    for hook in hookindex:
        try:
            hook_to = sep_commas(hookindex[hook][when])
        except KeyError:
            continue
        for cmd in hook_to:
           hooktree = traverse_hooktree(hookindex[hook], hooktree, cmd)
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
    filepath = path.abspath(__file__)

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


def load_hooks(when, hooks_file=path.join(atch_root, 'atchhooks')):
    try:
        with open(hooks_file, 'r') as f:
            return pickle.load(f)
    except (EOFError, IOError):
        return update_hooks(when, hooks_file)


def usage():
    print("usage info goes here")


def cmd_not_found():
    print("deal with missing commands here")


def runtime_substitution(inv_str, passed_args):
    for f in  re.finditer(r'\$(\d+)', inv_str):
        argument = passed_args[f.groups()[1:]]
        inv_str = inv_str[:f.start()] + argument + inv_str[:f.end()]
    return inv_str


def invoke(cmd, passed_args):
    pdb.set_trace()
    inv_str = runtime_substitution(cmd['invoke'], passed_args)
    vprint(inv_str, 2)
    subprocess.call(inv_str, shell=True)


def run_hooks(hooktree, passed_args):
    for hook in hooktree[1]:
        invoke(hook, passed_args)


def tree_select(tree, key):
    if key in tree:
        return tree[key]
    else:
        return None


def main():
    
    if len(sys.argv) == 0:
        usage()
        exit(1)
    
    passed_args = []
    cmd = load_index()
    beforehooks = load_hooks('before')
    afterhooks = load_hooks('after')
    args = sys.argv[1:]
    try:
        for arg_no, arg in enumerate(args):
            if cmd == ARG_DELIMITER:
                passed_args = args[arg_no + 1:]
            if cmd and not passed_args:
                cmd = tree_select(cmd, arg)
            if not cmd:
                if not passed_args:
                    passed_args = args[arg_no:]
            if afterhooks: 
                afterhooks = tree_select(afterhooks[0], arg)
            if beforehooks:
                beforehooks = tree_select(beforehooks[0], arg)
    except KeyError:
        pass

    if beforehooks:
        run_hooks(beforehooks, passed_args)
    if cmd:
        invoke(cmd, passed_args)
    if afterhooks:
        run_hooks(afterhooks, passed_args)

    if not beforehooks and not afterhooks and not cmd:
        cmd_not_found()

    exit(0)
    

if __name__ == '__main__':
    main()
