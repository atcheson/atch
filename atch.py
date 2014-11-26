import os.path as path
import os
import sys
import pdb
import re
import pickle
import subprocess
import json

signal_str = re.compile(r"^.*\|----->(.*)$") 
atch_root = os.path.dirname(os.path.abspath(__file__))

IGNORE_EXTENSIONS = ['.swp', '.pyc']
VERBOSITY = 2
ARG_DELIMITER = ':'
SAFE_COMMANDS = ['recover']
ATCH_SOURCE = ['source']
WHEN_SEPCHAR = '_'
LIST_SEP= ','
SCRIPTS_DIR = 'plugins'
WILDCARD = '*'
MAX_SUBSTITUTION_ITERATIONS = 10

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


def sep_list(str_list):
    return [x.strip() for x in str_list.split(LIST_SEP)]
   

def build_index(dirpath, atch_type, atch_path, subs=None):
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
                atchcmds['invoke'] = \
                    do_subs(atchcmds, atch_path, 'index', abspath, subs)
            try:
                if atch_type in sep_list(atchcmds['atch']):
                    for name in sep_list(atchcmds['names']):
                        index[name] = atchcmds
            except KeyError as e:
                vprint("no atch_type in: \n" + repr(atchcmds) , 2)

        elif path.isdir(abspath):
            subindex = \
                    build_index(abspath, atch_type, atch_path + [relpath])
            if subindex:
                index[path.basename(abspath)] = subindex
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
            hooktree[0][head][1].append(hook)
        else:
            hooktree[0][head] = (None, [hook])

    return hooktree


def get_hooks_from_index(hookindex):
    hooks = []
    for subindex_name in hookindex:
        subindex = hookindex[subindex_name]
        if 'atch' in subindex:
            hooks.append(subindex)
        else:
            hooks = hooks + get_hooks_from_index(subindex)
    return hooks


def build_hooktree(hookindex, when):
    hooktree = (dict(), [])
    hooks = get_hooks_from_index(hookindex)
    for hook in hooks:
        try:
            hook_to = sep_list(hook[when])
        except KeyError:
            continue
        for cmd in hook_to:
            hooktree = traverse_hooktree(hook, hooktree, cmd)
    return hooktree



def update_hooks(when, hooks_file=path.join(atch_root, 'hooks')):
    vprint("updating " + when + " hooks...", 1)
    with open(get_when_filename(hooks_file, when), 'wb') as f:
        hook_index = build_index(path.join(atch_root, SCRIPTS_DIR) \
                , atch_type = 'hook', atch_path = [])
        hooks = build_hooktree(hook_index, when)
        pickle.dump(hooks, f)
        return hooks


def update_index(index_file=path.join(atch_root, 'index')):
    vprint("updating index...", 1)
    with open(index_file, 'wb') as f:
        index = build_index(path.join(atch_root, SCRIPTS_DIR) \
                , atch_type = 'script', atch_path = [])
        pickle.dump(index, f)
        return index


def update_subs_singlepass(when, subs_file, subs):
     with open(get_when_filename(subs_file, when), 'wb') as f:
        subs_index = build_index(path.join(atch_root, SCRIPTS_DIR) \
                , atch_type = 'substitution', atch_path = [])
        subs = build_hooktree(subs_index, when)
        pickle.dump(subs, f)
        return subs


def update_subs(when, subs_file=path.join(atch_root, 'substitutions')):
    vprint("updating " + when + " substitutions...", 1)
    old_subs = ({}, [])
    subs = update_subs_singlepass(when, subs_file, old_subs)
    if when == 'index':
        count = 0
        pdb.set_trace()
        while old_subs != subs: # TODO: ensure this is a real deep comparison
            count += 1
            if count == MAX_SUBSTITUTION_ITERATIONS:
                raise Exception("max substitutions reached")
            old_subs = subs
            subs = update_subs_singlepass(when, subs_file, old_subs)
    return subs


def get_source_path():
    filepath = path.abspath(__file__)

    if filepath.endswith('.pyc') and os.path.exists(filepath[:-1]):
        filepath = filepath[:-1]

    return filepath


def build_subst_info(inv_str, params, abspath, subst_path):
    info = dict()
    info['inv_str'] = inv_str
    info['params'] = params
    info['abspath'] = abspath
    info['subst_path'] = subst_path
    return json.dumps(info)


def run_subs(inv_str, atch_path, when, params=None, abspath=None, subs=None):
    if not subs:
        subtree = load_subs(when)
    else:
        subtree = subs
    if not subtree:
        return inv_str

    wild = False
    for key in atch_path:
        if subtree[0] and (key in subtree[0]) and not wild:
            subtree = subtree[0][key]
        elif subtree[0] and (WILDCARD in subtree[0]):
            wild = True
            subtree = subtree[0][WILDCARD]
        elif not wild:
            subtree = None

    if not subtree or not subtree[1]:
        return inv_str

    for sub in subtree[1]:

        p = subprocess.Popen(sub['invoke'], \
            stdin = subprocess.PIPE, \
            stdout = subprocess.PIPE, \
            shell = True)

        p.stdin.write(build_subst_info(inv_str, \
                                       params, \
                                       abspath, \
                                       sub['abspath']))

        p.stdin.close()
        p.wait()
        inv_str = p.stdout.read()

    #inv_str = cmd['invoke']
    #inv_str = re.sub(r'\$atch_fcn "(.*)"', \
            #"""python -c "import imp; """
            #"""atch = imp.load_source('atch', '"""  
               #+ get_source_path() + "'); " + r'\1' + '"', inv_str)   
    #inv_str = re.sub(r"\$this", cmd['abspath'], inv_str)
    #inv_str = re.sub(r" \./", ' ' + path.dirname(cmd['abspath']) + '/', inv_str)
    #inv_str = re.sub(r"\$atch_root", atch_root, inv_str)

    return inv_str


def do_subs(inv_str, atch_path, when, params=None, abspath=None, subs=None):
    old_inv_str = None
    count = 0
    while old_inv_str != inv_str:
        count += 1
        if count == MAX_SUBSTITUTION_ITERATIONS:
            raise Exception("max substitutions reached")
        old_inv_str = inv_str
        inv_str = run_subs(inv_str, 
                           atch_path, 
                           when, 
                           params, 
                           abspath,
                           subs)

    return inv_str



def load_index(index_file=path.join(atch_root, 'index')):
    try:
        with open(index_file, 'r') as f:
            return pickle.load(f)
    except (EOFError, IOError):
        return update_index(index_file)


def load_subs(when, subs_file=path.join(atch_root, 'substitutions')):
    try:
        with open(get_when_filename(subs_file, when), 'r') as f:
            return pickle.load(f)
    except (EOFError, IOError):   
        return update_subs(when, subs_file)


def load_hooks(when, hooks_file=path.join(atch_root, 'hooks')):
    try:
        with open(get_when_filename(hooks_file, when), 'r') as f:
            return pickle.load(f)
    except (EOFError, IOError):
        return update_hooks(when, hooks_file)


def get_when_filename(hooks_file, when):
    return hooks_file + WHEN_SEPCHAR + when


def usage():
    print("usage info goes here")


def cmd_not_found():
    print("deal with missing commands here")


#def runtime_substitution(inv_str, passed_args):
    #for f in  re.finditer(r'\$(\d+)', inv_str):
        #argindex = f.groups()[0]
        #if len(passed_args) >= argindex:
            #argument = passed_args[argindex-1]
        #else:
            #argument = ''
        #new_inv_str = inv_str[:f.start()] + argument + inv_str[f.end():]
    #return new_inv_str


def invoke(cmd, passed_args, atch_path, sub):
    try:
        inv_str = cmd['invoke']
    except KeyError:
        return False

    if sub:
        inv_str = do_subs(cmd['invoke'], 
                          atch_path, 
                          'runtime', 
                          passed_args, 
                          cmd['abspath'])



    vprint(inv_str, 2)
    subprocess.call(inv_str, shell=True)


def run_hooks(hooktree, passed_args):
    for hook in hooktree[1]:
        invoke(hook, passed_args, None, False)


def main():

    if len(sys.argv) == 0:
        usage()
        exit(1)
    
    args = sys.argv[1:]
    
    did_something = False
    if ' '.join(args) in SAFE_COMMANDS:
        did_something = True
        update_subs('index')
        update_subs('runtime')
        update_hooks('before')
        update_hooks('after')
        update_index()

    if ' '.join(args) in ATCH_SOURCE:
        did_something = True
        sys.stdout.write(get_source_path())

    passed_args = []
    cmd = load_index()
    beforehooks = load_hooks('before')
    afterhooks = load_hooks('after')
    atch_path = []
    before_wild = False
    after_wild = False

    for arg_no, arg in enumerate(args):
        if cmd and (arg in cmd) and not passed_args:
            atch_path.append(arg)
            cmd = cmd[arg]
        else:
            passed_args = args[arg_no:]

        if beforehooks and arg in beforehooks[0] and not before_wild:
            beforehooks = beforehooks[0][arg]
        elif beforehooks and  (WILDCARD in beforehooks):
            before_wild = True
        else:
            beforehooks = None

        if afterhooks and arg in afterhooks[0] and not after_wild:
            afterhooks = afterhooks[0][arg]
        elif afterhooks and (WILDCARD in afterhooks):
            after_wild = True
        else:
            afterhooks = None

    if beforehooks:
        did_something = True
        run_hooks(beforehooks, passed_args)
    if cmd:
        did_something = invoke(cmd, passed_args, atch_path, True) or did_something
    if afterhooks:
        did_something = True
        run_hooks(afterhooks, passed_args)

    if not did_something:
        cmd_not_found()

    exit(0)
    

if __name__ == '__main__':
    main()
