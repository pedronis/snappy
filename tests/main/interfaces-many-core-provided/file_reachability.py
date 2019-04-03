#!/usr/bin/python3
import argparse
import glob
import json
import os
import re
import sys


# these are directories or symlinks to directores that snap-confine
# bind mounts eagerly from the host!
EAGER_BIND_MOUNTS = {
    '/dev',
    '/etc',
    '/home',
    '/root',
    '/sys',
    '/tmp',
    '/var/snap',
    '/var/lib/snapd',
    '/var/tmp',
    '/run',
    '/var/run',
    '/lib/modules',
    '/usr/src',
    '/var/log',
    '/media',
    '/mnt',
    '/var/lib/extrausers',
}


def eagerly_bind_mounted(p):
    segs = p.split('/')
    for pfx_segs in range(2, 5):
        if '/'.join(segs[:pfx_segs]) in EAGER_BIND_MOUNTS:
            return True
    return False


def warn(msg):
    print('W: '+msg, file=sys.stderr)


class FileReachability:

    mounted_base = None

    CACHE = 'file_reachability.cache'

    _cache = {}

    @classmethod
    def load_cache(cls):
        if os.path.exists(cls.CACHE):
            with open(cls.CACHE) as f:
                cls._cache = json.load(f)

    @classmethod
    def save_cache(cls):
        with open(cls.CACHE, 'w') as f:
            json.dump(cls._cache, f)

    def _cached(self, g):
        key = g
        if self.write_only:
            key = 'wo:' + g
        from_cache = self._cache.get(key)
        if from_cache is not None:
            return from_cache['samples'], from_cache.get('template', False)
        return None, False

    def _cache_put(self, g, samples):
        key = g
        if self.write_only:
            key = 'wo:' + g
        for_cache =  {
            'samples': samples,
        }
        if self.template:
            for_cache['template'] = True
        self._cache[key] = for_cache

    def __init__(self, g, variants, write_only=False):
        self.variants = variants
        self.write_only = write_only
        self._expected_samples = False
        self._expected_dir_samples = False
        self._samples = {}
        self._dir_samples = {}
        for v in self.variants:
            self._gen_samples(v)
        # warnings
        if self._expected_samples and not self._samples:
            warn('no samples for {}'.format(g))
        elif self._expected_dir_samples and not self._dir_samples:
            warn('no dir samples for {}'.format(g))

        for vg, samp in self._samples.items():
            if len(samp) == 1 and list(samp.values()) == [['.']]:
                warn("only 1 dir for {}".format(vg))

    def to_dict(self):
        return {
            'variants': self.variants,
            'write-only': self.write_only,
            'samples': self._samples,
            'dir-samples': self._dir_samples,
        }

    @classmethod
    def from_dict(cls, d):
        fr = cls.__new__(cls)
        fr.variants = d['variants']
        fr.write_only = d.get('write-only', False)
        fr._samples = d['samples']
        fr._dir_samples = d['dir-samples']
        return fr

    @property
    def has_samples(self):
        return self._samples or self._dir_samples

    def __repr__(self):
        return "{} {}".format(self._dir_samples, self._samples)

    def _gen_samples(self, g):
        from_cache, templ = self._cached(g)
        if templ and not self.template:
            # do not create checks for template rules unless in template
            # mode
            return

        from_base = '/bin' in g or '/sbin' in g or g.startswith('/usr')
        dir_only = g.endswith('/')
        if dir_only:
            self._expected_dir_samples = True
            acc = self._dir_samples
        else:
            self._expected_samples = True
            acc = self._samples

        if g in acc:
            return

        if from_cache is not None:
            acc[g] = from_cache
            return

        samples = {}

        patt = g
        if from_base:
            patt = os.path.join(self.mounted_base, g.lstrip('/'))
        if '**' not in g:
            files = glob.glob(patt)
        else:
            files = glob.glob(patt, recursive=True)
            # toplevel needs own rule (see /var/lib/fontconfig as example)
            if files and files[0] + '**' == patt:
                files = files[1:]

        justfiles = []
        for f in files:
            p = f
            if from_base:
                p = '/'+os.path.relpath(f, self.mounted_base)
            if p != '/':
                p = p.rstrip('/')
            if os.path.isdir(f):
                samples[p] = ['.']
            else:
                if os.path.exists(f):
                    justfiles.append(p)

        for p in justfiles:
            d, b = os.path.split(p)
            cur = samples.get(d, [])
            if self.write_only:
                cur.append(b)
            else:
                dir = 0
                if cur and cur[0] == '.':
                    dir = 1
                if len(cur)-dir > 1:
                    continue
                cur.append(b)
            samples[d] = cur

        self._cache_put(g, samples)

        if samples:
            acc[g] = samples

    def _check_sample(self, samp):
        for d, files in samp.items():
            for name in files:
                fl = os.O_RDONLY
                if name == '.':
                    fl |= os.O_DIRECTORY
                try:
                    fd = os.open(os.path.join(d, name), fl)
                    os.close(fd)
                except Exception as e:
                    print(e)

    def check(self):
        # XXX have check support for this case
        if self.write_only:
            return
        for samp in self._samples.values():
            self._check_sample(samp)


def explode_variants(g):
    if '{' not in g:
        yield g
        return
    crl_pos = g.index('{')
    crl_end = g.index('}', crl_pos)
    pre = g[:crl_pos]
    post = g[crl_end+1:]
    opts = g[crl_pos+1:crl_end]
    for v2 in explode_variants(post):
        for opt in opts.split(','):
            yield pre+opt+v2


def file_reachabilities(rule):
    glob, access = rule.split()[:2]  # ignore things after -> for example
    variants = []
    for v in explode_variants(glob):
        if eagerly_bind_mounted(v):
            continue  # we assume is reachable, no checks to perform
        if v == '/**':
            continue  # too general, no precise check
        variants.append(v)
    if variants:
        fr = FileReachability(glob, variants, 'r' not in access)
        if fr.has_samples:
            yield fr


def extract_rules(rule_source):
    # plain AA fileglob rule (and not a go comment) for r and/or w
    rule_re = re.compile("^\s*/(?!/)[^ ]* [^#]*[rw][^#]*,")
    # naive skipping over nested profiles
    profile_re = re.compile("^\s*profile\s")
    profile_end_re = re.compile("^\s*}")
    prof_level = 0
    for line in rule_source:
        m = profile_re.match(line)
        if m:
            prof_level += 1
            continue
        m = profile_end_re.match(line)
        if m:
            prof_level -= 1
            continue
        if prof_level != 1:
            continue
        m = rule_re.match(line)
        if m:
            yield m.group(0).strip()


def gen(args):
    FileReachability.template = args.template
    FileReachability.mounted_base = args.mounted_base
    FileReachability.load_cache()

    frs = []
    for rule in extract_rules(args.rule_source):
        # XXX no vars for now
        if '@{' in rule:
            continue
        for fr in file_reachabilities(rule):
            frs.append(fr.to_dict())

    FileReachability.save_cache()

    with args.gen_checks as f:
        json.dump(frs, f)


def check(args):
    checks = json.load(sys.stdin)
    for frd in checks:
        fr = FileReachability.from_dict(frd)
        fr.check()


def mounted_base(s):
    err_msg = ''
    if not os.path.isdir(s):
        err_msg = '{!r} is not a directory'
    elif (not os.path.exists(os.path.join(s, 'meta/snap.yaml')) or
          not os.path.isdir(os.path.join(s, 'usr'))):
        err_msg = '{!r} does not look like a base snap'
    if not err_msg:
        return s
    raise argparse.ArgumentTypeError(err_msg.format(s))


if __name__ == '__main__':
    argp = argparse.ArgumentParser(
        description='File reachability testing for interfaces')
    argp.set_defaults(func=check)
    subp = argp.add_subparsers(help='sub-command help')
    # gen command
    genp = subp.add_parser('gen', description='Generate checks',
                           help="generate checks")
    genp.set_defaults(func=gen)
    genp.add_argument('--template', action='store_true', help='capture template rules checks')
    genp.add_argument('mounted_base', metavar='<mounted-base>',
                      type=mounted_base)
    genp.add_argument('rule_source', metavar='<rule-source>',
                      type=argparse.FileType('r'))
    genp.add_argument('gen_checks', metavar='<gen-checks.json>',
                      type=argparse.FileType('w'))
    # check command
    checkp = subp.add_parser('check', description='Run checks (from stdin)',
                             help="run checks")
    args = argp.parse_args()
    args.func(args)
