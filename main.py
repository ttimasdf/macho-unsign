#!/usr/bin/env python3

from shutil import copyfile
import unsign

_suffix = '.unsigned'


def main(*args):
    if len(args) >= 2:
        src_file = args[1]
        if len(args) == 3:
            dst_file = args[2]
        else:
            dst_file = ''.join((src_file, _suffix))
    else:
        print("Usage: {} file [outfile]".format(__file__))
        raise SystemExit

    copyfile(src_file, dst_file)

    f = open(dst_file, 'r+b')
    unsign.unsign_macho(f)


if __name__ == '__main__':
    import sys
    main(*sys.argv)
