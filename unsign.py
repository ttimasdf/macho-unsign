import mmap
from . import macho
from io import SEEK_CUR
try:
    from EBP.logging import get_logger
except ImportError as e:
    from logging import getLogger as get_logger

log = get_logger(__name__)


def unsign_macho(f, pos=0):
    mm = mmap.mmap(f.fileno(), 0, offset=pos)

    macho_start = mm.tell()
    magic = mm[macho_start:macho_start+4]

    try:
        is_x64, is_little_endian = {
            macho.MH_MAGIC_64: (True, True),
            macho.MH_MAGIC: (False, True),
            macho.MH_MAGIC_64[::-1]: (True, False),
            macho.MH_MAGIC[::-1]: (False, False),
        }[magic]
    except KeyError:
        print("Unknown mach-o magic number {}".format(magic.hex()))
        raise SystemExit

    if is_x64:
        header = macho.MachHeader64(is_little_endian)
    else:
        header = macho.MachHeader(is_little_endian)
    header.unpack_to_dict(mm.read(header.size))

    cmd = macho.LoadCommand()
    ld_cmd = macho.LinkeditDataCommand()

    header.ncmds -= 1
    header.sizeofcmds -= ld_cmd.size
    mm.seek(-header.size, SEEK_CUR)
    mm.write(header.pack_from_dict())
    header.ncmds += 1
    header.sizeofcmds += ld_cmd.size

    for _ in range(header.ncmds):
        cmd.unpack_to_dict(mm.read(cmd.size))
        if cmd.cmd is macho.LC_CODE_SIGNATURE:
            mm.seek(-cmd.size, SEEK_CUR)
            log.info("Found sig!")
            ld_cmd.unpack_to_dict(mm.read(ld_cmd.size))
            ld_pos = mm.tell()
        else:
            mm.seek(cmd.cmdsize-cmd.size, SEEK_CUR)

    mm.move(ld_pos-ld_cmd.size, ld_pos, mm.tell()-ld_pos)
    mm.seek(-ld_cmd.size, SEEK_CUR)
    mm.write(b'\x00'*ld_cmd.size)
    mm.seek(macho_start+ld_cmd.dataoff)
    mm.write(b'\x00'*ld_cmd.datasize)

    mm.flush()
    return mm.tell()
