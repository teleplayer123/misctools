import capstone as cs
import lief

def xdump(data, bs=16, en="utf8"):
    if data == "" or data is None:
        return
    width = (bs * 2) + (bs // 2)
    lines = []
    cols = """
BLOCK  BYTES{} {}\n""".format(" " * (width + (width % bs) - 5), en.upper())
    dashes = """
{0:-<6} {1:-<{2}}{3}{4}\n""".format("", "", width + (width % bs), " ","-" * (len(en)+1))
    lines.append(cols)
    lines.append(dashes)
    for i in range(0, len(data), bs):
        block_data = data[i:i+bs]
        hexstr = " ".join(["%02x" %ord(chr(x)) for x in block_data])
        txtstr = "".join(["%s" %chr(x) if 32 <= ord(chr(x)) < 127  else "." for x in block_data])
        line = "{:06x} {:48}  {:16}\n".format(i, hexstr, txtstr)
        lines.append(line)
    return "".join([i for i in lines])

class BinDisasm:

    def __init__(self, filename, arch="arm", mode="arm", size=None):
        self.filename = filename
        self._size = size
        self._data_fd = None
        self.data = None
        self._code = None
        self._dis = None

        self._archs = {
            "arm": cs.CS_ARCH_ARM,
            "arm64": cs.CS_ARCH_ARM64,
            "x86": cs.CS_ARCH_X86,
            "mips": cs.CS_ARCH_MIPS
        }
        self._modes = {
            "x86": cs.CS_MODE_32,
            "x86_64": cs.CS_MODE_64,
            "arm": cs.CS_MODE_ARM,
            "mips32": cs.CS_MODE_MIPS32,
            "mips64": cs.CS_MODE_MIPS64,
            "thumb": cs.CS_MODE_THUMB
        }
        try:
            self._arch = self._archs[arch]
            self._mode = self._modes[mode]
        except KeyError:
            raise KeyError("arch or mode are not supported.")

    def _get_code(self, offset=0):
        self._dis = cs.Cs(self._arch, self._mode)
        code = self._dis.disasm(self.data, offset=offset)
        return [ins for ins in code]
    
    def reconfig_mode(self, mode):
        if self._dis is not None:
            self._dis.mode = mode
        else:
            raise EnvironmentError("File must be parsed before reconfiguring mode.")
        
    def set_syntax(self, syntax):
        if self._dis is not None:
            self._dis.syntax = syntax
        else:
            raise EnvironmentError("File must be parsed before setting syntax format.")

    def parse_code(self, offset=0):
        ins_info = {}
        code = self._get_code(offset)
        for i in code:
            ins_by_addr = {
                "address": i.address,
                "mnemonic": i.mnemonic,
                "operation": i.op_str
            }
            ins_info[str(i.address)] = ins_by_addr
        return ins_info

    def __enter__(self):
        self._data_fd = open(self.filename, "rb")
        if self._size is not None and type(self._size) == int:
            self.data = self._data_fd.read(self._size)
        else:
            self.data = self._data_fd.read()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._data_fd.close()


class ElfDisasm:

    def __init__(self, filename):
        self.elf = lief.parse(filename)

    def get_libs(self):
        return self.elf.libraries

    def sections_info_dict(self):
        e_sections = {}
        for section in self.elf.sections:
            e_sections[section.name] = {
                "virtual_addr": "{:08x}".format(section.virtual_address),
                "content": section.content.hex(),
                "offset": "{:08x}".format(section.offset)
            }

    def get_imported_funcs(self):
        return [(f.name, f.value) for f in self.elf.imported_functions]
        
    def get_sec_names(self):
        return [sec.name for sec in self.elf.sections]

    def hexdump_section(self, sec_name):
        sec_content = self.elf.get_section(sec_name).content
        hex_content = xdump(sec_content)
        return hex_content