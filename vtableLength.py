import json
import os
import pefile

class PyMemory:
    INVALID_ADDRESS = -1

    def __init__(self, file_path: str):
        self.pe = pefile.PE(file_path, fast_load=True)

    def read(self, addr: int, bytes_to_read: int = 8, cast_list: bool = True):
        for section in self.pe.sections:
            section_start = section.VirtualAddress
            section_end = section.VirtualAddress + section.Misc_VirtualSize
            if section_start <= addr < section_end:
                offset = addr - section_start
                section_data = section.get_data()
                if offset < len(section_data):
                    return [hex(byte) for byte in section_data[offset : offset + bytes_to_read]] if cast_list \
                        else section_data[offset : offset + bytes_to_read]
                else:
                    return None
        return None

    def resolve_relative_address(self, addr: int, offset_register = 0x3, offset_next_instruction = 0x7) -> int:
        skip_register = addr + offset_register
        relative_addr = int.from_bytes(self.read(skip_register, 4, False), byteorder='little')
        next_instruction = addr + offset_next_instruction
        return next_instruction + relative_addr

    def sig_scan(self, sig: str) -> int:
        byte_array = bytes.fromhex(sig)
        for section in self.pe.sections:
            section_data = section.get_data()
            offset = section_data.find(byte_array)
            if offset != -1:
                return section.VirtualAddress + offset
        return PyMemory.INVALID_ADDRESS

    @staticmethod
    def to_ida_pattern(bytes: list) -> str:
        return " ".join(f"{int(x, 16):02X}" for x in bytes)


if __name__ == '__main__':
    module = "server"
    game_path = r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game/"
    file_path = game_path + r"csgo/bin/win64/" + module + ".dll"

    sig = "E8 F5 80 20 00"

    mem = PyMemory(file_path)

    fn = mem.sig_scan(sig)

    print(hex(fn))

    jump = mem.resolve_relative_address(fn, 1, 5)
    print(hex(jump))

    ret_bytes = mem.read(jump, 12)
    print(PyMemory.to_ida_pattern(ret_bytes))

