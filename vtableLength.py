import pefile

class PyMemory:
    INVALID_ADDRESS = -1

    def __init__(self, file_path: str):
        self.pe = pefile.PE(file_path, fast_load=True)

    def get_address(self, section: pefile.SectionStructure, offset: int):
        section_start = section.VirtualAddress
        section_end = section.VirtualAddress + section.Misc_VirtualSize
        target_addr = section_start + offset
        if section_start <= target_addr < section_end:
            return target_addr
        return PyMemory.INVALID_ADDRESS

    def read_address(self, addr: int, bytes_to_read: int = 8, cast_list: bool = True):
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

    def get_section(self, name: str):
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if section_name == name:
                return section
        return None

    def resolve_relative_address(self, addr: int, offset_register = 0x3, offset_next_instruction = 0x7) -> int:
        skip_register = addr + offset_register
        relative_addr = int.from_bytes(self.read_address(skip_register, 4, False), byteorder='little')
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

    def find_pattern_by_str(self, pattern: str, section: pefile.SectionStructure) -> int:
        encoded_pattern = pattern.encode('utf-8')
        offset = section.get_data().find(encoded_pattern)
        if offset == -1:
            return PyMemory.INVALID_ADDRESS
        return self.get_address(section, offset)

    def find_pattern_by_bytes(self, pattern: bytes, section: pefile.SectionStructure, start_offset: int = 0) -> int:
        offset = section.get_data().find(pattern, start_offset)
        if offset == -1:
            return PyMemory.INVALID_ADDRESS
        return self.get_address(section, offset)

    def get_virtual_table_by_name(self, vtable_name: str, decorated: bool = False):
        if len(vtable_name) == 0:
            return None

        runtime_data = self.get_section(".data")
        if runtime_data is None:
            return None

        readonly_data = self.get_section(".rdata")
        if readonly_data is None:
            return None

        decorated_table_name = vtable_name if decorated \
            else ".?AV" + vtable_name + "@@"

        type_descriptor_name = self.find_pattern_by_str(decorated_table_name, runtime_data)
        rtti_type_descriptor = type_descriptor_name - 0x10
        rtti_type_descriptor_bytes = rtti_type_descriptor.to_bytes(4, byteorder='little')

        reference = 0
        while (reference := self.find_pattern_by_bytes(rtti_type_descriptor_bytes, readonly_data, reference)) != PyMemory.INVALID_ADDRESS:
            val1 = int(self.read_address(reference - 0xC, 1)[0], 16)
            val2 = int(self.read_address(reference - 0x8, 1)[0], 16)
            if val1 == 1 and val2 == 0:
                offset_reference = reference - 0xC + self.pe.OPTIONAL_HEADER.ImageBase
                offset_reference_bytes = offset_reference.to_bytes(8, byteorder='little')
                rtti_complete_object_locator = self.find_pattern_by_bytes(offset_reference_bytes, readonly_data)
                if rtti_complete_object_locator != PyMemory.INVALID_ADDRESS:
                    return rtti_complete_object_locator + 0x8
            reference = reference + 0x4


    @staticmethod
    def to_ida_pattern(byte_list: list) -> str:
        return " ".join(f"{int(x, 16):02X}" for x in byte_list)


if __name__ == '__main__':
    module = "server"
    game_path = r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game/"
    file_path = game_path + r"csgo/bin/win64/" + module + ".dll"

    mem = PyMemory(file_path)

    # sig = "E8 F5 80 20 00"
    # fn = mem.sig_scan(sig)
    #
    # print(hex(fn))
    #
    # jump = mem.resolve_relative_address(fn, 1, 5)
    # print(hex(jump))
    #
    # ret_bytes = mem.read_address(jump, 12)
    # print(PyMemory.to_ida_pattern(ret_bytes))

    addr = mem.get_virtual_table_by_name("CCSPlayerPawn")
    print(PyMemory.to_ida_pattern(mem.read_address(addr, 16)))