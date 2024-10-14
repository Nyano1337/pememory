import pefile
import capstone
import ctypes
from ctypes.wintypes import *


class PEMemory:
    INVALID_ADDRESS = -1

    def __init__(self,
                 file_path: str,
                 init_runtime_functions: bool = False,
                 init_type_descriptor_names: bool = False,
                 type_descriptor_filter: list[str] = None,
                 init_type_inherits: bool = False):
        self.dbghelp = ctypes.windll.dbghelp
        self.pe = pefile.PE(file_path, fast_load=True)
        self.rtti_helper = RTTIHelper(self)
        self.sig_maker = SigMaker(self)

        self.runtime_data = self.get_section(".data")
        self.readonly_data = self.get_section(".rdata")

        # vtable_name -> [address]
        self.vtable_cache: dict[str, list] = {}

        # fn_start -> fn_end
        self.runtime_functions: dict[int, int] = {}
        if init_runtime_functions:
            self.init_runtime_functions()

        # type_descriptor_name -> vtable_addr
        self.type_descriptor_names: dict[str, int] = {}
        self.type_descriptor_filter = type_descriptor_filter
        if init_type_descriptor_names or init_type_inherits:
            self.init_type_descriptor_names()

        self.type_inherits: dict[str, list] = {}
        if init_type_inherits:
            self.init_type_inherits()

    @staticmethod
    def to_ida_pattern(byte_list) -> str:
        if isinstance(byte_list, list):
            return " ".join(f"{int(x, 16):02X}" for x in byte_list)
        return " ".join(f"{x:02X}" for x in byte_list)

    def get_address(self, offset: int, section: pefile.SectionStructure = None):
        if section is not None:
            return self.get_address_with_section(offset, section)

        for section in self.pe.sections:
            section_start = section.VirtualAddress
            section_end = section.VirtualAddress + section.Misc_VirtualSize
            target_addr = section_start + offset
            if section_start <= target_addr < section_end:
                return target_addr
        return PEMemory.INVALID_ADDRESS

    def get_address_with_section(self, offset: int, section: pefile.SectionStructure):
        section_start = section.VirtualAddress
        section_end = section.VirtualAddress + section.Misc_VirtualSize
        target_addr = section_start + offset
        if section_start <= target_addr < section_end:
            return target_addr
        return PEMemory.INVALID_ADDRESS

    def read_address(self, addr: int, bytes_to_read: int = 8, cast_list: bool = True):
        for section in self.pe.sections:
            section_start = section.VirtualAddress
            section_end = section.VirtualAddress + section.Misc_VirtualSize
            if section_start <= addr < section_end:
                offset = addr - section_start
                section_data = section.get_data()
                if offset < len(section_data):
                    return [hex(byte) for byte in section_data[offset: offset + bytes_to_read]] if cast_list \
                        else section_data[offset: offset + bytes_to_read]
                else:
                    return None
        return None

    def get_int(self, addr: int):
        res = int.from_bytes(self.read_address(addr, 4, False), byteorder='little')
        return res if res != 0xFFFFFFFF else -1

    def get_long(self, addr: int):
        return int.from_bytes(self.read_address(addr, 8, False), byteorder='little')

    def get_string(self, addr: int, section: pefile.SectionStructure = None):
        if section is not None:
            return self.get_string_by_section(addr, section)

        for s in self.pe.sections:
            res = self.get_string_by_section(addr, s)
            if res != PEMemory.INVALID_ADDRESS:
                return res
        return PEMemory.INVALID_ADDRESS

    def get_string_by_section(self, addr: int, section: pefile.SectionStructure):
        section_start = section.VirtualAddress
        section_end = section.VirtualAddress + section.Misc_VirtualSize
        if section_start <= addr < section_end:
            start_index = addr - section_start
            section_data = section.get_data()
            section_len = len(section_data)
            if start_index < section_len:
                end_index = start_index
                while end_index < section_len and section_data[end_index] != 0:
                    end_index += 1
                return section_data[start_index:end_index].decode('utf-8')
        return PEMemory.INVALID_ADDRESS

    def get_section(self, name: str):
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if section_name == name:
                return section
        return None

    def resolve_relative_address(self, addr: int, offset_register=0x3, offset_next_instruction=0x7) -> int:
        skip_register = addr + offset_register
        relative_addr = self.get_int(skip_register)
        next_instruction = addr + offset_next_instruction
        return next_instruction + relative_addr

    def sig_scan(self, sig: str) -> int:
        byte_array = bytes.fromhex(sig)
        for section in self.pe.sections:
            section_data = section.get_data()
            offset = section_data.find(byte_array)
            if offset != -1:
                return section.VirtualAddress + offset
        return PEMemory.INVALID_ADDRESS

    def find_pattern_by_str(self, pattern: str, section: pefile.SectionStructure = None, start_offset: int = 0, to_addr: bool = True) -> int:
        return self.find_pattern_by_bytes(pattern.encode('utf-8'), section, start_offset, to_addr)

    def find_pattern_by_bytes(self, pattern: bytes, section: pefile.SectionStructure = None, start_offset: int = 0, to_addr: bool = True) -> int:
        offset = section.get_data().find(pattern, start_offset)
        return self.get_address(offset, section) if to_addr else offset

    # reference: https://github.com/komashchenko/DynLibUtils/blob/cc8b6ade9e912012d21d3fe4d07b98bd215abbe2/module_windows.cpp#L136
    def get_vtable_by_name(self, vtable_name: str, decorated: bool = False) -> int:
        if len(vtable_name) == 0:
            return PEMemory.INVALID_ADDRESS

        decorated_table_name = vtable_name if decorated \
            else ".?AV" + vtable_name + "@@"

        type_descriptor_name = self.find_pattern_by_str(decorated_table_name, self.runtime_data)
        if type_descriptor_name is PEMemory.INVALID_ADDRESS:
            return PEMemory.INVALID_ADDRESS

        rtti_type_descriptor = type_descriptor_name - 0x10
        rtti_type_descriptor_bytes = rtti_type_descriptor.to_bytes(4, byteorder='little')

        current_offset = 0
        while (current_offset := self.find_pattern_by_bytes(
                rtti_type_descriptor_bytes, self.readonly_data, current_offset, False)) != PEMemory.INVALID_ADDRESS:
            reference = self.get_address(current_offset, self.readonly_data)
            val1 = int(self.read_address(reference - 0xC, 1)[0], 16)
            val2 = int(self.read_address(reference - 0x8, 1)[0], 16)
            if val1 == 1 and val2 == 0:
                offset_reference = reference - 0xC + self.pe.OPTIONAL_HEADER.ImageBase
                offset_reference_bytes = offset_reference.to_bytes(8, byteorder='little')
                rtti_complete_object_locator = self.find_pattern_by_bytes(offset_reference_bytes, self.readonly_data)
                if rtti_complete_object_locator != PEMemory.INVALID_ADDRESS:
                    return rtti_complete_object_locator + 0x8
            current_offset += 0x4
        return PEMemory.INVALID_ADDRESS

    def is_valid_vtable_function(self, vtable_fn: int) -> bool:
        if int(self.read_address(vtable_fn)[7], 16) != 0x00:
            return False

        fn_start = self.get_long(vtable_fn) - self.pe.OPTIONAL_HEADER.ImageBase
        opcode = self.read_address(fn_start, 1)
        if opcode is None:
            return False

        if int(opcode[0], 16) >= 0x0F:
            return True

        return False

    def get_vtable_length(self, vtable_name: str) -> int:
        if vtable_name in self.vtable_cache:
            return len(self.vtable_cache[vtable_name])

        fn = self.get_vtable_by_name(vtable_name)
        if fn == PEMemory.INVALID_ADDRESS:
            return -1

        count = 0
        vtable_fns = []
        while self.is_valid_vtable_function(fn):
            vtable_fns.append(fn)
            count += 1
            fn += 8

        self.vtable_cache[vtable_name] = vtable_fns
        return count

    def get_vtable_func_by_offset(self, vtable_name: str, target_offset: int, use_dq_offset: bool = True) -> int:
        vtable_len = self.get_vtable_length(vtable_name)
        if target_offset < 0 or target_offset > vtable_len:
            return PEMemory.INVALID_ADDRESS

        fn = self.vtable_cache[vtable_name][target_offset]
        if use_dq_offset:
            dq_offset = self.get_long(fn)
            return dq_offset - self.pe.OPTIONAL_HEADER.ImageBase
        return fn

    def init_runtime_functions(self):
        procedure_data = self.get_section(".pdata")
        if procedure_data is None:
            return

        current_offset = procedure_data.VirtualAddress
        section_len = procedure_data.VirtualAddress + procedure_data.Misc_VirtualSize

        while current_offset < section_len:
            start_addr = self.get_int(current_offset)
            end_addr = self.get_int(current_offset + 4)
            # unwind_info_address = self.get_int(current_offset + 8)
            self.runtime_functions[start_addr] = end_addr
            current_offset += 12

    @staticmethod
    def RaiseIfZero(result, func=None, arguments=()):
        """
        Error checking for most Win32 API calls.

        The function is assumed to return an integer, which is C{0} on error.
        In that case the C{WindowsError} exception is raised.
        """
        if not result:
            raise ctypes.WinError()
        return result

    def undecorate_symbol_name(self, symbol_name):
        symbol_name = symbol_name.replace('.?AV?', '?').replace('.?AV', '?')

        flags = 0x1000 #UNDNAME_NAME_ONLY
        _UnDecorateSymbolNameA = self.dbghelp.UnDecorateSymbolName
        _UnDecorateSymbolNameA.argtypes = [LPSTR, LPSTR, DWORD, DWORD]
        _UnDecorateSymbolNameA.restype = DWORD
        _UnDecorateSymbolNameA.errcheck = self.RaiseIfZero

        buffer = ctypes.create_string_buffer(512)
        _UnDecorateSymbolNameA(symbol_name.encode('utf-8'), buffer, ctypes.sizeof(buffer), flags)
        return buffer.value.decode('utf-8')

    def init_type_descriptor_names(self):
        offset = 0
        while (offset := self.find_pattern_by_str('.?AV', self.runtime_data, start_offset=offset, to_addr=False)) != PEMemory.INVALID_ADDRESS:
            addr = self.get_address_with_section(offset, self.runtime_data)
            if addr != PEMemory.INVALID_ADDRESS:
                decorate_name = self.get_string(addr, self.runtime_data)
                if decorate_name != PEMemory.INVALID_ADDRESS:
                    offset += len(decorate_name)
                    vtable = self.get_vtable_by_name(decorate_name, decorated=True)
                    if vtable != PEMemory.INVALID_ADDRESS:
                        type_name = self.undecorate_symbol_name(decorate_name)
                        if self.type_descriptor_filter is not None:
                            if any(x for x in self.type_descriptor_filter if x in type_name):
                                continue
                        self.type_descriptor_names[type_name] = vtable
        self.type_descriptor_names = dict(sorted(self.type_descriptor_names.items(), key=lambda item: item[0]))

    def init_type_inherits(self):
        for type_name, vtable in self.type_descriptor_names.items():
            self.type_inherits[type_name] = self.rtti_helper.get_exact_inherits(vtable)


class RTTIHelper:
    def __init__(self, mem: PEMemory):
        self.mem = mem

    def get_object_locator(self, vtable_ptr: int):
        return self.RTTICompleteObjectLocator(self.mem.get_long(vtable_ptr - 8)  - self.mem.pe.OPTIONAL_HEADER.ImageBase, self.mem)

    def get_exact_inherits(self, vtable_ptr: int):
        object_locator = self.get_object_locator(vtable_ptr)
        if object_locator == PEMemory.INVALID_ADDRESS:
            return None

        inherits: list[str] = []
        base_idx = 0
        while base_idx != len(object_locator.hierarchyDescriptor.array_of_base_classes):
            base = object_locator.hierarchyDescriptor.array_of_base_classes[base_idx]
            inherits.append(self.mem.undecorate_symbol_name(base.pTypeDescriptor.name))
            base_idx += base.pClassDescriptor.num_base_classes
        return inherits

    class RTTITypeDescriptor:
        def __init__(self, descriptor_ptr: int, mem: PEMemory):
            # internal runtime reference
            self.runtime_reference = 0

            # type descriptor name
            self.name = mem.get_string(descriptor_ptr + 16)

    class RTTIBaseClassDescriptor:
        _BCD_NOTVISIBLE = 0x01
        _BCD_AMBIGUOUS = 0x02
        _BCD_PRIVORPROTINCOMPOBJ = 0x04
        _BCD_PRIVORPROTBASE = 0x08
        _BCD_VBOFCONTOBJ = 0x10
        _BCD_NONPOLYMORPHIC = 0x20
        _BCD_HASPCHD = 0x40

        def __init__(self, descriptor_ptr: int, mem: PEMemory):
            # reference to type description
            self.pTypeDescriptor = RTTIHelper.RTTITypeDescriptor(mem.get_int(descriptor_ptr), mem)

            # #of sub elements within base class array
            self.num_contained_bases = mem.get_int(descriptor_ptr + 4)

            # member displacement
            self.mdisp = mem.get_int(descriptor_ptr + 8)

            # vftable displacement
            self.vdisp = mem.get_int(descriptor_ptr + 12)

            # displacement within vftable
            self.dispwf = mem.get_int(descriptor_ptr + 16)

            # base class attributes
            self.attributes = mem.get_int(descriptor_ptr + 20)

            # reference to class hierarchy descriptor
            self.pClassDescriptor = RTTIHelper.RTTIClassHierarchyDescriptor(mem.get_int(descriptor_ptr + 24), mem)

        def is_not_visible(self) -> bool:
            return bool(self.attributes & self._BCD_NOTVISIBLE)

        def is_unknown_inherit(self) -> bool:
            return bool(self.attributes & self._BCD_AMBIGUOUS)

        def is_private_or_protected(self) -> bool:
            return bool(self.attributes & self._BCD_PRIVORPROTINCOMPOBJ)

        def is_base_private_or_protected(self) -> bool:
            return bool(self.attributes & self._BCD_PRIVORPROTBASE)

        def is_pure_virtual(self) -> bool:
            return bool(self.attributes & self._BCD_VBOFCONTOBJ)

        def is_non_polymorphic(self) -> bool:
            return bool(self.attributes & self._BCD_NONPOLYMORPHIC)

        def is_valid_rtti(self) -> bool:
            return bool(self.attributes & self._BCD_HASPCHD)

    class RTTIClassHierarchyDescriptor:
        _CHD_MULTINH = 0x01
        _CHD_VIRTINH = 0x02
        _CHD_AMBIGUOUS = 0x04

        def __init__(self, descriptor_ptr: int, mem: PEMemory):
            # the value always is 0
            self.signature = 0

            # attributes
            self.attributes = mem.get_int(descriptor_ptr + 4)

            # #of items in the array of base classes
            self.num_base_classes = mem.get_int(descriptor_ptr + 8)

            # reference to the array of base classes
            self.reference_array_of_base_classes = mem.get_int(descriptor_ptr + 12)
            self.array_of_base_classes: list[RTTIHelper.RTTIBaseClassDescriptor] = []

            if self.num_base_classes > 1:
                for i in range(self.num_base_classes):
                    if i == 0:
                        # pass self
                        continue
                    addr_base_class_descriptor = mem.get_int(self.reference_array_of_base_classes + i * 4)
                    base_class_descriptor = RTTIHelper.RTTIBaseClassDescriptor(addr_base_class_descriptor, mem)
                    self.array_of_base_classes.append(base_class_descriptor)


        def is_multiple_inherit(self):
            return bool(self.attributes & self._CHD_MULTINH)

        def is_virtual_inherit(self):
            return bool(self.attributes & self._CHD_VIRTINH)

        def is_unknown_inherit(self):
            return bool(self.attributes & self._CHD_AMBIGUOUS)

    class RTTICompleteObjectLocator:
        def __init__(self, locator_ptr: int, mem: PEMemory):
            # signature
            self.signature = mem.get_int(locator_ptr)

            # offset of this vtable in complete class (from top)
            self.offset = mem.get_int(locator_ptr + 4)

            # offset of constructor displacement
            self.cdOffset = mem.get_int(locator_ptr + 8)

            # reference to type description
            self.pTypeDescriptor = RTTIHelper.RTTITypeDescriptor(mem.get_int(locator_ptr + 12), mem)

            # reference to hierarchy description
            self.hierarchyDescriptor = RTTIHelper.RTTIClassHierarchyDescriptor(mem.get_int(locator_ptr + 16), mem)

            # reference to object's base
            self.pSelf = locator_ptr

class SigMaker:
    def __init__(self, mem: PEMemory):
        self.mem = mem
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def get_function_end(self, fn_start: int) -> int:
        if fn_start in self.mem.runtime_functions:
            return self.mem.runtime_functions[fn_start]

        text_data = self.mem.get_section(".text")
        section_end = text_data.VirtualAddress + text_data.Misc_VirtualSize
        current_addr = fn_start

        # Guessing Attributes: thunk
        codes = self.mem.read_address(current_addr, 20, False)
        instructions = self.md.disasm(codes, current_addr + self.mem.pe.OPTIONAL_HEADER.ImageBase)[0]
        current_ins_idx = 1
        for ins in instructions:
            current_addr += ins.size
            if current_ins_idx <= 3 and ins.mnemonic == "jmp":
                return current_addr
            current_ins_idx += 1

        # Guessing game
        # I don't know how IDA parse function
        while current_addr < section_end:
            code = self.mem.read_address(current_addr, 20, False)
            ins = self.md.disasm(code, fn_start + self.mem.pe.OPTIONAL_HEADER.ImageBase)[0]
            current_addr += ins.size

            # Finally we got the true ret instruction?
            if ins.mnemonic == "ret":
                return current_addr

        return PEMemory.INVALID_ADDRESS

    def make_sig(self, fn_start):
        fn_end = self.get_function_end(fn_start)
        if fn_end is PEMemory.INVALID_ADDRESS:
            return []
        return self.mem.to_ida_pattern(self.mem.read_address(fn_start, fn_end - fn_start, cast_list=False))
