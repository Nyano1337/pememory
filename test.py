from pememory import PEMemory

if __name__ == '__main__':
    module = "server"
    game_path = r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game/"
    file_path = game_path + r"csgo/bin/win64/" + module + ".dll"

    mem = PEMemory(file_path)

    sig = "E8 F5 80 20 00"
    fn = mem.sig_scan(sig)
    print(hex(fn))

    jump = mem.resolve_relative_address(fn, 1, 5)
    print(hex(jump))

    ret_bytes = mem.read_address(jump, 16)
    print(PEMemory.to_ida_pattern(ret_bytes))

    addr = mem.get_virtual_table_by_name("CCSPlayerPawn")
    print(PEMemory.to_ida_pattern(mem.read_address(addr, 16)))
    print(mem.get_vtable_length("CCSPlayerPawn"))