import json
import os
import pefile


def read_byte_at_virtual_address(pe, virtual_address):
    # 遍历所有节以找到包含该虚拟地址的节
    for section in pe.sections:
        section_start = section.VirtualAddress
        section_end = section.VirtualAddress + section.Misc_VirtualSize

        # 检查虚拟地址是否在节的范围内
        if section_start <= virtual_address < section_end:
            # 计算在节中的偏移量
            offset = virtual_address - section_start
            # 读取该偏移的字节
            section_data = section.get_data()
            # 以安全方式获取字节
            if offset < len(section_data):
                byte_value = section_data[offset]
                print(f"Byte at new virtual address {hex(virtual_address)}: {hex(byte_value)}")
                return offset
            else:
                print("Offset out of range for the section.")
                return None

    print("Virtual address not found in any section.")
    return None

def find_signature(pe, signature):
    # 将十六进制签名转换为字节数组
    byte_array = bytes.fromhex(signature)
    sig_length = len(byte_array)

    # 遍历所有节
    for section in pe.sections:
        # 读取节的内容
        section_data = section.get_data()

        # 在节数据中查找签名
        offset = section_data.find(byte_array)
        if offset != -1:
            virtual_addr = section.VirtualAddress + offset;
            print(f"Signature found in section '{section.Name.decode().rstrip(chr(0))}' at offset {hex(virtual_addr)}")

            to_offset = int.from_bytes(section_data[offset + 1:offset + 5], byteorder='little')
            print(f"to_offset: {to_offset}")

            jump_to = virtual_addr + 5 + to_offset
            print(f"Jump to: {hex(jump_to)}")

            offs = read_byte_at_virtual_address(pe, jump_to)

            ret_bytes = section_data[offs:offs + 12]
            print(f"Bytes: {[hex(b) for b in ret_bytes]}")
            #first_byte = section_data[offset]
            #print(f"First byte at the signature offset: {hex(first_byte)}")

if __name__ == '__main__':
    module = "server"
    game_path = "E:/Steam/steamapps/common/Counter-Strike Global Offensive/game/"
    file_path = game_path + "csgo/bin/win64/" + module + ".dll"

    sig = "E8 F5 80 20 00"

    pe = pefile.PE(file_path, fast_load=True)
    # 打印 PE 文件的基本信息
    #print(f"Number of Sections: {len(pe.sections)}")
    #print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    #print(pe.dump_info())

    find_signature(pe, sig)

