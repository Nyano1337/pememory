import capstone

from pememory import PEMemory
from capstone import *

if __name__ == '__main__':
    module = "engine2"
    game_path = r"E:\Steam\steamapps\common\Counter-Strike Global Offensive\game"
    file_path = game_path + r"/bin/win64/" + module + ".dll"

    mem = PEMemory(file_path)

    for x in mem.pe.sections:
        print(x.Name.decode('utf-8'))

    vlen = mem.get_vtable_length("CEngineWatchdogThread")
    print(vlen)