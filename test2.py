import json

import capstone

from pememory import PEMemory
from capstone import *

if __name__ == '__main__':
    module = "engine2"
    game_path = r"E:\Steam\steamapps\common\Counter-Strike Global Offensive\game"
    file_path = game_path + r"/bin/win64/" + module + ".dll"

    mem = PEMemory(r'E:\cs2bins\2024-10-8\engine2.dll')
    vtable = mem.get_vtable_by_name("CEngineWatchdogThread")
    helper = mem.rtti_helper.get_object_locator(vtable)
    # vlen = mem.get_vtable_length("CEngineWatchdogThread")
    # print(vlen)

    mem.init_type_descriptor_names()

    print(json.dumps(mem.type_descriptor_names, indent=4))
    name = mem.undecorate_symbol_name(".?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??AddViewsToSceneSystemForSplitScreenSlot@CRenderingWorldSession@@AEAAXAEBUSplitscreenViewParams_t@3@@Z@XPEAVISceneView@@AEBURenderViewport_t@@PEAUHSceneViewRenderTarget__@@PEAU7@@std@@")
    print(name)