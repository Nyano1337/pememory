import json

import capstone

from pememory import PEMemory
from capstone import *

if __name__ == '__main__':
    module = "engine2"
    game_path = r"E:\Steam\steamapps\common\Counter-Strike Global Offensive\game"
    file_path = game_path + r"/bin/win64/" + module + ".dll"

    filter_type_name = [
        '<lambda',
        'std::',
        'RepeatedFieldPrimitiveAccessor',
        '_Associated',
        '_Deferred',
        '_Func_base',
        '_Func_impl',
        '_Packaged_state',
        '_Ref_count_obj',
        '_Task_async_state',
        'anonymous namespace',
        'ctype<',
        'numpunct<',
        'snappy::',
        'type_info',
        'google::protobuf::'
    ]
    mem = PEMemory(file_path, init_type_inherits=True, type_descriptor_filter=filter_type_name)
    print(json.dumps(mem.type_inherits, indent=4))
    #vtable = mem.get_vtable_by_name("TEST_H")
    #helper = mem.rtti_helper.get_exact_inherits(vtable)
    # vlen = mem.get_vtable_length("CEngineWatchdogThread")
    # print(vlen)

    # mem.init_type_descriptor_names()


    #name = mem.undecorate_symbol_name(".?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??AddViewsToSceneSystemForSplitScreenSlot@CRenderingWorldSession@@AEAAXAEBUSplitscreenViewParams_t@3@@Z@XPEAVISceneView@@AEBURenderViewport_t@@PEAUHSceneViewRenderTarget__@@PEAU7@@std@@")
    #print(name)