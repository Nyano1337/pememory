from pememory import PEMemory
import os

class ClassDumper:
    def __init__(self, game_path: str, type_filter: list = None):
        self.game_path = game_path
        self.pe_files: dict[str, PEMemory] = {}
        self.type_filter = type_filter

    def load_library(self, library: str) -> PEMemory | None:
        if library in self.pe_files and self.pe_files[library] is not None:
            return self.pe_files[library]

        file_path = ""

        try:
            if library in ("server", "matchmaking"):
                file_path = self.game_path + "csgo/bin/win64/" + library + ".dll"
            else:
                file_path = self.game_path + "bin/win64/" + library + ".dll"

            self.pe_files[library] = PEMemory(file_path, type_descriptor_filter=self.type_filter, init_type_inherits=True)
        except Exception as e:
            print(
                f"Error: An unexpected error occurred while opening the file {file_path}. Exception: {e}")
            return None

        return self.pe_files[library]

    def dump(self, dir_path: str):
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        for _lib, _mem in self.pe_files.items():
            with open(os.path.join(dir_path, _lib) + '.cpp', 'w') as file:
                for class_name, bases in _mem.type_inherits.items():
                    file.write(f'class {class_name}')
                    num_bases = len(bases)
                    if num_bases > 0:
                        file.write(' : ')
                        if num_bases == 1:
                            class_names = bases[0]
                        else:
                            class_names = ', '.join(bases)
                    file.write(f'{class_names}' + ' {}\n')

if __name__ == '__main__':
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
        'google::protobuf::',
        'iterator_buffer',
        'fmt::'
    ]

    _game_path = "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive/game/"
    dumper = ClassDumper(_game_path, filter_type_name)
    #libs = ["server", "matchmaking", "engine2", "tier0", "networksystem"]
    libs = ["tier0"]
    for lib in libs:
        dumper.load_library(lib)

    dumper.dump('./class_dump')
