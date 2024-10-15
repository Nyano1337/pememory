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

        def write_inheritance(_file, _name, _bases, is_class=True):
            type_name = 'class' if is_class else 'struct'
            _file.write(f'{type_name} {_name}')
            if _bases:
                _file.write(' : ')
                inherits = ', '.join(_bases) if len(_bases) > 1 else _bases[0]
                _file.write(f'{inherits}')
            _file.write(' {}\n')

        for _lib, _mem in self.pe_files.items():
            with open(os.path.join(dir_path, _lib) + '.hpp', 'w') as file:
                for class_name, bases in _mem.class_inherits.items():
                    write_inheritance(file, class_name, bases, is_class=True)
                for struct_name, bases in _mem.struct_inherits.items():
                    write_inheritance(file, struct_name, bases, is_class=False)

if __name__ == '__main__':
    filter_type_name = [
        '`',
        '<lambda',
        'std::',
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
        'buffer<',
        'snappy::',
        'type_info',
        'google::protobuf::',
        'iterator_buffer',
        'fmt::',
        'Concurrency::'
    ]

    _game_path = "E:/Steam/steamapps/common/Counter-Strike Global Offensive/game/"
    dumper = ClassDumper(_game_path, filter_type_name)
    libs = ["server", "matchmaking", "engine2", "tier0", "networksystem"]
    for lib in libs:
        dumper.load_library(lib)

    dumper.dump('./class_dump')
