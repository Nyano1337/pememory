import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pememory import PEMemory

print_lock = threading.Lock()

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

            with print_lock:
                print(f'[{library}] Parsing...')

            self.pe_files[library] = PEMemory(file_path, type_descriptor_filter=self.type_filter, init_type_inherits=True)

            with print_lock:
                print(f'[{library}] Done!')
        except Exception as e:
            print(
                f"Error: An unexpected error occurred while opening the file {file_path}. Exception: {e}")
            return None

        return self.pe_files[library]

    def dump(self, dir_path: str):
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        def write_inheritance(_file, _name, _bases, vtable_len = 0, is_class=True):
            type_name = 'class' if is_class else 'struct'
            _file.write(f'{type_name} {_name}')
            if _bases:
                _file.write(' : ')
                inherits = ', '.join(_bases) if len(_bases) > 1 else _bases[0]
                _file.write(f'{inherits}')
            if vtable_len > 0:
                _file.write(' { ' + f'void* vtable[{vtable_len}];' + ' }\n')
            else:
                _file.write(' {}\n')

        for _lib, _mem in self.pe_files.items():
            with open(os.path.join(dir_path, _lib) + '.hpp', 'w') as file:
                for class_name, bases in _mem.class_inherits.items():
                    vtable_len = 0 if class_name not in _mem.vtable_cache else len(_mem.vtable_cache[class_name])
                    write_inheritance(file, class_name, bases, vtable_len, is_class=True)
                for struct_name, bases in _mem.struct_inherits.items():
                    vtable_len = 0 if struct_name not in _mem.vtable_cache else len(_mem.vtable_cache[struct_name])
                    write_inheritance(file, struct_name, bases, vtable_len, is_class=False)

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
        'Concurrency::',
        'moodycamel::'
    ]

    _game_path = "E:/Steam/steamapps/common/Counter-Strike Global Offensive/game/"
    dumper = ClassDumper(_game_path, filter_type_name)
    # "server", "engine2", "matchmaking", "tier0", "networksystem"
    libs = ["server", "engine2", "matchmaking", "tier0", "networksystem"]
    threads = []
    with ThreadPoolExecutor(max_workers=len(libs)) as executor:
        executor.map(dumper.load_library, libs)

    dumper.dump('./class_dump')
