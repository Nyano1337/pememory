import json
from pathlib import Path
from pememory import PEMemory

class ClassInformer:
    def __init__(self, game_path: str):
        self.game_path = game_path
        self.pe_files: dict[str, PEMemory] = {}
        self.vtable_methods: dict[str, int] = {}

    def load_library(self, library: str) -> PEMemory | None:
        if library in self.pe_files and self.pe_files[library] is not None:
            return self.pe_files[library]

        file_path = ""

        try:
            if library in ("server", "matchmaking"):
                file_path = self.game_path + "csgo/bin/win64/" + library + ".dll"
            else:
                file_path = self.game_path + "bin/win64/" + library + ".dll"

            self.pe_files[library] = PEMemory(file_path)
        except Exception as e:
            print(
                f"Error: An unexpected error occurred while opening the file {file_path}. Exception: {e}")
            return None

        return self.pe_files[library]

    def read_files_in_directory(self, directory: str) -> None:
        stack = [Path(self.game_path + directory)]

        while stack:
            current_path = stack.pop()

            for path in current_path.iterdir():
                if path.is_file():
                    with path.open("r", encoding="utf-8") as file:
                        _offsets = json.load(file).get("Offset")
                        if _offsets is None:
                            continue

                        for key, val in _offsets.items():
                            class_name = key.split("::")[0]
                            self.vtable_methods[class_name] = self.count_vtable_offset(class_name)
                elif path.is_dir():
                    stack.append(path)

    def count_vtable_offset(self, class_name: str):
        if class_name in self.vtable_methods:
            return self.vtable_methods[class_name]

        mem: PEMemory
        for _, mem in self.pe_files.items():
            class_vtable_len = mem.get_vtable_length(class_name)
            if class_vtable_len != -1:
                return class_vtable_len
        return -1

if __name__ == '__main__':
    _game_path = "E:/Steam/steamapps/common/Counter-Strike Global Offensive/game/"
    vtb = ClassInformer(_game_path)
    libs = ["server", "matchmaking", "engine2", "tier0", "networksystem"]
    for lib in libs:
        vtb.load_library(lib)

    vtb.read_files_in_directory(r"csgo/addons/source2mod/gamedata")

    offsets = [f"[{class_name}] {count}" for class_name, count in vtb.vtable_methods.items()]
    print(f"Offsets: \n" + "\n".join(offsets))