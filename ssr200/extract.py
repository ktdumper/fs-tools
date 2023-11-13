from pyfatfs.PyFatFS import PyFatFS
import os
import sys
import pathlib

fs = PyFatFS(sys.argv[1], read_only=True)
outdir = sys.argv[2]

contents = dict()

def recursively_extract(path):
    for sub in fs.scandir(path):
        if sub.is_dir:
            recursively_extract(os.path.join(path, sub.name))
        else:
            if sub.name.startswith("$__"):
                continue
            pathlib.Path(os.path.join(outdir, path)).mkdir(parents=True, exist_ok=True)

            name = os.path.join(path, sub.name)
            try:
                data = fs.openbin(name).read()
            except StopIteration:
                print("!! {} failed !!".format(name))
                continue

            with open(os.path.join(outdir, path, sub.name), "wb") as outf:
                if name in contents:
                    assert contents[name] == data
                contents[name] = data
                outf.write(data)


recursively_extract("")
