import argparse
import glob
import os
import sys

from dataparsers import MarioParamsParser

def resource_path(relative_path: str = "") -> str:
    """ Get absolute path to resource, works for dev and for cx_freeze """
    if getattr(sys, "frozen", False):
        # The application is frozen
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
        
    return os.path.join(base_path, relative_path)

def get_program_folder(folder: str = "") -> str:
    """ Get path to appdata """
    if sys.platform == "win32":
        datapath = os.path.join(os.getenv("APPDATA"), folder)
    elif sys.platform == "darwin":
        if folder:
            folder = "." + folder
        datapath = os.path.join(os.path.expanduser("~"), "Library", "Application Support", folder)
    elif "linux" in sys.platform:
        if folder:
            folder = "." + folder
        datapath = os.path.join(os.getenv("HOME"), folder)
    else:
        raise NotImplementedError(f"{sys.platform} OS is unsupported")
    return datapath

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='params.bin parser for SMS modding using the SME engine',
                                     description='Create/Edit/Save/Extract params.bin files',
                                     allow_abbrev=False)

    parser.add_argument('file', help='input file')
    parser.add_argument('job',
                        help="Job to execute. Valid jobs are `i', `c' and `d'",
                        choices=['i', 'c', 'd'])
    parser.add_argument('--dest',
                        help='Where to create/dump contents to',
                        metavar = 'filepath')

    args = parser.parse_args()

    matchingfiles = glob.glob(args.file)
    paramParser = MarioParamsParser(resource_path("params.json"), useFolders=(len(matchingfiles) > 1))

    try:
        if len(matchingfiles) > 0:
            for filename in matchingfiles:
                if args.job == 'd':
                    if not filename.lower().endswith('.bin'):
                        print(f'{filename} is not a .bin file')
                        continue
                    paramParser.decode_bin(filename, args.dest)
                elif args.job == 'c':
                    if not filename.lower().endswith('.txt'):
                        print('Input file is not a .txt file')
                        continue
                    paramParser.encode_txt(filename, args.dest)
                elif args.job == 'i':
                    paramParser.init_file(filename)
                else:
                    parser.print_help(sys.stderr)
        else:
            if args.job == 'i':
                paramParser.init_file(args.file)
            else:
                parser.print_help(sys.stderr)
    except FileNotFoundError as e:
        parser.error(e)
