import os
import re
import sys
import struct
import json


def wrap_text(string, comment=False) -> str:
    if comment is False:
        return '-'*(len(string) + 2) + '\n|' + string + '|\n' + '-'*(len(string) + 2)
    else:
        return '#' + '-'*(len(string) + 2) + '#' + '\n# ' + string + ' #\n' + '#' + '-'*(len(string) + 2) + '#'


def get_size(file, offset: int = 0) -> int:
    ''' Return a file's size '''
    file.seek(0, 2)
    return file.tell() + offset


def get_file_alignment(file, alignment: int) -> int:
    ''' Return file alignment, 0 = aligned, non zero = misaligned '''
    size = get_size(file)

    if size % alignment != 0:
        return alignment - (size % alignment)
    else:
        return 0


def align_file(file, alignment: int, char: str = '00'):
    ''' Align a file to be the specified size '''
    file.write(bytes.fromhex(char * get_file_alignment(file, alignment)))


def byte2bool(byte: bytes) -> str:
    return "True" if byte == b"\x01" else "False"


def bool2byte(string: str) -> bytes:
    return b'\x01' if string == "True" else b"\x00"


def bit2bool(byte: bytes, idx: int, size: int = 4) -> str:
    if idx >= (size << 3):
        raise IndexError(f"Bit index {idx} is greater than a byte set")

    _val = int.from_bytes(byte, "big", signed=False)

    return "True" if (_val >> (7 - idx)) & 1 else "False"

def bool2bit(string: str, idx: int, size: int = 4) -> int:
    if idx >= (size << 3):
        raise IndexError(f"Bit index {idx} is greater than a byte set")

    _val = 1 if string == "True" else 0

    return _val << (7 - idx)


class TxtParser(object):

    @staticmethod
    def get_parent(string: str):
        return re.findall(r'(?:[a-zA-Z_])[\w\s]+(?=\s*[<0-9>]*=)', string)[0].strip()

    @staticmethod
    def get_value_size_key(string: str):
        return int(re.findall(r'(?:\s*<)([0-9]+)(?=>\s*=)', string)[0].strip())

    @staticmethod
    def get_all_key(string: str):
        string = string.partition("#")[0]
        return re.findall(r'(?:=\s*)([\w\s\-.,]*)', string)[0].strip()

    @staticmethod
    def get_hex_key(string: str, byteslength=None):
        string = string.partition("#")[0]
        try:
            key = re.findall(r'(?:=\s*)(0x[0-9a-fA-F\-]+)(?=;)', string)[0]
            if byteslength is not None:
                key = '0x{:08X}'.format(int(key[2:], 16))[8 - (byteslength << 1):]
            return key.strip()
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper hexadecimal'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_float_key(string: str):
        string = string.partition("#")[0]
        try:
            return float(re.findall(r'(?:=\s*)([0-9\-.]+)(?=;)', string)[0].strip())
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper float'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_int_key(string: str):
        string = string.partition("#")[0]
        try:
            return int(re.findall(r'(?:=\s*)([0-9\-]+)(?=;)', string)[0].strip())
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper int'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_bool_key(string: str):
        string = string.partition("#")[0]
        try:
            return re.findall(r'(?:=\s*)(True|False|true|false)(?=;)', string)[0].strip()
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper boolean'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_tuple_key(string: str):
        string = string.partition("#")[0]
        try:
            keys = re.findall(
                r'(?:=\s*\(\s*)([\w\s\-.,]+)(?=\s*\);)', string)[0]
            keys = keys.split(',')
            for i, key in enumerate(keys):
                keys[i] = key.strip()
            return tuple(keys)
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper tuple'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_list_key(string: str):
        string = string.partition("#")[0]
        try:
            keys = re.findall(
                r'(?:=\s*\[\s*)([\w\s\-.,]+)(?=\s*\];)', string)[0]
            keys = keys.split(',')
            for i, key in enumerate(keys):
                keys[i] = key.strip()
            return list(keys)
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper list'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def get_string_key(string: str):
        try:
            return str(re.findall(r'(?:=\s*\")([\s\w.\-\/!?]+)(?=\";)', string)[0])
        except IndexError:
            raise ValueError('Value "{}" at key "{}" is not a proper string'.format(
                TxtParser.get_all_key(string), TxtParser.get_parent(string)))

    @staticmethod
    def safe_write_value(file, value, size=1, byteorder='big', signed=False, allowfloat=True):
        if allowfloat is True:
            if '(' in value or ')' in value or '[' in value or ']' in value:
                raise ValueError('Value "{}" at key "{}" is not int or hexadecimal or float'.format(
                    TxtParser.get_all_key(value), TxtParser.get_parent(value)))
        else:
            if '.' in value or '(' in value or ')' in value or '[' in value or ']' in value:
                raise ValueError('Value "{}" at key "{}" is not int or hexadecimal'.format(
                    TxtParser.get_all_key(value), TxtParser.get_parent(value)))
        if '0x' in value:
            if len(value[2:]) < (size << 1):
                value = '0x' + ('0'*((size << 1) - len(value[2:]))) + value[2:]
            file.write(bytes.fromhex(value[2:]))
        elif '.' in value:
            file.write(struct.pack('>f', float(value)))
        else:
            file.write(int(value).to_bytes(
                size, byteorder=byteorder, signed=signed))


class JsonParser(object):

    def __init__(self, f: str = None):
        if f is None:
            self._data = None
            self._currentfilepath = None
            return

        self.open(f)

    def open(self, f: str):
        self._currentfilepath = f
        with open(f, "r") as jsonf:
            self._data = jsonf.read()
            self.jsonData = JsonParser._decode(self._data)

    def close(self):
        self._data = None

    def save(self, f: str = None):
        if f is None:
            f = self._currentfilepath

        with open(f, "w") as jsonf:
            json.dump(self.jsonData, jsonf)

    @staticmethod
    def _decode(data: str) -> dict:
        return json.loads(data)

class MarioParamsParser(JsonParser):

    def __init__(self, f: str = None, useFolders=False):
        super().__init__(f)
        self.attrLookupTable = SmeFileParser._init_table(self.jsonData)
        self.considerfolder = useFolders

    @staticmethod
    def _init_table(jsonData):
        _table = []
        for section in jsonData:
            for sectionName in section.keys():
                for item in section[sectionName]:
                    _table.append(item)
        return _table

    def init_file(self, f: str):
        with open(f, "w") as newfile:
            newfile.write(wrap_text("PARAMS", True) + "\n")

            for section in self.jsonData:
                for sectionName in section.keys():
                    label = sectionName.replace(" ", "-")
                    newfile.write(f"\n#--{label}--#\n\n")
                    for item in section[sectionName]:
                        name = item["name"]
                        value = item["default"]
                        comment = item["comment"]

                        if item["type"].strip() == "string":
                            value = '"' + value.strip('"') + '"'

                        if comment:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};".ljust(32, ' ') + f"# {comment}\n")
                        else:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};\n")

    def decode_bin(self, f: str, dest: str = None):
        if dest is None:
            dest = os.path.abspath(os.path.normpath(os.path.splitext(f)[
                                   0].lstrip('\\').lstrip('/') + '.txt'))
        elif self.considerfolder:
            dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[
                                0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(f)[0] + '.txt'))

        if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
            os.makedirs(os.path.dirname(dest))

        with open(f, "rb") as params_file, open(dest, "w") as newfile:
            newfile.write(wrap_text("PARAMS", True) + "\n")

            for section in self.jsonData:
                for sectionName in section.keys():
                    label = sectionName.replace(" ", "-")
                    newfile.write(f"\n#--{label}--#\n\n")
                    for item in section[sectionName]:
                        name = item["name"]
                        offset = item["offset"]
                        comment = item["comment"]

                        itemtype = item["type"].lower().replace(" ", "").rstrip("*")
                        isPointer = item["type"].strip().endswith("*")

                        if isPointer:
                            params_file.seek(offset[0])
                            offset = int.from_bytes(params_file.read(4), byteorder="big", signed=True)
                            params_file.seek(offset)
                        elif itemtype == "bit":
                            params_file.seek(offset[0])
                        else:
                            params_file.seek(offset)

                        if "f" in itemtype:
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(
                                        str(struct.unpack('>f', params_file.read(4))[0]))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = struct.unpack(
                                    '>f', params_file.read(4))[0]

                        elif itemtype == "bit":
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for i in range(len(item["default"])):
                                    _valueList.append(bit2bool(params_file.read(1), offset[1] + i))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = bit2bool(params_file.read(1), offset[1])

                        elif itemtype == "bool":
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(
                                        byte2bool(params_file.read(1)))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = byte2bool(params_file.read(1))

                        elif itemtype == "string":
                            value = ''
                            while char := params_file.read(1):
                                if char == b'\x00':
                                    break
                                value += char.decode("ascii")

                        else:
                            size = int(itemtype[1:]) >> 3

                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(str(int.from_bytes(params_file.read(
                                        size), byteorder='big', signed='s' in item["type"])))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = int.from_bytes(params_file.read(
                                    size), byteorder='big', signed='s' in item["type"])

                        if itemtype == "string":
                            value = '"' + value.strip('"') + '"'

                        if comment:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};".ljust(32, ' ') + f"# {comment}\n")
                        else:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};\n")

    def encode_txt(self, f: str, dest: str = None):
        if dest is None:
            dest = os.path.abspath(os.path.normpath(os.path.splitext(f)[0].lstrip('\\').lstrip('/') + '.bin'))
        elif self.considerfolder:
            dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(f)[0] + '.bin'))

        if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
            os.makedirs(os.path.dirname(dest))

        with open(f, "r") as txtdump, open(dest, "wb+") as params_file:
            _size = 0
            for item in self.attrLookupTable:
                if isinstance(item["offset"], int):
                    if item["offset"] > _size:
                        _size = item["offset"]
                else:
                    if item["offset"][1] > _size:
                        _size = item["offset"][1]

            params_file.write(b'\x00' * (_size + 1))
            params_file.seek(0)

            for line in txtdump:
                if line.strip() == "" or line.strip().startswith("#"):
                    continue

                thisItem = None
                _val = None

                for i, item in enumerate(self.attrLookupTable):
                    if item["name"] == TxtParser.get_parent(line).strip():
                        thisItem = self.attrLookupTable[i]
                        break

                if thisItem is None:
                    continue

                itemtype = thisItem["type"].lower().replace(" ", "").rstrip("*")
                isPointer = thisItem["type"].strip().endswith("*")

                if isPointer:
                    params_file.seek(thisItem["offset"][0])
                    params_file.write(thisItem["offset"][1].to_bytes(
                        4, byteorder="big", signed=True))
                    params_file.seek(thisItem["offset"][1])
                elif itemtype == "bit":
                    params_file.seek(thisItem["offset"][0])
                else:
                    params_file.seek(thisItem["offset"])

                if itemtype.startswith("f"):
                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            params_file.write(struct.pack(">f", float(piece)))
                    else:
                        _val = TxtParser.get_float_key(line)
                        params_file.write(struct.pack(">f", float(_val)))

                elif itemtype == "bit":
                    curVal = int.from_bytes(params_file.read(1), "big", signed=False)
                    params_file.seek(-1, 1)
                    if isinstance(item["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for i, bit in enumerate(_val):
                            params_file.write(((curVal | bool2bit(bit, thisItem["offset"][1] + i)) & 0xFF).to_bytes(1, "big", signed=False))
                    else:
                        bit = TxtParser.get_bool_key(line)
                        params_file.write(((curVal | bool2bit(bit, thisItem["offset"][1])) & 0xFF).to_bytes(1, "big", signed=False))

                elif itemtype == "bool":
                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            params_file.write(bool2byte(piece))
                    else:
                        _val = TxtParser.get_bool_key(line)
                        params_file.write(bool2byte(_val))

                elif itemtype == "string":
                    _val = TxtParser.get_string_key(line)
                    params_file.write(_val.encode("utf-8") + b"\x00")

                else:
                    size = int(thisItem["type"][1:]) >> 3

                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            TxtParser.safe_write_value(
                                params_file, piece, size, "big", 's' in thisItem["type"], False)
                    else:
                        _val = TxtParser.get_all_key(line)
                        TxtParser.safe_write_value(
                            params_file, _val, size, "big", 's' in thisItem["type"], False)

            align_file(params_file, 32)

class SmeFileParser(JsonParser):

    def __init__(self, f: str = None, useFolders=False):
        super().__init__(f)
        self.attrLookupTable = SmeFileParser._init_table(self.jsonData)
        self.considerfolder = useFolders

    @staticmethod
    def _init_table(jsonData):
        _table = []
        for section in jsonData:
            for sectionName in section.keys():
                for item in section[sectionName]:
                    _table.append(item)
        return _table

    def init_file(self, f: str):
        with open(f, "w") as newfile:
            newfile.write(wrap_text("PARAMS", True) + "\n")

            for section in self.jsonData:
                for sectionName in section.keys():
                    label = sectionName.replace(" ", "-")
                    newfile.write(f"\n#--{label}--#\n\n")
                    for item in section[sectionName]:
                        name = item["name"]
                        value = item["default"]
                        comment = item["comment"]

                        if item["type"].strip() == "string":
                            value = '"' + value.strip('"') + '"'

                        if comment:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};".ljust(32, ' ') + f"# {comment}\n")
                        else:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};\n")

    def decode_bin(self, f: str, dest: str = None):
        if dest is None:
            dest = os.path.abspath(os.path.normpath(os.path.splitext(f)[
                                   0].lstrip('\\').lstrip('/') + '.txt'))
        elif self.considerfolder:
            dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[
                                0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(f)[0] + '.txt'))

        if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
            os.makedirs(os.path.dirname(dest))

        with open(f, "rb") as params_file, open(dest, "w") as newfile:
            newfile.write(wrap_text("PARAMS", True) + "\n")

            for section in self.jsonData:
                for sectionName in section.keys():
                    label = sectionName.replace(" ", "-")
                    newfile.write(f"\n#--{label}--#\n\n")
                    for item in section[sectionName]:
                        name = item["name"]
                        offset = item["offset"]
                        comment = item["comment"]

                        itemtype = item["type"].lower().replace(" ", "").rstrip("*")
                        isPointer = item["type"].strip().endswith("*")

                        if isPointer:
                            params_file.seek(offset[0])
                            offset = int.from_bytes(params_file.read(4), byteorder="big", signed=True)
                            params_file.seek(offset)
                        elif itemtype == "bit":
                            params_file.seek(offset[0])
                        else:
                            params_file.seek(offset)

                        if "f" in itemtype:
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(
                                        str(struct.unpack('>f', params_file.read(4))[0]))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = struct.unpack(
                                    '>f', params_file.read(4))[0]

                        elif itemtype == "bit":
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for i in range(len(item["default"])):
                                    _valueList.append(bit2bool(params_file.read(1), offset[1] + i))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = bit2bool(params_file.read(1), offset[1])

                        elif itemtype == "bool":
                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(
                                        byte2bool(params_file.read(1)))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = byte2bool(params_file.read(1))

                        elif itemtype == "string":
                            value = ''
                            while char := params_file.read(1):
                                if char == b'\x00':
                                    break
                                value += char.decode("ascii")

                        else:
                            size = int(itemtype[1:]) >> 3

                            if isinstance(item["default"], (tuple, list)):
                                _valueList = []
                                for _ in range(len(item["default"])):
                                    _valueList.append(str(int.from_bytes(params_file.read(
                                        size), byteorder='big', signed='s' in item["type"])))
                                _valueList = ", ".join(_valueList)
                                value = f"[{_valueList}]"
                            else:
                                value = int.from_bytes(params_file.read(
                                    size), byteorder='big', signed='s' in item["type"])

                        if itemtype == "string":
                            value = '"' + value.strip('"') + '"'

                        if comment:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};".ljust(32, ' ') + f"# {comment}\n")
                        else:
                            newfile.write(f"{name}".ljust(
                                32, ' ') + f"=  {value};\n")

    def encode_txt(self, f: str, dest: str = None):
        if dest is None:
            dest = os.path.abspath(os.path.normpath(os.path.splitext(f)[0].lstrip('\\').lstrip('/') + '.bin'))
        elif self.considerfolder:
            dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(f)[0] + '.bin'))

        if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
            os.makedirs(os.path.dirname(dest))

        with open(f, "r") as txtdump, open(dest, "wb+") as params_file:
            _size = 0
            for item in self.attrLookupTable:
                if isinstance(item["offset"], int):
                    if item["offset"] > _size:
                        _size = item["offset"]
                else:
                    if item["offset"][1] > _size:
                        _size = item["offset"][1]

            params_file.write(b'\x00' * (_size + 1))
            params_file.seek(0)

            for line in txtdump:
                if line.strip() == "" or line.strip().startswith("#"):
                    continue

                thisItem = None
                _val = None

                for i, item in enumerate(self.attrLookupTable):
                    if item["name"] == TxtParser.get_parent(line).strip():
                        thisItem = self.attrLookupTable[i]
                        break

                if thisItem is None:
                    continue

                itemtype = thisItem["type"].lower().replace(" ", "").rstrip("*")
                isPointer = thisItem["type"].strip().endswith("*")

                if isPointer:
                    params_file.seek(thisItem["offset"][0])
                    params_file.write(thisItem["offset"][1].to_bytes(
                        4, byteorder="big", signed=True))
                    params_file.seek(thisItem["offset"][1])
                elif itemtype == "bit":
                    params_file.seek(thisItem["offset"][0])
                else:
                    params_file.seek(thisItem["offset"])

                if itemtype.startswith("f"):
                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            params_file.write(struct.pack(">f", float(piece)))
                    else:
                        _val = TxtParser.get_float_key(line)
                        params_file.write(struct.pack(">f", float(_val)))

                elif itemtype == "bit":
                    curVal = int.from_bytes(params_file.read(1), "big", signed=False)
                    params_file.seek(-1, 1)
                    if isinstance(item["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for i, bit in enumerate(_val):
                            params_file.write(((curVal | bool2bit(bit, thisItem["offset"][1] + i)) & 0xFF).to_bytes(1, "big", signed=False))
                    else:
                        bit = TxtParser.get_bool_key(line)
                        params_file.write(((curVal | bool2bit(bit, thisItem["offset"][1])) & 0xFF).to_bytes(1, "big", signed=False))

                elif itemtype == "bool":
                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            params_file.write(bool2byte(piece))
                    else:
                        _val = TxtParser.get_bool_key(line)
                        params_file.write(bool2byte(_val))

                elif itemtype == "string":
                    _val = TxtParser.get_string_key(line)
                    params_file.write(_val.encode("utf-8") + b"\x00")

                else:
                    size = int(thisItem["type"][1:]) >> 3

                    if isinstance(thisItem["default"], (tuple, list)):
                        _val = TxtParser.get_list_key(line)
                        for piece in _val:
                            TxtParser.safe_write_value(
                                params_file, piece, size, "big", 's' in thisItem["type"], False)
                    else:
                        _val = TxtParser.get_all_key(line)
                        TxtParser.safe_write_value(
                            params_file, _val, size, "big", 's' in thisItem["type"], False)

            align_file(params_file, 32)
            params_file.seek(0)
            params_file.write(b"CODE")
