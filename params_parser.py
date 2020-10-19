import os
import re
import sys
import struct
import binascii
import argparse
import glob

from io import BytesIO, RawIOBase

def wrap_text(string, comment=False):
    if comment == False:
        return '-'*(len(string) + 2) + '\n|' + string + '|\n' + '-'*(len(string) + 2)
    else:
        return '#' + '-'*(len(string) + 2) + '#' + '\n# ' + string + ' #\n' + '#' + '-'*(len(string) + 2) + '#'

def resource_path(relative_path):
    ''' Get absolute path to resource, works for dev and for PyInstaller '''
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_size(file, offset=0):
    ''' Return a file's size '''
    file.seek(0, 2)
    return file.tell() + offset

def get_file_alignment(file, alignment):
    ''' Return file alignment, 0 = aligned, non zero = misaligned '''
    size = get_size(file)

    if size % alignment != 0:
        return alignment - (size % alignment)
    else:
        return 0

def align_file(file, alignment, char='00'):
    ''' Align a file to be the specified size '''
    file.write(bytes.fromhex(char * get_file_alignment(file, alignment)))

def byte2bool(byte: str):
    if byte == b'\x01':
        return 'True'
    else:
        return 'False'

def bool2byte(string: str):
    if string == 'True':
        return b'\x01'
    else:
        return b'\x00'

def get_parent(string: str):
    return re.findall(r'(?:[a-zA-Z_])[\w\s]+(?=\s*[<0-9>]*=)', string)[0].strip()

def get_value_size_key(string: str):
    return int(re.findall(r'(?:\s*<)([0-9]+)(?=>\s*=)', string)[0].strip())

def get_all_key(string: str):
    return re.findall(r'(?:=\s*)([\w\s\-.,]*)', string)[0].strip()

def get_hex_key(string: str, byteslength=None):
    try:
        key = re.findall(r'(?:=\s*)(0x[0-9a-fA-F\-]+)(?=;)', string)[0]
        if byteslength is not None:
            key = '0x' + '{:08X}'.format(int(key[2:], 16))[8 - (byteslength << 1):]
        return key.strip()
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper hexadecimal'.format(get_all_key(string), get_parent(string)))

def get_float_key(string: str):
    try:
        return float(re.findall(r'(?:=\s*)([0-9\-.]+)(?=;)', string)[0].strip())
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper float'.format(get_all_key(string), get_parent(string)))

def get_int_key(string: str):
    try:
        return int(re.findall(r'(?:=\s*)([0-9\-]+)(?=;)', string)[0].strip())
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper int'.format(get_all_key(string), get_parent(string)))

def get_bool_key(string: str):
    try:
        return re.findall(r'(?:=\s*)(True|False|true|false)(?=;)', string)[0].strip()
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper boolean'.format(get_all_key(string), get_parent(string)))

def get_tuple_key(string: str):
    try:
        keys = re.findall(r'(?:=\s*\(\s*)([\w\s\-.,]+)(?=\s*\);)', string)[0]
        keys = keys.split(',')
        for i, key in enumerate(keys):
            keys[i] = key.strip()
        return tuple(keys)
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper tuple'.format(get_all_key(string), get_parent(string)))

def get_list_key(string: str):
    try:
        keys = re.findall(r'(?:=\s*\[\s*)([\w\s\-.,]+)(?=\s*\];)', string)[0]
        keys = keys.split(',')
        for i, key in enumerate(keys):
            keys[i] = key.strip()
        return list(keys)
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper list'.format(get_all_key(string), get_parent(string)))

def get_string_key(string: str):
    try:
        return str(re.findall(r'(?:=\s*\")([\s\w.\-\/!?]+)(?=\";)', string)[0])
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper string'.format(get_all_key(string), get_parent(string)))

def safe_write_value(file, value, size=1, byteorder='big', signed=False, allowfloat=True):
    if allowfloat == True:
        if '(' in value or ')' in value or '[' in value or ']' in value:
            parser.error('Value "{}" at key "{}" is not int or hexadecimal or float'.format(get_all_key(value), get_parent(value)))
    else:
        if '.' in value or '(' in value or ')' in value or '[' in value or ']' in value:
            parser.error('Value "{}" at key "{}" is not int or hexadecimal'.format(get_all_key(value), get_parent(value)))
    if '0x' in value:
        if len(value[2:]) < (size << 1):
            value = '0x' + ('0'*((size << 1) - len(value[2:]))) + value[2:]
        file.write(bytes.fromhex(value[2:]))
    elif '.' in value:
        file.write(struct.pack('>f', float(value)))
    else:
        file.write(int(value).to_bytes(size, byteorder=byteorder, signed=signed))

class ParamsFile():

    def __init__(self, f):
        self.rawdata = BytesIO(f.read())
        self.size = get_size(f)
        self.rawdata.seek(0)

    def get_active(self):
        self.rawdata.seek(0x1)
        return [self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1)]

    def set_active(self, active_list):
        self.rawdata.seek(0x1)
        for byte in active_list:
            self.rawdata.write(byte)

def init_attributes(dest=None):
    if dest is None:
        dest = 'mario_params.txt'

    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    activelist = ['#--Accessibles--#\n\n',
                  'Can Use Fludd'.ljust(32, ' ') + '=  True;\n',
                  'Can Ride Yoshi'.ljust(32, ' ') + '=  True;\n',
                  'Has Scuba Helmet'.ljust(32, ' ') + '=  False;\n',
                  'Has Sunglasses'.ljust(32, ' ') + '=  False;\n',
                  'Has Shine Shirt'.ljust(32, ' ') + '=  False;\n']

    with open(dest, 'w+') as txtdump:
        txtdump.write(wrap_text('PARAMS', True) + '\n\n')

        for flag in activelist:
            txtdump.write(flag)

        txtdump.write('\n#--Basic-Settings--#\n\n')

        txtdump.write('Max Jumps'.ljust(32, ' ') + '=  1;\n')
        txtdump.write('Start Health'.ljust(32, ' ') + '=  8;\n')
        txtdump.write('Max Health'.ljust(32, ' ') + '=  8;\n')
        txtdump.write('OOB Timer Step'.ljust(32, ' ') + '=  4;\n')
        txtdump.write('OOB Max Timer'.ljust(32, ' ') + '=  480;\n')

        txtdump.write('\n#--Multipliers--#\n\n')

        txtdump.write('Size XYZ Multiplier'.ljust(32, ' ') + '=  ( 1.0, 1.0, 1.0 );\n')
        txtdump.write('Gravity Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('NPC Bounce 1 Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('NPC Bounce 2 Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('NPC Bounce 3 Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('Max Fall No Damage Multi'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('Base Jump Height Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('Extra Jump Height Multiplier'.ljust(32, ' ') + '=  0.875;'.ljust(32, ' ') + '# baseJumpHeight * (multiplier^curJump)\n')
        txtdump.write('Extra Jump F-Speed Multiplier'.ljust(32, ' ') + '=  1.0;\n')
        txtdump.write('Forward Speed Multiplier'.ljust(32, ' ') + '=  1.0;\n')

        txtdump.write('\n#--Fludd-Settings--#\n\n')

        txtdump.write('Enable Spray Nozzle'.ljust(32, ' ') + '=  True;\n')
        txtdump.write('Enable Rocket Nozzle'.ljust(32, ' ') + '=  True;\n')
        txtdump.write('Enable Hover Nozzle'.ljust(32, ' ') + '=  True;\n')
        txtdump.write('Enable Turbo Nozzle'.ljust(32, ' ') + '=  True;\n')
        txtdump.write('Fludd Water Color'.ljust(32, ' ') + '=  [ 0x3C, 0x46, 0x78, 0x14 ];\n')
        txtdump.write('Fludd Cleaning Type'.ljust(32, ' ') + '=  1;'.ljust(32, ' ') + '# 0 = None, 1 = Clean, 2 = Goop\n')
        txtdump.write('Spray Nozzle Joint Index'.ljust(32, ' ') + '=  14;'.ljust(32, ' ') + '# The joint index, 14 is the chest joint\n')
        txtdump.write('Rocket Nozzle Joint Index'.ljust(32, ' ') + '=  14;'.ljust(32, ' ') + '# The joint index, 14 is the chest joint\n')
        txtdump.write('Hover Nozzle Joint Index'.ljust(32, ' ') + '=  14;'.ljust(32, ' ') + '# The joint index, 14 is the chest joint\n')
        txtdump.write('Turbo Nozzle Joint Index'.ljust(32, ' ') + '=  14;'.ljust(32, ' ') + '# The joint index, 14 is the chest joint\n')
        txtdump.write('Can Fludd Clean Seals'.ljust(32, ' ') + '=  False;'.ljust(32, ' ') + '# Yoshi seals\n')

        txtdump.write('\n#--Misc--#\n\n')

        txtdump.write('Can Breathe Underwater'.ljust(32, ' ') + '=  False;\n'.ljust(32, ' '))
        txtdump.write('Name Key'.ljust(32, ' ') + '=  "Put a name in these quotes!";')
        
def set_attributes(file, dest=None, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.bin'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.bin'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    with open(file, 'r') as txtdump, open(dest, 'wb+') as params_file:
        for line in txtdump.readlines():
            if 'Max Jumps' in line:
                params_file.seek(0)
                jumps = get_all_key(line)
                safe_write_value(params_file, jumps, 1, 'big', False, False)

            elif 'Can Use Fludd' in line:
                params_file.seek(0x1)
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Can Ride Yoshi' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Mario Has Helmet' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Mario Has Sunglasses' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Mario Has Shine Shirt' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Start Health' in line:
                params_file.seek(0x8)

                sHealth = get_all_key(line)
                safe_write_value(params_file, sHealth, 2, 'big', False, False)

            elif 'Max Health' in line:
                mHealth = get_all_key(line)
                safe_write_value(params_file, mHealth, 2, 'big', False, False)

            elif 'OB Timer Step' in line:
                sOBTimer = get_all_key(line)
                safe_write_value(params_file, sOBTimer, 2, 'big', False, False)

            elif 'OB Max Timer' in line:
                mOBTimer = get_all_key(line)
                safe_write_value(params_file, mOBTimer, 2, 'big', False, False)

            elif 'Size XYZ Multiplier' in line:
                coordinates = get_tuple_key(line)
                for coordinate in coordinates:
                    params_file.write(struct.pack('>f', float(coordinate)))

            elif 'Gravity Multiplier' in line:
                gravity = get_float_key(line)
                params_file.write(struct.pack('>f', float(gravity)))

            elif 'NPC Bounce 1 Multiplier' in line:
                bounce = get_float_key(line)
                params_file.write(struct.pack('>f', float(bounce)))
                
            elif 'NPC Bounce 2 Multiplier' in line:
                bounce = get_float_key(line)
                params_file.write(struct.pack('>f', float(bounce)))

            elif 'NPC Bounce 3 Multiplier' in line:
                bounce = get_float_key(line)
                params_file.write(struct.pack('>f', float(bounce)))

            elif 'Max Fall No Damage Multi' in line:
                falldamage = get_float_key(line)
                params_file.write(struct.pack('>f', float(falldamage)))

            elif 'Base Jump Height Multiplier' in line:
                jump = get_float_key(line)
                params_file.write(struct.pack('>f', float(jump)))

            elif 'Extra Jump Height Multiplier' in line:
                exjump = get_float_key(line)
                params_file.write(struct.pack('>f', float(exjump)))

            elif 'Extra Jump F-Speed Multiplier' in line:
                exspeed = get_float_key(line)
                params_file.write(struct.pack('>f', float(exspeed)))

            elif 'Forward Speed Multiplier' in line:
                fspeed = get_float_key(line)
                params_file.write(struct.pack('>f', float(fspeed)))

            elif 'Enable Spray Nozzle' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))

            elif 'Enable Rocket Nozzle' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))
                params_file.write(b'\x01')

            elif 'Enable Hover Nozzle' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))
            
            elif 'Enable Turbo Nozzle' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))
                params_file.write(b'\x00\x00\x00')

            elif 'Fludd Water Color' in line:
                for color in get_list_key(line):
                    safe_write_value(params_file, color, 1, 'big', False, False)

            elif 'Fludd Cleaning Type' in line:
                cleantype = get_all_key(line)
                safe_write_value(params_file, cleantype, 4, 'big', False, False)

            elif 'Spray Nozzle Joint Index' in line:
                index = get_all_key(line)
                safe_write_value(params_file, index, 1, 'big', False, False)

            elif 'Rocket Nozzle Joint Index' in line:
                index = get_all_key(line)
                safe_write_value(params_file, index, 1, 'big', False, False)
                params_file.write(b'\x0E')

            elif 'Hover Nozzle Joint Index' in line:
                index = get_all_key(line)
                safe_write_value(params_file, index, 1, 'big', False, False)

            elif 'Turbo Nozzle Joint Index' in line:
                index = get_all_key(line)
                safe_write_value(params_file, index, 1, 'big', False, False)
                params_file.write(b'\x0E\x0E\x0E')

            elif 'Can Fludd Clean Seals' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))
                align_file(params_file, 4)

            elif 'Can Breathe Underwater' in line:
                boolean = get_bool_key(line)
                params_file.write(bool2byte(boolean))
                align_file(params_file, 0x40)

            elif 'Name Key' in line:
                name = get_string_key(line)
                params_file.write(name.encode('utf-8') + b'\x00')
                align_file(params_file, 32)


def get_attributes(file, dest=None, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.txt'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.txt'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    activelist = ['#--Accessibles--#\n\n',
                  'Can Use Fludd'.ljust(32, ' ') + '=  ',
                  'Can Ride Yoshi'.ljust(32, ' ') + '=  ',
                  'Has Scuba Helmet'.ljust(32, ' ') + '=  ',
                  'Has Sunglasses'.ljust(32, ' ') + '=  ',
                  'Has Shine Shirt'.ljust(32, ' ') + '=  ']
    
    with(open(file, 'rb')) as params_file:
        paramFile = ParamsFile(params_file)

    with open(dest, 'w+') as txtdump:
        txtdump.write(wrap_text('PARAMS', True) + '\n\n')
        
        for i, item in enumerate(paramFile.get_active()):
            txtdump.write(activelist[i] + byte2bool(item) + ';\n')

        paramFile.rawdata.seek(0)

        txtdump.write('\n#--Basic-Settings--#\n\n')

        txtdump.write('Max Jumps'.ljust(32, ' ') + '=  {};\n'.format(int.from_bytes(paramFile.rawdata.read(1),
                                                                        byteorder='big',
                                                                        signed=False)))

        paramFile.rawdata.seek(0x8)

        txtdump.write('Start Health'.ljust(32, ' ') + '=  {};\n'.format(int.from_bytes(paramFile.rawdata.read(2),
                                                                         byteorder='big',
                                                                         signed=False)))
        txtdump.write('Max Health'.ljust(32, ' ') + '=  {};\n'.format(int.from_bytes(paramFile.rawdata.read(2),
                                                                       byteorder='big',
                                                                       signed=False)))
        txtdump.write('OOB Timer Step'.ljust(32, ' ') + '=  {};\n'.format(int.from_bytes(paramFile.rawdata.read(2),
                                                                           byteorder='big',
                                                                           signed=False)))
        txtdump.write('OOB Max Timer'.ljust(32, ' ') + '=  {};\n'.format(int.from_bytes(paramFile.rawdata.read(2),
                                                                          byteorder='big',
                                                                          signed=False)))

        txtdump.write('\n#--Multipliers--#\n\n')

        sizeMultiplier = struct.unpack('>fff', paramFile.rawdata.read(12))
        txtdump.write('Size XYZ Multiplier'.ljust(32, ' ') + '=  ( {}, {}, {} );\n'.format(sizeMultiplier[0],
                                                                           sizeMultiplier[1],
                                                                           sizeMultiplier[2]))

        txtdump.write('Gravity Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 1 Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 2 Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 3 Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('Max Fall No Damage Multi'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('Base Jump Height Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('Extra Jump Height Multiplier'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(struct.unpack('>f', paramFile.rawdata.read(4))[0]) + '#baseJumpHeight * (multiplier^curJump)\n')
        txtdump.write('Extra Jump F-Speed Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        txtdump.write('Forward Speed Multiplier'.ljust(32, ' ') + '=  {};\n'.format(struct.unpack('>f', paramFile.rawdata.read(4))[0]))
        
        txtdump.write('\n#--Fludd-Settings--#\n\n')

        txtdump.write('Enable Spray Nozzle'.ljust(32, ' ') + '=  {};\n'.format(byte2bool(paramFile.rawdata.read(1))))
        txtdump.write('Enable Rocket Nozzle'.ljust(32, ' ') + '=  {};\n'.format(byte2bool(paramFile.rawdata.read(1))))

        paramFile.rawdata.seek(1, 1)

        txtdump.write('Enable Hover Nozzle'.ljust(32, ' ') + '=  {};\n'.format(byte2bool(paramFile.rawdata.read(1))))
        txtdump.write('Enable Turbo Nozzle'.ljust(32, ' ') + '=  {};\n'.format(byte2bool(paramFile.rawdata.read(1))))

        paramFile.rawdata.seek(3, 1)
        
        txtdump.write('Fludd Water Color'.ljust(32, ' ') + '=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(paramFile.rawdata.read(1).hex().upper(),
                                                                                     paramFile.rawdata.read(1).hex().upper(),
                                                                                     paramFile.rawdata.read(1).hex().upper(),
                                                                                     paramFile.rawdata.read(1).hex().upper()))

        txtdump.write('Fludd Cleaning Type'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(int.from_bytes(paramFile.rawdata.read(4),
                                                                                            byteorder='big',
                                                                                            signed=False)) + '# 0 = None, 1 = Clean, 2 = Goop\n')
        txtdump.write('Spray Nozzle Joint Index'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(int.from_bytes(paramFile.rawdata.read(1),
                                                                                                 byteorder='big',
                                                                                                 signed=False)) + '# The index of the joint, 14 is the chest joint\n')
        txtdump.write('Rocket Nozzle Joint Index'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(int.from_bytes(paramFile.rawdata.read(1),
                                                                                                  byteorder='big',
                                                                                                  signed=False)) + '# The index of the joint, 14 is the chest joint\n')
        paramFile.rawdata.seek(1, 1)
        
        txtdump.write('Hover Nozzle Joint Index'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(int.from_bytes(paramFile.rawdata.read(1),
                                                                                                 byteorder='big',
                                                                                                 signed=False)) + '# The index of the joint, 14 is the chest joint\n')
        txtdump.write('Turbo Nozzle Joint Index'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(int.from_bytes(paramFile.rawdata.read(1),
                                                                                                 byteorder='big',
                                                                                                 signed=False)) + '# The index of the joint, 14 is the chest joint\n')
        paramFile.rawdata.seek(3, 1)
        
        txtdump.write('Can Fludd Clean Seals'.ljust(32, ' ') + '=  {};'.ljust(32, ' ').format(byte2bool(paramFile.rawdata.read(1))) + '# Yoshi seals\n')
        
        txtdump.write('\n#--Misc--#\n\n')
        
        paramFile.rawdata.seek(0x5C)

        txtdump.write('Can Breathe Underwater'.ljust(32, ' ') + '=  {};\n'.ljust(32, ' ').format(byte2bool(paramFile.rawdata.read(1))))

        paramFile.rawdata.seek(0xA0)

        namekey = ''
        while char := paramFile.rawdata.read(1):
            if char == b'\x00':
                break
            namekey += char.decode('utf-8')

        txtdump.write('Name Key'.ljust(32, ' ') + '=  "{}";\n'.format(namekey))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='params.bin parser for SMS modding using the SME engine',
                                     description='Create/Edit/Save/Extract params.bin files',
                                     allow_abbrev=False)

    parser.add_argument('file', help='input file')
    parser.add_argument('-d', '--dump',
                        help='Dump parsed params.bin file output to a txt file',
                        action='store_true')
    parser.add_argument('-c', '--compile',
                        help='Compile a txt file into params.bin',
                        action='store_true')
    parser.add_argument('-i', '--init',
                        help='Create a clean txt template',
                        action='store_true')
    parser.add_argument('--dest',
                        help='Where to create/dump contents to',
                        metavar = 'filepath')

    args = parser.parse_args()

    matchingfiles = glob.glob(args.file)

    if len(matchingfiles) > 1:
        considerfolder = True
    else:
        considerfolder = False

    try:
        if len(matchingfiles) > 0:
            for filename in matchingfiles:
                if not filename.lower().endswith('.bin') and args.dump == True:
                    print('Input file is not a .bin file')
                    continue
                elif not filename.lower().endswith('.txt') and args.compile == True:
                    print('Input file is not a .txt file')
                    continue
                
                if args.dump == True:
                    if args.dest is not None:
                        get_attributes(filename, args.dest, considerfolder)
                    else:
                        get_attributes(filename)
                elif args.compile == True:
                    if args.dest is not None:
                        set_attributes(filename, args.dest, considerfolder)
                    else:
                        set_attributes(filename)
                elif args.init == True:
                    init_attributes(filename)
                else:
                    parser.print_help(sys.stderr)
        else:
            if args.init == True:
                init_attributes(args.file)
            else:
                parser.print_help(sys.stderr)
    except FileNotFoundError as e:
        parser.error(e)
    sys.exit(1)
