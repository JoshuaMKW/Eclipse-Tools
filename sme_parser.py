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
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_size(file, offset=0):
    """ Return a file's size """
    file.seek(0, 2)
    return file.tell() + offset

def getFileAlignment(file, alignment):
    """ Return file alignment, 0 = aligned, non zero = misaligned """
    size = get_size(file)

    if size % alignment != 0:
        return alignment - (size % alignment)
    else:
        return 0

def alignFile(file, alignment, char='00'):
    """ Align a file to be the specified size """
    file.write(bytes.fromhex(char * getFileAlignment(file, alignment)))

def byte2bool(byte: str):
    if byte == b'\x01':
        return "True"
    else:
        return "False"

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

class SMEFile():

    def __init__(self, f):
        self.rawdata = BytesIO(f.read())
        self.size = get_size(f).to_bytes(4, byteorder='big', signed=False)
        f.seek(0)
        self.magic = f.read(4)
        self.loadAddress = f.read(4)
        self.markedSize = f.read(4)
        self.totalSections = f.read(1)
        sectionType = int.from_bytes(f.read(1), byteorder="big", signed=True)
        if sectionType == 1:
            self.isExecutable = True
        else:
            self.isExecutable = False
        self.nextSectionOffset = f.read(2)
        self.activeTypes = self.get_active()
        self.rawdata.seek(0)

    def get_active(self):
        self.rawdata.seek(0x10)
        return [self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1), self.rawdata.read(1)]

    def set_active(self, active_list):
        self.rawdata.seek(0x10)
        for byte in active_list:
            self.rawdata.write(byte)

def init_attributes(dump=None):
    if dump is None:
        dump = 'smefile.txt'

    if not os.path.exists(os.path.dirname(dump)) and os.path.dirname(dump) not in ('', '/'):
        os.makedirs(os.path.dirname(dump))

    activelist = ['Modify Light\t\t=  False;\n',
                  'Modify Mario\t\t=  False;\n',
                  'Modify Yoshi\t\t=  False;\n',
                  'Modify Music\t\t=  False;\n',
                  'Modify Fludd\t\t=  False;\n']

    with open(dump, 'w+') as txtdump:
        txtdump.write(wrap_text('SME FILE', True) + '\n\n')
        txtdump.write('Initialize Address\t=  0x00000000;\t#(0 = Load into internal heap)\n\n')
        txtdump.write('Is Extra Stage\t\t=  False;\n')
        txtdump.write('Is Diving Stage\t\t=  False;\n')
        txtdump.write('Is Option Stage\t\t=  False;\n')
        txtdump.write('Is Multiplayer Stage\t=  False;\n\n')
        for flag in activelist:
            txtdump.write(flag)

        txtdump.write('\n#--LIGHT--#\n')
        txtdump.write('Light State\t\t=  0x01;\t#(0 = None, 1 = StaticPos, 2 = Follow Mario)\n')
        txtdump.write('XYZ Coordinates\t\t=  ( 0.0, 3600.0, -7458.0 );\n')
        txtdump.write('Light Size\t\t=  8000.0;\n')
        txtdump.write('Layer Step\t\t=  100.0;\n')
        txtdump.write('Light RGBA\t\t=  [ 0x00, 0x14, 0x28, 0x00 ];\n')
        txtdump.write('Layers\t\t\t=  0x05;\n')
        txtdump.write('Lightness\t\t=  0xFF;\t#(if 0xFF (255), it is auto calculated in game)\n')

        #MARIO
        txtdump.write('\n#--MARIO--#\n')
        txtdump.write('Has Fludd\t\t=  True;\n')
        txtdump.write('Has Helmet\t\t=  False;\n')
        txtdump.write('Has Shades\t\t=  False;\n')
        txtdump.write('Has Shirt\t\t=  False;\n')
        txtdump.write('Speed Multiplier\t=  0.9765625;\n')
        txtdump.write('Gravity Multiplier\t=  1.0;\n')
        txtdump.write('NPC Bounce 1\t\t=  35.0;\n')
        txtdump.write('NPC Bounce 2\t\t=  45.0;\n')
        txtdump.write('NPC Bounce 3\t\t=  70.0;\n')
        txtdump.write('Max No Damage Fall\t=  2048.0;\n')
        txtdump.write('Health\t\t\t=  0x08;\n')
        txtdump.write('Max Health\t\t=  0x08;\n')
        txtdump.write('OOB Timer Step\t\t=  0x0004;\n')
        txtdump.write('OOB Max Timer\t\t=  0x01E0;\n')
        
        #YOSHI
        txtdump.write('\n#--YOSHI--#\n')
        txtdump.write('Max Juice\t\t=  0x5334;\n')
        txtdump.write('Green Yoshi RGBA\t=  [ 0x40, 0xA1, 0x24, 0xFF ];\n')
        txtdump.write('Orange Yoshi RGBA\t=  [ 0xFF, 0x8C, 0x1C, 0xFF ];\n')
        txtdump.write('Purple Yoshi RGBA\t=  [ 0xAA, 0x4C, 0xFF, 0xFF ];\n')
        txtdump.write('Pink Yoshi RGBA\t\t=  [ 0xFF, 0xA0, 0xBE, 0xFF ];\n')
        txtdump.write('Max YSpd Init Flutter\t=  -5.0;\n')
        txtdump.write('Flutter Acceleration\t=  1.2000000476837158;\n')
        txtdump.write('Max Flutter Length\t=  0x0078;\n')
        txtdump.write('Green Yoshi Mod\t\t=  False;\n')
        txtdump.write('Free Egg Hatch\t\t=  False;\n')

        #MUSIC
        txtdump.write('\n#--MUSIC--#\n')
        txtdump.write('Volume\t\t\t=  0.75;\t#(Between 0 and 1 inclusive)\n')
        txtdump.write('Speed\t\t\t=  1.0;\t\t#(Lower number = faster)\n')
        txtdump.write('Pitch\t\t\t=  1.0;\n')
        txtdump.write('Play Music\t\t=  True;\n')
        txtdump.write('Music ID\t\t=  0x0000;\n')
        txtdump.write('Area ID\t\t\t=  0x00;\t#(Used for sound bank search)\n')
        txtdump.write('Episode ID\t\t=  0x00;\t#(Used for sound bank search)\n')

        #FLUDD
        txtdump.write('\n#--FLUDD--#\n')
        txtdump.write('Primary Nozzle\t\t=  0x00;\t#(0 = Spray, 1 = Rocket, 2 = UnderWater\n\t\t\t\t\t# 3 = Yoshi, 4 = Hover, 5 = Turbo)\n')
        txtdump.write('Secondary Nozzle\t=  0x04;\t#(0 = Spray, 1 = Rocket, 2 = UnderWater\n\t\t\t\t\t# 3 = Yoshi, 4 = Hover, 5 = Turbo)\n')
        txtdump.write('Water RGBA\t\t=  [ 0x3C, 0x46, 0x78, 0x14 ];\n')
        txtdump.write('Change Water Color\t=  False;\n')
        
def set_attributes(file, dump=None, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.sme'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.sme'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    with open(file, 'r') as txtdump, open(dump, 'wb+') as sme_file:
        sme_file.write(b'CODE')
        for line in txtdump.readlines():
            if "Initialize Address" in line:
                address = bytes.fromhex(get_hex_key(line, 4)[2:])
                sme_file.write(address + b'\x00\x00\x00\xA0\x00\x00\x00\x10')

            elif "Is Extra Stage" in line:
                sme_file.seek(0x18)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 3)

                sme_file.seek(0x18)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Is Diving Stage" in line:
                sme_file.seek(0x18)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 2)

                sme_file.seek(0x18)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Is Option Stage" in line:
                sme_file.seek(0x18)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 1)

                sme_file.seek(0x18)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Is Multiplayer Stage" in line:
                sme_file.seek(0x18)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= boolean

                sme_file.seek(0x18)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Modify Light" in line:
                sme_file.seek(0x10)
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Modify Mario" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Modify Yoshi" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Modify Music" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))
                
            elif "Modify Fludd" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Light State" in line:
                state = bytes.fromhex(get_hex_key(line, 1)[2:])
                sme_file.write(state)

            elif "XYZ Coordinates" in line:
                alignFile(sme_file, 16)
                coordinates = get_tuple_key(line)
                for coordinate in coordinates:
                    sme_file.write(struct.pack('>f', float(coordinate)))

            elif "Light Size" in line:
                size = get_float_key(line)
                sme_file.write(struct.pack('>f', float(size)))

            elif "Layer Step" in line:
                step = get_float_key(line)
                sme_file.write(struct.pack('>f', float(step)))

            elif "Light RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)

            elif "Layers" in line:
                layers = get_all_key(line)
                safe_write_value(sme_file, layers, 1, 'big', False, False)

            elif "Lightness" in line:
                lightness = get_all_key(line)
                safe_write_value(sme_file, lightness, 1, 'big', False, False)
                alignFile(sme_file, 4)

            elif "Has Fludd" in line:
                sme_file.seek(0x16)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 3)

                sme_file.seek(0x16)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Has Helmet" in line:
                sme_file.seek(0x16)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 2)

                sme_file.seek(0x16)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Has Shades" in line:
                sme_file.seek(0x16)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= (boolean << 1)

                sme_file.seek(0x16)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Has Shirt" in line:
                sme_file.seek(0x16)

                state = int.from_bytes(sme_file.read(2), byteorder='big', signed=False)
                boolean = int.from_bytes(bool2byte(get_bool_key(line)), byteorder='big', signed=False)
                state |= boolean

                sme_file.seek(0x16)
                sme_file.write(state.to_bytes(length=2, byteorder='big', signed=False))

            elif "Speed Multiplier" in line:
                sme_file.seek(0x3C)
                speed = get_float_key(line)
                sme_file.write(struct.pack('>f', float(speed)))

            elif "Gravity Multiplier" in line:
                gravity = get_float_key(line)
                sme_file.write(struct.pack('>f', float(gravity)))
                
            elif "NPC Bounce 1" in line:
                npcbounceA = get_float_key(line)
                sme_file.write(struct.pack('>f', float(npcbounceA)))
                
            elif "NPC Bounce 2" in line:
                npcbounceB = get_float_key(line)
                sme_file.write(struct.pack('>f', float(npcbounceB)))
                
            elif "NPC Bounce 3" in line:
                npcbounceC = get_float_key(line)
                sme_file.write(struct.pack('>f', float(npcbounceC)))
                
            elif "Max No Damage Fall" in line:
                falldamage = get_float_key(line)
                sme_file.write(struct.pack('>f', float(falldamage)))

            elif "Health" in line:
                health = get_all_key(line)
                safe_write_value(sme_file, health, 2, 'big', False, False)

            elif "Max Health" in line:
                maxhealth = get_all_key(line)
                safe_write_value(sme_file, maxhealth, 2, 'big', False, False)
            
            elif "OOB Timer Step" in line:
                oobstep = get_all_key(line)
                safe_write_value(sme_file, oobstep, 2, 'big', False, False)

            elif "OOB Max Timer" in line:
                oobmax = get_all_key(line)
                safe_write_value(sme_file, oobmax, 2, 'big', False, False)
                alignFile(sme_file, 16)

            elif "Max Juice" in line:
                maxjuice = get_all_key(line)
                safe_write_value(sme_file, maxjuice, 4, 'big', False, False)

            elif "Green Yoshi RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)
            
            elif "Orange Yoshi RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)

            elif "Purple Yoshi RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)

            elif "Pink Yoshi RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)

            elif "Max YSpd Init Flutter" in line:
                yflutter = get_float_key(line)
                sme_file.write(struct.pack('>f', float(yflutter)))

            elif "Flutter Acceleration" in line:
                flutteraccel = get_float_key(line)
                sme_file.write(struct.pack('>f', float(flutteraccel)))

            elif "Max Flutter Length" in line:
                flutterlen = get_all_key(line)
                safe_write_value(sme_file, flutterlen, 2, 'big', False, False)

            elif "Green Yoshi Mod" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Free Egg Hatch" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Volume" in line:
                volume = get_float_key(line)
                sme_file.write(struct.pack('>f', float(volume)))

            elif "Speed" in line:
                speed = get_float_key(line)
                sme_file.write(struct.pack('>f', float(speed)))

            elif "Pitch" in line:
                pitch = get_float_key(line)
                sme_file.write(struct.pack('>f', float(pitch)))

            elif "Play Music" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))

            elif "Music ID" in line:
                musicid = get_all_key(line)
                safe_write_value(sme_file, musicid, 2, 'big', False, False)

            elif "Area ID" in line:
                areaid = get_all_key(line)
                safe_write_value(sme_file, areaid, 1, 'big', False, False)

            elif "Episode ID" in line:
                episodeid = get_all_key(line)
                safe_write_value(sme_file, episodeid, 1, 'big', False, False)

            elif "Primary Nozzle" in line:
                mainnozzle = get_all_key(line)
                safe_write_value(sme_file, mainnozzle, 1, 'big', False, False)

            elif "Secondary Nozzle" in line:
                secondnozzle = get_all_key(line)
                safe_write_value(sme_file, secondnozzle, 1, 'big', False, False)

            elif "Water RGBA" in line:
                RGBA = get_list_key(line)
                for color in RGBA:
                    safe_write_value(sme_file, color, 1, 'big', False, False)

            elif "Change Water Color" in line:
                boolean = get_bool_key(line)
                sme_file.write(bool2byte(boolean))
                alignFile(sme_file, 16, char='FF')


def get_attributes(file, dump=None, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.txt'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.txt'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    activelist = ['Modify Light\t\t=  ',
                  'Modify Mario\t\t=  ',
                  'Modify Yoshi\t\t=  ',
                  'Modify Music\t\t=  ',
                  'Modify Fludd\t\t=  ']
    
    with(open(file, 'rb')) as smeFile:
        sme_file = SMEFile(smeFile)

    with open(dump, 'w+') as txtdump:
        txtdump.write(wrap_text('SME FILE', True) + '\n\n')
        sme_file.rawdata.seek(0x4)
        txtdump.write('Initialize Address\t=  0x{};\t#(0 = Load into internal heap)\n\n'.format(sme_file.loadAddress.hex().upper()))
        
        sme_file.rawdata.seek(0x18)
        stagetypes = int.from_bytes(sme_file.rawdata.read(1), byteorder='big', signed=False)

        if (stagetypes & 0x8) == 1:
            txtdump.write('Is Extra Stage\t\t=  True;\n')
        else:
            txtdump.write('Is Extra Stage\t\t=  False;\n')
        if (stagetypes & 0x4) == 1:
            txtdump.write('Is Diving Stage\t\t=  True;\n')
        else:
            txtdump.write('Is Diving Stage\t\t=  False;\n')
        if (stagetypes & 0x2) == 1:
            txtdump.write('Is Option Stage\t\t=  True;\n')
        else:
            txtdump.write('Is Option Stage\t\t=  False;\n')
        if (stagetypes & 0x1) == 1:
            txtdump.write('Is Multiplayer Stage\t=  True;\n\n')
        else:
            txtdump.write('Is Multiplayer Stage\t=  False;\n\n')
        
        for i, item in enumerate(sme_file.activeTypes):
            txtdump.write(activelist[i] + byte2bool(item) + ';\n')

        #LIGHT
        txtdump.write('\n#--LIGHT--#\n')
        sme_file.rawdata.seek(0x15)
        txtdump.write('Light State\t\t=  0x{};\t#(0 = None, 1 = StaticPos, 2 = Follow Mario)\n'.format(sme_file.rawdata.read(1).hex().upper()))
        sme_file.rawdata.seek(0x20)
        lightcoordinates = struct.unpack('>fff', sme_file.rawdata.read(12))
        txtdump.write('XYZ Coordinates\t\t=  ( {}, {}, {} );\n'.format(lightcoordinates[0],
                                                                   lightcoordinates[1],
                                                                   lightcoordinates[2]))
        txtdump.write('Light Size\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Layer Step\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Light RGBA\t\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Layers\t\t\t=  0x{};\n'.format(sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Lightness\t\t=  0x{};\t#(if 0xFF (255), it is auto calculated in game)\n'.format(sme_file.rawdata.read(1).hex().upper()))

        #MARIO
        txtdump.write('\n#--MARIO--#\n')
        sme_file.rawdata.seek(0x16)
        marioStates = int.from_bytes(sme_file.rawdata.read(2), byteorder='big', signed=False)

        if (marioStates & 0x80) == 1:
            txtdump.write('Has Fludd\t\t=  True;\n')
        else:
            txtdump.write('Has Fludd\t\t=  False;\n')
        if (marioStates & 0x40) == 1:
            txtdump.write('Has Helmet\t\t=  True;\n')
        else:
            txtdump.write('Has Helmet\t\t=  False;\n')
        if (marioStates & 0x20) == 1:
            txtdump.write('Has Shades\t\t=  True;\n')
        else:
            txtdump.write('Has Shades\t\t=  False;\n')
        if (marioStates & 0x10) == 1:
            txtdump.write('Has Shirt\t\t=  True;\n')
        else:
            txtdump.write('Has Shirt\t\t=  False;\n')

        sme_file.rawdata.seek(0x3C)
        txtdump.write('Speed Multiplier\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Gravity Multiplier\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 1\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 2\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('NPC Bounce 3\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Max No Damage Fall\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Health\t\t\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        txtdump.write('Max Health\t\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        txtdump.write('OOB Timer Step\t\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        txtdump.write('OOB Max Timer\t\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        
        #YOSHI
        txtdump.write('\n#--YOSHI--#\n')
        sme_file.rawdata.seek(0x60)
        txtdump.write('Max Juice\t\t=  0x{:04X};\n'.format(int.from_bytes(sme_file.rawdata.read(4), byteorder='big', signed=True)))
        txtdump.write('Green Yoshi RGBA\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Orange Yoshi RGBA\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Purple Yoshi RGBA\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Pink Yoshi RGBA\t\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Max YSpd Init Flutter\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Flutter Acceleration\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Max Flutter Length\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        txtdump.write('Green Yoshi Mod\t\t=  {};\n'.format(byte2bool(sme_file.rawdata.read(1))))
        txtdump.write('Free Egg Hatch\t\t=  {};\n'.format(byte2bool(sme_file.rawdata.read(1))))

        #MUSIC
        txtdump.write('\n#--MUSIC--#\n')
        sme_file.rawdata.seek(0x80)
        txtdump.write('Volume\t\t\t=  {};\t#(Between 0 and 1 inclusive)\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Speed\t\t\t=  {};\t\t#(Lower number = faster)\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Pitch\t\t\t=  {};\n'.format(struct.unpack('>f', sme_file.rawdata.read(4))[0]))
        txtdump.write('Play Music\t\t=  {};\n'.format(byte2bool(sme_file.rawdata.read(1))))
        txtdump.write('Music ID\t\t=  0x{};\n'.format(sme_file.rawdata.read(2).hex().upper()))
        txtdump.write('Area ID\t\t\t=  0x{};\t#(Used for sound bank search)\n'.format(sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Episode ID\t\t=  0x{};\t#(Used for sound bank search)\n'.format(sme_file.rawdata.read(1).hex().upper()))

        #FLUDD
        txtdump.write('\n#--FLUDD--#\n')
        sme_file.rawdata.seek(0x90)
        txtdump.write('Primary Nozzle\t\t=  0x{};\t#(0 = Spray, 1 = Rocket, 2 = UnderWater\n\t\t\t\t\t# 3 = Yoshi, 4 = Hover, 5 = Turbo)\n'.format(sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Secondary Nozzle\t=  0x{};\t#(0 = Spray, 1 = Rocket, 2 = UnderWater\n\t\t\t\t\t# 3 = Yoshi, 4 = Hover, 5 = Turbo)\n'.format(sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Water RGBA\t\t=  [ 0x{}, 0x{}, 0x{}, 0x{} ];\n'.format(sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper(),
                                                            sme_file.rawdata.read(1).hex().upper()))
        txtdump.write('Change Water Color\t=  {};\n'.format(byte2bool(sme_file.rawdata.read(1))))
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='SME File Parser',
                                     description='Process .sme files',
                                     allow_abbrev=False)

    parser.add_argument('file', help='input file')
    parser.add_argument('-d', '--dump',
                        help='Dump parsed sme file output to a txt file',
                        action='store_true')
    parser.add_argument('-c', '--compile',
                        help='Compile a txt file into .sme',
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
                if not filename.lower().endswith('.sme') and args.dump == True:
                    print('Input file is not a .sme file')
                    continue
                elif not filename.lower().endswith('.txt') and args.compile == True:
                    print('Input file is not a .txt file')
                    continue
                
                if args.dump == True:
                    if args.dest is not None:
                        get_attributes(filename, args.dest)
                    else:
                        get_attributes(filename)
                elif args.compile == True:
                    if args.dest is not None:
                        set_attributes(filename, args.dest)
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