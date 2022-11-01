#!/usr/bin/python3
import hashlib
import socket
import sys
import subprocess
import os
import magic
from tabulate import tabulate

# File size
def convert_bytes(num):
    """
        this function will convert bytes to MB.... GB... etc
        """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(file_path):
    """
        this function will return the file size
        """
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)


def get_tlsh(filename):
    the_val = ""
    try:
        the_val = tlsh.hash(open(filename, 'rb').read())
    except:
        the_val = ""
    return the_val


def get_hash(filename):
    fh = open(filename, 'rb')
    m = hashlib.md5()
    s = hashlib.sha1()
    s256 = hashlib.sha256()
    s512 = hashlib.sha512()
    while True:
        data = fh.read(8192)
        if not data:
            break

        m.update(data)
        s.update(data)
        s256.update(data)
        s512.update(data)

    md5 = m.hexdigest()
    sha1 = s.hexdigest()
    sha256 = s256.hexdigest()
    sha512 = s512.hexdigest()

    return md5, sha1, sha256, sha512


def print_hex(file_hndl, pos, length, matched):
    file_hndl.seek(pos)
    for i in range((length//16) + 1):
        b = file_hndl.read(16)
        hex_str = " ".join([f"{i:02x}" for i in b])
        hex_str = hex_str[0:23] + " " + hex_str[23:]
        ascii = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])
        print(f"\033[38;5;15m{(i*16)+pos:08x}:\033[0m  \033[90m{hex_str} \033[93m| \033[90m{ascii}\033[93m |\033[0m")


def processor(yara_params, line_multi):
    
    proc = subprocess.Popen(yara_params, stdout=subprocess.PIPE)
    cur_file = None
    cur_file_hndl = None
    col_names = ["\033[1mMatched\033[0m", "\033[1mYara information.\033[0m"]
    while True:
        line = proc.stdout.readline().rstrip()
        if not line:
            break
        #print(">", line.decode())
        if not line.startswith(b"0x"):
            cur_file = line.split(maxsplit=2)[1].decode()
            #print('\033[91m[!] '+cur_file)
            #print(proc.stdout.readline().rstrip())
            if cur_file_hndl:
                cur_file_hndl.close()
                cur_file_hndl = None
        else:
            if not cur_file:
                continue

            if not cur_file_hndl:
                cur_file_hndl = open(cur_file, "rb")
            pos, str_name, match_str = line.split(b":", maxsplit=3)

            pos = int(pos.decode(), 16)
            match_str_len = len(match_str) - match_str.count(b"\\x")*4
            """print('\033[91m[!] Matched!')
            print('[!] offset: '+hex(pos))
            print('[!] string: '+str_name.decode())
            print('[!] matched: '+match_str.decode()+'\033[0m')
            #print(hex(pos), str_name.decode(), match_str_len, sep=":")"""
            content = [["\033[90mfilename\033[0m", '\033[91m'+cur_file+'\033[0m'],
                        ["\033[90moffset\033[0m", '\033[91m'+hex(pos)+'\033[0m'],
                        ["\033[90mstring\033[0m", '\033[91m'+str_name.decode()+'\033[0m'],
                        ["\033[90mmatched\033[0m", '\033[91m'+match_str.decode()+'\033[0m'],


            ]
            prompt = '\033[38;5;15m[ENGINE@CORE]\033[38;5;3m:>\033[0m'
            print("\n{} \033[91mRule::hit_{}\033[0m \n".format(prompt, str_name.decode()))
            prompt = '\033[38;5;15m[{}]\033[38;5;3m:>'.format(hex(pos))
            print(tabulate(content,  headers=col_names, tablefmt="grid"))
            print(" \n{} \033[0mHexdump@matched::offset\033[0m\n".format(prompt) )
            print("\033[92moffset     hex                                               ascii\033[0m")
            print_hex(cur_file_hndl, pos, match_str_len+line_multi if line_multi else match_str_len*4, match_str)
            

    proc.terminate()
    if cur_file_hndl:
        cur_file_hndl.close()


def fileinfo(file):
    if file[2]:
        md5, sha1, sha256, sha512 =  get_hash(file[2])
        try:
            filetype = str(magic.from_file(file[2], mime=False))
        except:
            filetype = "na"

        
        
        banner = """
        
 _____ 
|0101 |  \033[90mFilename :\033[0m {}
|1010 |  \033[90mSHA256.  :\033[0m {}
|     |  \033[90mFiletype :\033[0m {}
|___BIN  \033[90mFilesize :\033[0m {}
    """.format(file[2], sha256, filetype, file_size(file[2]))
        print(banner)
    else:
        print("ERROR! cant read file.")

def help():
    print(f"""\
Hexyara: little enchancement of yara
{sys.argv[0]} [hex_line_count] <yara with params>
    """)
    sys.exit()


if __name__ == "__main__":
    yara_params = sys.argv[1:]
    if not yara_params:
        help()
    try:
        multi = int(yara_params[0], 10)
        yara_params = yara_params[1:]
    except:
        multi = None
    if "-s" not in yara_params:
        yara_params.append("-s")
    prompt = '\033[38;5;15m[READY@CORE]\033[38;5;3m:>\033[0m'
    print("\n{} Loading yara rule and file...".format(prompt))
    fileinfo(yara_params)
    processor(yara_params, multi)
    prompt = '\033[38;5;15m[RETURN@CORE]\033[38;5;3m:>\033[0m'
    print("\n{} Process completed.\n".format(prompt))