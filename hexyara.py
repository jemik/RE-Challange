#!/usr/bin/python3
import socket
import sys
import subprocess
import os
from tabulate import tabulate

def print_hex(file_hndl, pos, length, matched):
    file_hndl.seek(pos)
    for i in range((length//16) + 1):
        b = file_hndl.read(16)
        hex_str = " ".join([f"{i:02x}" for i in b])
        hex_str = hex_str[0:23] + " " + hex_str[23:]
        ascii = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])
        print(f"\033[38;5;15m{(i*16)+pos:08x}:\033[0m  \033[90m{hex_str} \033[93m|\033[90m{ascii}\033[93m|\033[0m")


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
            prompt = '\033[38;5;15m[{}]\033[38;5;3m:>'.format(hex(pos))
            print(tabulate(content,  headers=col_names, tablefmt="grid"))
            print(" \n{} \033[0mHexdump@matched::offset\033[0m\n".format(prompt) )
            print_hex(cur_file_hndl, pos, match_str_len+line_multi if line_multi else match_str_len*4, match_str)
            

    proc.terminate()
    if cur_file_hndl:
        cur_file_hndl.close()


def help():
    print(f"""\
Hexyara: little enchancement of yara
{sys.argv[0]} [hex_line_count] <yara with params>
    """)
    exit()


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
    processor(yara_params, multi)
    prompt = '\033[38;5;15m[RETURN@CORE]\033[38;5;3m:>\033[0m'
    print("\n{} Process completed.\n".format(prompt))