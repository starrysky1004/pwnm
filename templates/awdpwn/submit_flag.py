#!/usr/bin/env python3
# A script for awd loop submit flag
import threading
from time import sleep
import os
import json
import requests

flag_file = './flags'
threads = []

def submit(flag):
    try:
        # url = 'https://ctf.bugku.com/awd/submit.html?token=88b02ce3b420ec1f4b4a2e02dd6fe305&flag=' + flag[:-1]
        url = f"curl -X POST http://27.25.152.77:19999/api/flag -H 'Authorization: 7f120ca9b0e3024d06734a04a986cc55' -d '{{ \"flag\": \"{flag[:-1]}\"}}'"
        print(url)
        # r = requests.get(url)
        os.system(url)
        print('\x1b[01;38;5;214m[+] pwned!\x1b[0m')
    except Exception as e:
        print('\x1b[01;38;5;214m[-] connect fail: {}\x1b[0m'.format(str(e)))

def main():
    with open(flag_file) as flag_txt:
        flags = flag_txt.readlines()
        for flag in flags:
            thread = threading.Thread(target=submit, args=(flag,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()
