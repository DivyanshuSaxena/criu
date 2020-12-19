# Module to analyze criu dumps of regular vma areas of two containers.
# Arguments:
# 1: Dump File for container 1
# 2: Flags for container 1
# 3: Dump File for container 2
# 4: Flags for container 2
# 5: Chunk Size

import os
import sys
import json
import hashlib


CHUNK_SIZE = int(sys.argv[5])
FLAG_CODE = {
    "VMA_AREA_NONE":    (0 <<  0),
    "VMA_AREA_REGULAR":	(1 <<  0),
    "VMA_AREA_STACK":	(1 <<  1),
    "VMA_AREA_VSYSCALL":(1 <<  2),
    "VMA_AREA_VDSO":	(1 <<  3),
    "VMA_AREA_HEAP":	(1 <<  5),
    "VMA_FILE_PRIVATE":	(1 <<  6),
    "VMA_FILE_SHARED":	(1 <<  7),
    "VMA_ANON_SHARED":	(1 <<  8),
    "VMA_ANON_PRIVATE":	(1 <<  9),
    "VMA_AREA_SYSVIPC":	(1 <<  10),
    "VMA_AREA_SOCKET":	(1 <<  11),
    "VMA_AREA_VVAR":	(1 <<  12),
    "VMA_AREA_AIORING":	(1 <<  13),
    "VMA_CLOSE":		(1 <<  28),
    "VMA_NO_PROT_WRITE":(1 <<  29),
    "VMA_PREMMAPED":	(1 <<  30),
    "VMA_UNSUPP":		(1 <<  31)
}


def make_hash_table(dump, flags):
    """Make a hash table for the dump in the format: [md5_hash] => {[bit] => count}
    The dictionary mapped for each key, comes with an additional 'total' key. 

    Args:
        dump (dump file object)
        flags (flags list)

    Returns:
        table object
    """
    table = {}
    counter = 0
    completion = 0
    chunk = dump.read(CHUNK_SIZE)
    while chunk != b"":
        md5_hash = hashlib.md5(chunk)
        if md5_hash not in table:
            table[md5_hash] = {}
            table[md5_hash]['total'] = 1
        else:
            table[md5_hash]['total'] += 1
        
        flag = flags[counter]
        bin_flag = bin(flag)[2:]
        num_digits = len(bin_flag)
        for bit in range(num_digits):
            if bin_flag[num_digits-1-bit] == '1':
                if bit not in table[md5_hash]:
                    table[md5_hash][bit] = 1
                else:
                    table[md5_hash][bit] += 1

        counter += 1
        percent = counter/len(flags) * 100
        if percent//10 == completion and percent%10 < 0.01:
            print('[INFO]: Completion: {}', completion)
            completion += 1
        chunk = dump.read(CHUNK_SIZE)
    return table


def get_analysis(table1, table2):
    """Run the analysis over the hash tables for the two containers

    Args:
        table1, table2
    """
    print('[INFO]: Starting the analysis and dump method')
    common_hashes = table1.keys() & table2.keys()
    counts1 = {'total':0}
    counts2 = {'total':0}

    for key in common_hashes:
        dict1 = table1[key]
        dict2 = table2[key]

        for flag in dict1:
            if flag in counts1:
                counts1[flag] += dict1[flag]
            else:
                counts1[flag] = dict1[flag]
        for flag in dict2:
            if flag in counts2:
                counts2[flag] += dict2[flag]
            else:
                counts2[flag] = dict2[flag]

    print(counts1)
    print(counts2)
    json1 = open('common_chunks1.json', 'w')
    json2 = open('common_chunks2.json', 'w')
    json.dump(counts1, json1)
    json.dump(counts2, json2)


dump1 = open(sys.argv[1], "rb")
dump2 = open(sys.argv[3], "rb")
with open(sys.argv[2]) as f:
    content = f.readlines()
flags1 = [int(l) for l in content]

with open(sys.argv[4]) as f:
    content = f.readlines()
flags2 = [int(l) for l in content]

size1 = os.stat(sys.argv[1]).st_size
size2 = os.stat(sys.argv[3]).st_size

assert size1/CHUNK_SIZE == len(flags1)
assert size2/CHUNK_SIZE == len(flags2)

print('[INFO]: Assertions fulfilled. Total chunks: {}, {}', len(flags1), len(flags2))

dict1 = {}
dict2 = {}

try:
    table1 = make_hash_table(dump1, flags1)
    table2 = make_hash_table(dump2, flags2)
    get_analysis(table1, table2)

finally:
    dump1.close()
    dump2.close()
