# Module to analyze criu dumps of regular vma areas of two containers.
# Arguments:
# 1: Dump File for container 1
# 2: Flags for container 1
# 3: Dump File for container 2
# 4: Flags for container 2
# 5: Chunk Size
# 6: Directory to write the results into

import os
import sys
import json
import hashlib

CHUNK_SIZE = int(sys.argv[5])
RESULTS_DIR = sys.argv[6]
FLAG_CODE = {
    "VMA_AREA_REGULAR": 0,
    "VMA_AREA_STACK": 1,
    "VMA_AREA_VSYSCALL": 2,
    "VMA_AREA_VDSO": 3,
    "VMA_AREA_HEAP": 5,
    "VMA_FILE_PRIVATE": 6,
    "VMA_FILE_SHARED": 7,
    "VMA_ANON_SHARED": 8,
    "VMA_ANON_PRIVATE": 9,
    "VMA_AREA_SYSVIPC": 10,
    "VMA_AREA_SOCKET": 11,
    "VMA_AREA_VVAR": 12,
    "VMA_AREA_AIORING": 13,
    "VMA_CLOSE": 28,
    "VMA_NO_PROT_WRITE": 29,
    "VMA_PREMMAPED": 30,
    "VMA_UNSUPP": 31
}

if len(sys.argv) != 7:
    print(
        'Usage: python3 analyze_file.py <dump1> <owners1> <dump2> <owners2> <chunk-size> <results-dir>'
    )


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
        md5_hash = hashlib.md5(chunk).hexdigest()
        if md5_hash not in table:
            table[md5_hash] = {}
            table[md5_hash]['total'] = 1
        else:
            table[md5_hash]['total'] += 1

        flag = flags[counter]
        bin_flag = bin(flag)[2:]
        num_digits = len(bin_flag)
        for bit in range(num_digits):
            if bin_flag[num_digits - 1 - bit] == '1':
                if bit not in table[md5_hash]:
                    table[md5_hash][bit] = 1
                else:
                    table[md5_hash][bit] += 1

        counter += 1
        percent = counter / len(flags) * 100
        if percent // 10 == completion and percent % 10 < 0.01:
            print('[INFO]: Completion: {}', completion)
            completion += 1
        chunk = dump.read(CHUNK_SIZE)
    return table


def get_analysis(table1, table2):
    """Run the analysis over the hash tables for the two containers

    Args:
        table1, table2

    Returns:
        tuple: of dictionaries holding the counts of various flags in common hashes
    """
    print('[INFO]: Starting the analysis and dump method')
    counts1 = {'total': 0}
    d_counts1 = {'total': 0}
    counts2 = {'total': 0}
    d_counts2 = {'total': 0}

    common_hashes = table1.keys() & table2.keys()
    print('[INFO]: Number of common hashes: ' + str(len(common_hashes)))
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

    distinct_hashes1 = set(table1.keys()) - set(table2.keys())
    print('[INFO]: Number of distinct hashes in container 1: ' +
          str(len(distinct_hashes1)))
    for key in distinct_hashes1:
        dict1 = table1[key]
        for flag in dict1:
            if flag in d_counts1:
                d_counts1[flag] += dict1[flag]
            else:
                d_counts1[flag] = dict1[flag]

    distinct_hashes2 = set(table2.keys()) - set(table1.keys())
    print('[INFO]: Number of distinct hashes in container 2: ' +
          str(len(distinct_hashes2)))
    for key in distinct_hashes2:
        dict2 = table2[key]
        for flag in dict2:
            if flag in d_counts2:
                d_counts2[flag] += dict2[flag]
            else:
                d_counts2[flag] = dict2[flag]

    print(counts1)
    print(counts2)
    return counts1, d_counts1, counts2, d_counts2


def write_to_file(file, counts1, counts2):
    """Write the counts objects for the two containers in the given file

    Args:
        file (string): name of the file to write into
        counts1 (dict)
        counts2 (dict)
    """
    fo = open(file, 'w')
    fo.write('Type, Count1, Count2\n')
    fo.write('Total, ' + str(counts1['total']) + ', ' + str(counts2['total']) +
             '\n')
    for flag, code in FLAG_CODE.items():
        count1 = 0 if code not in counts1 else counts1[code]
        count2 = 0 if code not in counts2 else counts2[code]
        fo.write(flag + ', ' + str(count1) + ', ' + str(count2) + '\n')
    fo.close()


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

assert size1 / CHUNK_SIZE == len(flags1)
assert size2 / CHUNK_SIZE == len(flags2)

print('[INFO]: Assertions fulfilled. Total chunks: {}, {}', len(flags1),
      len(flags2))

try:
    table1 = make_hash_table(dump1, flags1)
    table2 = make_hash_table(dump2, flags2)
    counts1, d_counts1, counts2, d_counts2 = get_analysis(table1, table2)
    write_to_file(RESULTS_DIR + '/common_analysis_' + str(CHUNK_SIZE) + '.txt',
                  counts1, counts2)
    write_to_file(
        RESULTS_DIR + '/distinct_analysis_' + str(CHUNK_SIZE) + '.txt',
        d_counts1, d_counts2)
finally:
    dump1.close()
    dump2.close()
