# Module to analyze criu dumps of regular vma areas of two containers.
# Arguments:
# 1: Directory with dump files for base container
# 2: Directory with dump files for dedup container
# 3: Chunk Size

import os
import sys
import json
import random
import xdelta3
import hashlib

CHUNK_SIZE = int(sys.argv[3])
PAGE_SIZE = 4096
# RESULTS_DIR = sys.argv[4]
# EXP_TYPE = sys.argv[5]

locations = []
hash_table = {}

if len(sys.argv) != 6:
    print(
        'Usage: python3 patching.py <base-dump-dir> <dedup-dump-dir> <chunk-size> <results-dir> <exp-type>'
    )


def choose_locations(num):
    global locations
    partition = PAGE_SIZE // num
    for n in range(num):
        loc = random.randint(n * partition, (n + 1) * partition - CHUNK_SIZE)
        locations.append(loc)


def make_hash_table(dump_dir):
    """Make a hash table for the dump in the format: [md5_hash] => count
    The dictionary mapped for each key, comes with an additional 'total' key. 

    Args:
        dump_dir (directory to get the dumps from)
    """
    global locations, hash_table

    (_, _, filenames) = next(os.walk(dump_dir))
    pages = [p for p in filenames if 'pages-' in p]

    raw_pages = []
    index = 0

    for page_file in pages:
        dump = open(os.path.join(dump_dir, page_file), 'rb')
        page = dump.read(PAGE_SIZE)
        while page != b"":
            raw_pages.append(page)
            for loc in locations:
                chunk = page[loc:loc + CHUNK_SIZE]
                md5_hash = hashlib.md5(chunk).hexdigest()
                if md5_hash not in hash_table:
                    hash_table[md5_hash].append(index)
                else:
                    hash_table[md5_hash] = [index]
                index += 1

            page = dump.read(PAGE_SIZE)
        print('[INFO]: Read file ' + page_file)

    return raw_pages


def compute_patches(dump_dir, raw_pages):
    global locations, hash_table

    (_, _, filenames) = next(os.walk(dump_dir))
    pages = [p for p in filenames if 'pages-' in p]

    raw_length = 0
    patched_length = 0
    patch_length = 0

    for page_file in pages:
        dump = open(os.path.join(dump_dir, page_file), 'rb')
        page = dump.read(PAGE_SIZE)
        while page != b"":
            raw_length += PAGE_SIZE
            possible_locations = []
            for loc in locations:
                chunk = page[loc:loc + CHUNK_SIZE]
                md5_hash = hashlib.md5(chunk).hexdigest()
                if md5_hash in hash_table:
                    possible_locations.extend(hash_table[md5_hash])

            check_set = set(possible_locations)
            best_patch = ''
            for index in check_set:
                delta = xdelta3.encode(raw_pages[index], page)
                if len(delta) < len(best_patch) or len(best_patch) == 0:
                    best_patch = delta

            patch_length += len(best_patch)
            if len(best_patch) == 0:
                patched_length += PAGE_SIZE
            else:
                patched_length += len(best_patch)
            page = dump.read(PAGE_SIZE)
        print('[INFO]: Read file ' + page_file)

    return raw_length, patched_length, patch_length


choose_locations(3)
raw_pages = make_hash_table(sys.argv[1])
raw_length, patched_length, patch_length = compute_patches(
    sys.argv[2], raw_pages)
print('Raw Length: {}, Dedup Length: {}, Patch Length: {}'.format(
    raw_length, patched_length, patch_length))
