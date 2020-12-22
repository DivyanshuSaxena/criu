# Module to analyze criu dumps of regular vma areas of two containers.
# Arguments:
# 1: Directory with dump files for container 1
# 2: Directory with dump files for container 2
# 3: Chunk Size
# 4: Directory to write the results into

import os
import sys
import json
import hashlib

CHUNK_SIZE = int(sys.argv[3])
RESULTS_DIR = sys.argv[4]

if len(sys.argv) != 5:
    print(
        'Usage: python3 analyze_dir.py <dump1-dir> <dump2-dir> <chunk-size> <results-dir>'
    )


def make_hash_table(dump_dir):
    """Make a hash table for the dump in the format: [md5_hash] => count
    The dictionary mapped for each key, comes with an additional 'total' key. 

    Args:
        dump_dir (directory to get the dumps from)
    """
    table = {}
    counter = 0
    completion = 0
    (_, _, filenames) = next(os.walk(dump_dir))
    pages = [p for p in filenames if 'pages-' in p]

    for page_file in pages:
        dump = open(os.join(dump_dir, page_file), 'rb')
        chunk = dump.read(CHUNK_SIZE)
        while chunk != b"":
            md5_hash = hashlib.md5(chunk).hexdigest()
            if md5_hash not in table:
                table[md5_hash] = 1
            else:
                table[md5_hash] += 1

            chunk = dump.read(CHUNK_SIZE)
        print('[INFO]: Read file ' + page_file)

    return table


def get_analysis(table1, table2):
    """Run the analysis over the hash tables for the two containers

    Args:
        table1, table2

    Returns:
        tuple: of dictionaries holding the counts of various flags in common hashes
    """
    print('[INFO]: Starting the analysis and dump method')
    counts1 = {
        'common': {
            'hashes': 0,
            'chunks': 0
        },
        'distinct': {
            'hashes': 0,
            'chunks': 0
        }
    }
    counts2 = {
        'common': {
            'hashes': 0,
            'chunks': 0
        },
        'distinct': {
            'hashes': 0,
            'chunks': 0
        }
    }

    common_hashes = table1.keys() & table2.keys()
    distinct_hashes1 = set(table1.keys()) - set(table2.keys())
    distinct_hashes2 = set(table2.keys()) - set(table1.keys())

    print('[INFO]: Number of common hashes: ' + str(len(common_hashes)))
    print('[INFO]: Number of distinct hashes in container 1: ' +
          str(len(distinct_hashes1)))
    print('[INFO]: Number of distinct hashes in container 2: ' +
          str(len(distinct_hashes2)))

    counts1['common']['hashes'] = len(common_hashes)
    counts2['common']['hashes'] = len(common_hashes)
    counts1['distinct']['hashes'] = len(distinct_hashes1)
    counts2['distinct']['hashes'] = len(distinct_hashes2)

    for key in common_hashes:
        counts1['common']['chunks'] += table1[key]
        counts2['common']['chunks'] += table2[key]

    for key in distinct_hashes1:
        counts1['distinct']['chunks'] += table1[key]

    for key in distinct_hashes2:
        counts2['distinct']['chunks'] += table2[key]

    return counts1, counts2


def write_to_file(file, counts1, counts2):
    """Write the counts objects for the two containers in the given file

    Args:
        file (string): name of the file to write into
        counts1 (dict)
        counts2 (dict)
    """
    fo = open(file, 'w')
    fo.write('Type, Count1, Count2\n')

    # Calculation
    th1 = counts1['common']['hashes'] + counts1['distinct']['hashes']
    th2 = counts2['common']['hashes'] + counts2['distinct']['hashes']
    tc1 = counts1['common']['chunks'] + counts1['distinct']['chunks']
    tc2 = counts2['common']['chunks'] + counts2['distinct']['chunks']
    ch_percent1 = counts1['common']['hashes'] / th1
    ch_percent2 = counts2['common']['hashes'] / th2
    cc_percent1 = counts1['common']['chunks'] / tc1
    cc_percent2 = counts2['common']['chunks'] / tc2

    fo.write('Common Hashes Percent, ' + '{:.2f}'.format(ch_percent1) + ', ' +
             '{:.2f}'.format(ch_percent2) + '\n')
    fo.write('Distinct Hashes, ' + str(counts1['distinct']['hashes']) + ', ' +
             str(counts2['distinct']['hashes']) + '\n')
    fo.write('Total Hashes, ' + str(th1) + ', ' + str(th2) + '\n')

    fo.write('Common Chunks Percent, ' + '{:.2f}'.format(cc_percent1) + ', ' +
             '{:.2f}'.format(cc_percent2) + '\n')
    fo.write('Distinct Chunks, ' + str(counts1['distinct']['chunks']) + ', ' +
             str(counts2['distinct']['chunks']) + '\n')
    fo.write('Total Chunks, ' + str(tc1) + ', ' + str(tc2) + '\n')
    fo.close()


table1 = make_hash_table(sys.argv[1])
table2 = make_hash_table(sys.argv[2])
counts1, counts2 = get_analysis(table1, table2)
write_to_file(RESULTS_DIR + '/analysis_' + str(CHUNK_SIZE) + '.txt', counts1,
              counts2)
