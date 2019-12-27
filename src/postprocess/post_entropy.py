import re
import math
from collections import Counter

def shannon_entropy(s):
    # https://rosettacode.org/wiki/Entropy#Python
    s = str(s)
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


def run(results, raw_paste_data, paste_object):
    # Calculate the Shannon Entropy for the raw paste
    paste_object["Shannon Entropy"] = shannon_entropy(raw_paste_data)
    # Send the updated json back
    return paste_object
