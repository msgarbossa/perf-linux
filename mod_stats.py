#!/usr/bin/env python

from math import sqrt

def calc_avg_sd(lst,decimal):

    """Calculates the standard deviation for a list of numbers."""
    num_items = len(lst)
    #if num_items == 0:
    #    return (0, 0, 0, 0)
    mean = sum(lst) / num_items
    xmin = min(lst)
    xmax = max(lst)
    differences = [x - mean for x in lst]
    sq_differences = [d ** 2 for d in differences]
    ssd = sum(sq_differences)
    variance = ssd / num_items
    sd = sqrt(variance)

    # print('debug types: mean={0}, sd={1}, xmin={2}, xmax={3}, dec={4}'.format(type(mean), type(sd), type(xmin), type(xmax), decimal))
    # print('debug vals: mean={0}, sd={1}, xmin={2}, xmax={3}, dec={4}'.format(mean, sd, xmin, xmax, decimal))
    mean = round(float(mean), decimal)
    sd = round(float(sd), decimal)
    xmin = round(float(xmin), decimal)
    xmax = round(float(xmax), decimal)
    return (mean, sd, xmin, xmax)

def divide(numerator, denominator, decimal):
    if denominator == 0:
        print('Cannot divide by zero')
        return 0
    return round((numerator / denominator), decimal)

class DictDiffer(object):
    """
    Calculate the difference between two dictionaries as:
    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values

    Example:
    dict_diff = DictDiffer(dict_current, dict_past)
    print("Added:", dict_diff.added())
    print("Removed:", dict_diff.removed())
    print("Changed:", dict_diff.changed())
    print("Unchanged:", dict_diff.unchanged())
    """

    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.current_keys, self.past_keys = [
            set(d.keys()) for d in (current_dict, past_dict)
        ]
        self.intersect = self.current_keys.intersection(self.past_keys)

    def added(self):
        return self.current_keys - self.intersect

    def removed(self):
        return self.past_keys - self.intersect

    def changed(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] != self.current_dict[o])

    def unchanged(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] == self.current_dict[o])

# Color definitions
def fmtRed(text): return "\033[91m {}\033[00m".format(text)
def fmtGreen(text): return "\033[92m {}\033[00m".format(text)
def fmtYellow(text): return "\033[93m {}\033[00m".format(text)
def fmtLightPurple(text): return "\033[94m {}\033[00m".format(text)
def fmtPurple(text): return "\033[95m {}\033[00m".format(text)
def fmtCyan(text): return "\033[96m {}\033[00m".format(text)
def fmtLightGray(text): return "\033[97m {}\033[00m".format(text)
def fmtBlack(text): return "\033[98m {}\033[00m".format(text)