# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from sys import argv
from re import compile as reg_comp, VERBOSE
from signature import Signature

REGEX = reg_comp(r""" ^
    #s_id
    (\d{,99999}:\s)?
    #PROTO
    ([A-Z]{,4}\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #DIR
    (<>\s|->\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #PAYLOAD
    (\*)
        $ """, VERBOSE)

REGEX_SQL = r"(\s*([\0\b\'\"\n\r\t\%\_\\]*\s*(((select\s*.+\s*from\s*.+)|(insert\s*.+\s*into\s*.+)|(update\s*.+\s*set\s*.+)|(delete\s*.+\s*from\s*.+)|(drop\s*.+)|(truncate\s*.+)|(alter\s*.+)|(exec\s*.+)|(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+)|(let\s+.+[\=]\s*.*)|(begin\s*.*\s*end)|(\s*[\/\*]+\s*.*\s*[\*\/]+)|(\s*(\-\-)\s*.*\s+)|(\s*(contains|containsall|containskey)\s+.*)))(\s*[\;]\s*)*)+)"
try:
    RULEPATH = argv[1]
except IndexError:
    RULEPATH = 'default.rules'
finally:
    print(f"[*] loading {RULEPATH}")


def verify_rules(ruleset):
    signatures = []
    for rule in ruleset:
        if rule[0] != '#':
            if REGEX.match(rule):
                sig = Signature(rule)
                if sig.s_id == '':
                    sig.s_id = str(len(signatures)+1)
                if sig.s_id in [s.s_id for s in signatures]:
                    raise ValueError(' ID in use for %s' % (rule))
                signatures.append(sig)
            else:
                raise ValueError(f"{rule} does not match the syntax")
    print(*signatures, sep='\n')
    try:
        signatures[0]
    except IndexError:
        raise ValueError('empty signature set')
    else:
        return signatures


def load_rules(path):
    try:
        with open(path) as new_file:
            rules = new_file.readlines()
    except FileNotFoundError as err:
        raise ValueError(err)
    else:
        try:
            vrules = verify_rules([x.strip() for x in rules if len(x) > 1])
        except ValueError as err:
            raise err
        else:
            return vrules

try:
    RULES = load_rules(RULEPATH)
    print('[*] parsed rules')
except ValueError as err:
    exit(f"[@] {err}")
