#! /usr/bin/env python
# -*- coding:utf-8 -*-


import os
import sys
from wordsegment import load, segment
import Levenshtein
from nltk.parse.stanford import StanfordDependencyParser
from nltk.corpus import wordnet as wn

res = []

FLAG = False

HANDLE_ABBR = False

# predicates list
PREDICATES = [
    'get.v.01',
    'acquire.v.01',
    # 'obtain.v.01',
    # 'assign.v.04',
    'allocate.v.01',
    # 'receive.v.01',
]

WORDS_ABBR = {
    "malloc": "memory allocate",
    "kmalloc": "kernel memory allocate",
    "realloc": "reallocate",
    "allocation": "allocation",
}

WORD_ABBR = {
    "mem": "memory",
    "buf": "buffer",
    "alloc": "allocate"
}

# objects list
OBJECTS = [
    'memory.n.04',
    'space.n.02',
    'space.n.03',
    'space.n.07',
    # 'buffer.n.04'
]


def initiate():
    # Stanford Parser jar location env
    os.environ["STANFORD_MODELS"] = \
        "stanford/stanford-parser-3.9.1-models.jar"
    os.environ["STANFORD_PARSER"] = \
        "stanford/stanford-parser.jar"

def dobj_dependence(row):
    """
    dependence type is direct obj, predicate is a verb and object is a noun
    :param row: (('dog', 'NN'), 'case', ('over', 'IN'))
    :return: True or False
    """
    if row[1] == "dobj" and "V" in row[0][1] and "NN" in row[2][1]:
        print(row)
        return True
    else:
        return False


# def dep_dependence(row):
#     """
#     dependence of pair, predicate is a verb and object is a noun
#     :param row: (('dog', 'NN'), 'case', ('over', 'IN'))
#     :return: True or False
#     """
#     if row[1] == "dep":
#         print(row)
#         return True
#     else:
#         return False


def sim_list_cmp(word, genre):
    """
    compare the similarity between synsets and word
    return the most similar meaning of word
    :param word: the word need be compared
    :param genre: verb or noun
    :return: dict of comparing result: {'meaning1': sim1, ...}
    """

    pre = {}
    obj = {}
    # choose verb meanings of the verb
    words = get_list(word, genre)

    if not words:
        return
        # # word is an abbreviation of sensitive word
        # if word in ABBREVIATIONS.keys():
        #     words = [wn.synset(ABBREVIATIONS[word])]
        #     if not words:
        #         return
        # else:
        #     return

    # calculate one synset in list
    if genre == "verb":
        synsets = PREDICATES
        for synset in synsets:
            # get the most similar meaning of verbs of verb
            pre[synset] = get_similarity(synset, words)
        pre = sorted(pre.items(), key=lambda kv: kv[1], reverse=True)
        return pre[0]

    elif genre == "noun":
        synsets = OBJECTS
        for synset in synsets:
            # get the most similar meaning of nouns of noun
            obj[synset] = get_similarity(synset, words)
        obj = sorted(obj.items(), key=lambda kv: kv[1], reverse=True)
        return obj[0]
    else:
        return


def get_list(w, genre):
    # get the list of the type of word
    return [_ for _ in wn.synsets(w) if genre in _.lexname()]


def get_similarity(synset, words):
    """
    get the most similar word
    :param synset: synset in synset we specific in PREDICATES and OBJECT list
    :param words: lists of the word synset
    :return: the most similar word to synset in words
    """
    _ = {}
    for __ in words:
        # _[__.name()] = wn.synset(synset).path_similarity(__)
        _[__.name()] = wn.synset(synset).wup_similarity(__)
    return sorted(_.items(), key=lambda kv: kv[1], reverse=True)[0]


def alloc_check(sentence):
    # check if sensitive when sentence contains `alloc`
    """
    :param sentence: line need to check
    :return: true if sensitive
    """
    # words = sentence.split()

    if sentence.endswith('memory allocate'):
        print("REV: " + sentence)
        return True
    # sent = "allocate xxx xxx xxx"
    elif sentence.startswith('allocate'):
        print("REV: " + sentence)
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False
    # sent = "xxx xxx allocate/allocation"
    elif sentence.endswith('allocate') or sentence.endswith('allocation'):
        sentence = 'allocate ' + ''.join(list(sentence.replace(sentence.split()[-1], '')))
        print("REV: " + sentence)
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False
    # sent = "xxx xxx xxx allocate xxx xxx"
    else:
        sentence = sentence[sentence.index("alloc"):]
        print("REV: " + sentence + "--")
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False


def acquire_check(sentence):
    # check if sensitive when sentence contains `alloc`
    """
    :param sentence: line need to check
    :return: true if sensitive
    """
    # words = sentence.split()

    if sentence.endswith('memory acquire'):
        print("REV: " + sentence)
        return True
    # sent = "allocate xxx xxx xxx"
    elif sentence.startswith('acquire'):
        print("REV: " + sentence)
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False
    # sent = "xxx xxx allocate/allocation"
    elif sentence.endswith('acquire'):
        sentence = 'acquire ' + ''.join(list(sentence.replace(sentence.split()[-1], '')))
        print("REV: " + sentence)
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False
    # sent = "xxx xxx xxx allocate xxx xxx"
    else:
        sentence = sentence[sentence.index("acquire"):]
        print("REV: " + sentence + "--")
        for obj in OBJECTS:
            # sent = "allocate xxx xxx memory"
            obj = obj.split('.')[0]
            if Levenshtein.ratio(sentence.split()[-1], obj) > 0.7:
                print(obj, sentence.split()[-1])
                return True
            else:
                continue
        return False


def     check_pred_ojb(row):
    # predicate and object of a pair dependency
    pred = row[0][0]
    objc = row[2][0]

    # Predicate: zero => Object: histogram
    print("Predicate: " + pred + " => " + "Object: " + objc)

    # compare similarity of the pre_verb and p in p_list
    # ('get.v.01', (u'zero.v.01', 0.33333))
    pre_sim = sim_list_cmp(pred, genre='verb')

    # compare similarity of the obj_noun and o in o_list
    # ('space.n.02', (u'histogram.n.01', 0.3076923076923077))
    obj_sim = sim_list_cmp(objc, genre='noun')

    if pre_sim and obj_sim:
        # use the most similar value
        if pre_sim[1][1] > 0.5 and obj_sim[1][1] > 0.7:
            print(pre_sim[1][0] + " => " + pre_sim[0] + " : " + str(pre_sim[1][1]))
            print(obj_sim[1][0] + " => " + obj_sim[0] + " : " + str(obj_sim[1][1]))
            return True
        else:
            return False
    else:
        return False


if __name__ == '__main__':

    initiate()

    dep_parser = StanfordDependencyParser()

    load()

    if len(sys.argv) < 2:
        print("Please input at least one file!")

    sent_files = sys.argv[1:]

    for sent_file in sent_files:
        r = open(sent_file, "r")

        s = open(sent_file + "_sensitive.list", "w", buffering=0)
        if not os.path.isfile(sent_file):
            print(sent_file + " isn't exist!")
            continue
        s.write("\n" + sent_file + "\n")

        # read lines
        for raw_line in r.readlines():
            sentence = ""
            segmentation = []
            line = ' '.join(segment(raw_line))

            if len(line.split()) < 2:
                continue
            line = line.replace(".", "").strip()
            print("\nRAW: " + line)

            # replace the abbreviation in dicts of sentences
            for word in line.split(' '):
                replace_flag = 0
                for words_abbr in WORDS_ABBR.keys():
                    if word == words_abbr or (words_abbr in word and WORDS_ABBR[words_abbr] not in line):
                        line = line.replace(words_abbr, " " + WORDS_ABBR[words_abbr] + " ").strip()
                        replace_flag = 1
                for word_abbr in WORD_ABBR.keys():
                    if not replace_flag:
                        if word == word_abbr or (word_abbr in word and WORD_ABBR[word_abbr] not in line):
                            line = line.replace(word_abbr, " " + WORD_ABBR[word_abbr] + " ").strip()
                            replace_flag = 1
            print("PRE: " + line)

            # check containing alloc sensitive or not
            if "alloc" in line and alloc_check(line):
                print(">>>>>sensitive<<<<<")
                FLAG = True
            else:
                # parser line
                res = list(dep_parser.parse(line.split()))

                # check dependence, predicate and object semantics
                # all dependencies of words in same line
                for sent_row in res[0].triples():
                    # sent_row= ((('dog', 'NN'), 'case', ('over', 'IN')))
                    # direct object dependence
                    if dobj_dependence(sent_row):
                        FLAG = check_pred_ojb(sent_row)
                    # unrecognized object dependence
                    # elif dep_dependence(sent_row):
                    #     sent_row = reverse_pair(sent_row)
                    #     FLAG = check_pred_ojb(sent_row)
            if FLAG:
                # print this line and write into file
                # print(line.strip() + "is sensitive！")
                s.write(raw_line)
            FLAG = False
        s.close()
        r.close()
