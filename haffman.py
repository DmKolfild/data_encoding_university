
from collections import Counter


# Инструкция

# # Создание дерева
# tree = get_tree_haffman("123456789")
#
# # Получение словаря частот
# codes = get_code_haffman(tree, codes=dict())
#
# # Шифрофвание. На выходе зашифрованная строка из нулей и единиц
# coding_str = coding_haffman("123456789", codes)
#
# # Декодирование
# decoding_str = decoding_haffman(coding_str, codes)


# Класс узлов
class Node:
    def __init__(self, value, left=None, right=None):
        self.right = right
        self.left = left
        self.value = value


# подсчет частот и возвращение словаря частот
def get_code_haffman(root, codes=dict(), code=''):
    if root is None:
        return
    if isinstance(root.value, str):
        codes[root.value] = code
        return codes

    get_code_haffman(root.left, codes, code + '0')
    get_code_haffman(root.right, codes, code + '1')

    return codes


# построение дерева
def get_tree_haffman(string):
    string_count = Counter(string)

    if len(string_count) <= 1:
        node = Node(None)
        if len(string_count) == 1:
            node.left = Node([key for key in string_count][0])
            node.right = Node(None)

        string_count = {node: 1}

    while len(string_count) != 1:
        node = Node(None)
        spam = string_count.most_common()[:-3:-1]

        if isinstance(spam[0][0], str):
            node.left = Node(spam[0][0])
        else:
            node.left = spam[0][0]

        if isinstance(spam[1][0], str):
            node.right = Node(spam[1][0])
        else:
            node.right = spam[1][0]

        del string_count[spam[0][0]]
        del string_count[spam[1][0]]
        string_count[node] = spam[0][1] + spam[1][1]

    return [key for key in string_count][0]


# кодирование строки при помощи алгоритма Хафмана
def coding_haffman(string, codes):
    res = ''
    for symbol in string:
        res += codes[symbol]
    return res


# декодирование
# На входе декодируемая строка + ключи шифрования
def decoding_haffman(string, codes):
    res = ''
    i = 0
    count = 0
    while i < len(string):
        for code in codes:
            if string[i:].find(codes[code]) == 0:
                res += code
                i += len(codes[code])
        count += 1
    return res
