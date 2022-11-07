
from decimal import Decimal, getcontext
from arithmetic import float2bin, bin2float

# def float2bin(x, eps=Decimal(10**(-1000))):
#     print("x = ", x)
#     res = ''
#     while x > eps:
#         x *= 2
#         res += str(int(x))
#         x -= int(x)
#     print("res =", res)
#     return res

#
# def bin2float(x):
#     return sum(2 ** (-i - 1) for i, digit in enumerate(x) if digit == '1')


def find_code(a, b):
    i = 0
    a += '0' * (len(b) - len(a))
    while a[i] == b[i]:
        i += 1
    res = a[:i] + '0'
    cnt = 0
    while a[i] == 1:
        i += 1
        cnt += 1
    res += '1' * (cnt + 1)
    return res


def coding(word, alphabet, p):
    left, right = 0, 1

    for letter in word:
        i = alphabet.index(letter)
        left, right = (Decimal(left) + (Decimal(right) - Decimal(left)) * Decimal(sum(p[:i])),
                       Decimal(left) + (Decimal(right) - Decimal(left)) * Decimal(sum(p[: i + 1])))
    print(left, right)
    print("find    =", find_code(*map(float2bin, (left, right))))
    left2 = float2bin(left)
    right2 = float2bin(right)
    if len(str(right)) > len(str(left)):
        left2 = str(left2).ljust(len(str(right2)), "0")
    else:
        right2 = str(right2).ljust(len(str(left2)), "0")
    print("left  =", left2)
    print("rigth =", right2)
    flags = 0
    result = ""
    for i in range(len(left2)):
        if left2[i] == right2[i]:
            result += left2[i]

    return result+"01"


def decoding(code, length, alphabet, p):
    code = Decimal(bin2float("0."+code))
    print("code=", code)
    word = ''
    left, right = 0, 1

    for _ in range(length):
        for i, letter in enumerate(alphabet):
            interval = (Decimal(left) + (Decimal(right) - Decimal(left)) * Decimal(sum(p[:i])),
                        Decimal(left) + (Decimal(right) - Decimal(left)) * Decimal(sum(p[:i + 1])))
            if interval[0] <= code < interval[1]:
                word += letter
                code = (code - interval[0]) / (interval[1] - interval[0])
                break

    return word


# word = 'cccddc'*100
#
# getcontext().prec = 5000000
#
# alphabet = 'abcd'
# p = (Decimal(3/4), Decimal(1/8), Decimal(1/16), Decimal(1/16))
#
# code = coding(word, alphabet, p)
# print("|||")
# print(code)
#
# print(decoding(code, len(word), alphabet, p))