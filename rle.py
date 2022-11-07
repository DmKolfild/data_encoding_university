
from support_function import hex_format_string, str_to_bytes


# Инструкция

# Шифрование. На выходе строка байт
# coding_str = coding_rle("aassqq1111111111111111qq2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222abcd")
#
# Декодирование
# decoding_str = decoding_rle(coding_str)


def coding_rle(string):
    dict = {}
    dict2 = {}
    position = 0
    if str(position) not in dict:
        dict[str(position)] = 1
        dict2[str(position)] = string[0]
    for i in range(1, len(string)):
        if string[i] != string[i-1]:
            position += 1
        if (str(position) in dict) and (dict[str(position)] < 129):
            dict[str(position)] += 1
        else:
            position += 1
            dict[str(position)] = 1
            dict2[str(position)] = string[i]

    list_value = []
    list_key = []
    flag = 1
    for i in dict:
        if dict[i] >= 3:
            list_value.append(dict[i])
            list_key.append(dict2[i])
            flag = 0
        else:
            if len(list_value) == 0:
                list_value.append(dict[i])
                # добавление кодируемой строки dict2[i]
                # Умножение на dict[i], чтобы запсать 2-ые символы
                list_key.append(dict2[i] * dict[i])
            elif (flag == 0) or (list_value[-1] + dict[i] > 128):
                list_value.append(dict[i])
                # добавление кодируемой строки dict2[i]
                # Умножение на dict[i], чтобы запсать 2-ые символы
                list_key.append(dict2[i] * dict[i])
            else:
                list_value[-1] += dict[i]
                list_key[-1] += dict2[i] * dict[i]
            flag = 1

    for i in range(len(list_value)):
        if (len(list_key[i]) == 1) and (list_value[i] >= 3):
            list_value[i] += 128 - 2
        else:
            list_value[i] -= 1

    list_value = list(map(hex_format_string, list_value))
    list_key = list(map(str_to_bytes, list_key))

    concat_func = lambda x, y: x + y
    s = list(map(concat_func, list_value, list_key))  # list the map function
    s = "".join(s)

    return bytearray.fromhex(s)


def decoding_rle(string):
    string = " ".join(['{:02x}'.format(byte) for byte in string])
    list_bytes = string.split(" ")
    decoding_string = b""
    i = 0
    count = 0

    while i < len(list_bytes):
        count = int(list_bytes[i], 16)
        if count <= 128:
            count += 1  # коррекция длины, восстановление значения
            i += 1  # место, занимаемое count
            for j in range(i, i+count):
                decoding_string += bytearray.fromhex(list_bytes[j])
            i += count
        elif count >= 129:
            count -= 128  # избавление от флаг бита
            count += 2  # коррекция длины
            i += 1  # место, занимаемое count
            decoding_string += bytearray.fromhex(list_bytes[i]) * count
            i += 1

    return decoding_string
