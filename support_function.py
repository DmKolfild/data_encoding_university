
import os
from get_signature import get
from extennsion_ofset_signature import data
from haffman import get_tree_haffman, get_code_haffman, coding_haffman


# перевод числа в шестнадцатеричную систему
def hex_format_bytes(string):
    s = hex(string).replace("0x", "")
    if len(s) % 2 == 1:
        s = "0" + s
    return bytearray.fromhex(s)


# перевод числа в шестнадцатеричную систему
def hex_format_string(string):
    s = hex(string).replace("0x", "")
    if len(s) % 2 == 1:
        s = "0" + s
    return s


# перевод числа в десятичное число
def int_format(string):
    hex_bytes = "".join(['{:02X}'.format(byte) for byte in string])
    return int(hex_bytes, 16)


def string_encode_for_the_record(string):
    string = "1" + string  # дописаваем первую единицу, чтобы при декодировании не отвалился первый ноль (нули)
    # ПРИ ДЕКОДИРОВАНИИ НЕ ЗАБЫТЬ ПРО ЭТУ ЕДИНИЦУ!!!
    string = (str(hex(int(string, 2)))[2:]).encode()
    return string, len(string)


# применение кодирования Хаффмана, возвращение байтов для записи в файл
def bin_to_hex_haffman(string, encryption_dict):
    string = coding_haffman(string, encryption_dict)  # получение шифра (Хаффман)
    string, len_string = string_encode_for_the_record(string)  # обработка строки для записи в файл
    return string, len_string


# преобразование байтов в строку 256-символьного алфавита
def bytes_to_256(string):
    str_bytes = " ".join(['{:02X}'.format(byte) for byte in string])  # строка из байт 16-bit
    str_alphabet = ""
    for i in str_bytes.split():
        str_alphabet += chr(int(i, 16))  # преобразуем в 256-символьный алфавит

    return str_alphabet


# преобразуем строку ascii в байты
def str_to_bytes(string):
    s = ""
    for i in list(string):
        s += (str(hex(ord(i)))[2:]).rjust(2, '0')
    return s

def prepared_file_for_report(name_coder_file, name_files):
    if name_coder_file in name_files:
        print("Имя файла, в которые записывается закодированная информация, не должно быть в списке файлов")
        return 0
    # удаление файла, если он существует, а затем его создание вновь
    try:
        os.remove(str(os.path.abspath(name_coder_file)))
    except:
        print("Файла my_sig.snoopy нет, удаление невозможно")
    # создать файл, если он отсутвует
    with open(name_coder_file, "w") as f1:
        pass


def read_signature_from_file(name_file):
    file_for_codec = {}
    # открываем файл и определяем сигнатуру
    with open(name_file, "r+b") as file:
        info = get(file.read(128))

    # по найденной сигнатуре из json файла берем информацию по данному типу файла
    if info == "txt":
        file_for_codec = {"id": 1, "extension": "txt", "offset": 0, "signature": [b""]}
    else:
        for element in data:
            if element["extension"] == info:
                file_for_codec = element

    return file_for_codec


def write_into_file(data_snoopy2, name_coder_file):
    # копирование данных, уже записанных в файл
    with open(name_coder_file, 'rb') as original:
        data_snoopy1 = original.read()

    # запись старых и новых данных в один файл
    with open(name_coder_file, 'wb') as modified:
        modified.write(data_snoopy1 + data_snoopy2)


def get_bytes_from_files_as_a_single_string(list_file):
    all_data_from_file = b""
    for name_file in list_file.split():
        with open(name_file, "rb") as file:
            all_data_from_file += file.read()
    str_alphabet = bytes_to_256(all_data_from_file)

    return str_alphabet


def get_encrypt_dict_for_haffman(list_file):
    str_alphabet = get_bytes_from_files_as_a_single_string(list_file)  # получение содержимого файла\файлов в виде одной строки

    tree = get_tree_haffman(str_alphabet)  # создаем дерево шифрования
    encrypt_dict = get_code_haffman(tree, codes=dict())  # Получаем словарь для шифрования

    return encrypt_dict