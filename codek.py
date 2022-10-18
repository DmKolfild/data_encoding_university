
import datetime
import time
from get_signature import get
from extennsion_ofset_signature import data
from snoopy import snoopy, snoopy1
from haffman import get_tree_haffman, get_code_haffman, coding_haffman, decoding_haffman
import os


# перевод числа в шестнадцатеричную систему
def hex_format(string):
    s = hex(string).replace("0x", "")
    if len(s) % 2 == 1:
        s = "0" + s
    return bytearray.fromhex(s)


# перевод числа в десятичное число
def int_format(string):
    hex_bytes = "".join(['{:02X}'.format(byte) for byte in string])
    return int(hex_bytes, 16)


def bin_to_hex(string, encryption_dict):
    print(encryption_dict)
    string = coding_haffman(string, encryption_dict)
    string = "1" + string  # дописаваем первую единицу, чтобы при декодировании не отвалился первый ноль (нули)
    # ПРИ ДЕКОДИРОВАНИИ НЕ ЗАБЫТЬ ПРО ЭТУ ЕДИНИЦУ!!!
    string = (str(hex(int(string, 2)))[2:]).encode()
    return string, len(string)


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
    string = bytearray.fromhex(s)

    return string


# name_files = "test.txt ..\\test\\test_subset\\56.txt 123.webp J.jpg"
name_files = "J.jpg test.txt ..\\test\\test_subset\\56.txt 123.webp"
name_coder_file = "my_sig.snoopy"
encryption_dict = ''  # с2
# cловарь частот символов


def prepared_file_for_report():
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


def write_into_file(data_snoopy2):
    # копирование данных, уже записанных в файл
    with open(name_coder_file, 'rb') as original:
        data_snoopy1 = original.read()

    # запись старых и новых данных в один файл
    with open(name_coder_file, 'wb') as modified:
        modified.write(data_snoopy1 + data_snoopy2)


def get_encrypt_dict(list_file):
    all_data_from_file = b""
    for name_file in list_file.split():
        with open(name_file, "rb") as file:
            all_data_from_file += file.read()
    str_alphabet = bytes_to_256(all_data_from_file)

    tree = get_tree_haffman(str_alphabet)  # создаем дерево шифрования
    encrypt_dict = get_code_haffman(tree, codes=dict())  # Получаем словарь для шифрования

    return encrypt_dict


def coder_without_encryptiion(name_file):

    file_for_codec = read_signature_from_file(name_file)

    sig = snoopy1[1]["signature"]

    ver = (hex_format(snoopy1[1]["version"])).rjust(snoopy1[1]["offset_code_alg"] - snoopy1[1]["offset_version"], b"\x00")

    alg = (hex_format(1)).rjust(snoopy1[1]["offset_size_of_file"] - snoopy1[1]["offset_code_alg"], b"\x00")

    size = os.path.getsize(name_file)  # получение размера файла
    size = (hex_format(size)).rjust(snoopy1[1]["offset_id"] - snoopy1[1]["offset_size_of_file"],b"\x00")

    id = (hex_format(file_for_codec["id"])).rjust(snoopy1[1]["offset_link"] - snoopy1[1]["offset_id"], b"\x00")

    # получение абсолютного пути файла
    link = str(os.path.abspath(name_file)).encode()
    link = link.rjust(snoopy1[1]["offset_data"] - snoopy1[1]["offset_link"], b"\x00")

    # запись данных из изходного файла с соответсвующей позиции
    with open(name_file, "rb") as f2:
        data_read = f2.read()
    data_snoopy2 = sig + ver + alg + size + id + link + data_read


    # добавление исходных данных в файл
    return data_snoopy2


def coder_with_encryptiion(name_file, encrypt_dict):

    file_for_codec = read_signature_from_file(name_file)

    sig = snoopy1[2]["signature"]

    ver = (hex_format(snoopy1[2]["version"])).rjust(snoopy1[2]["offset_code_alg"] - snoopy1[2]["offset_version"], b"\x00")

    alg = (hex_format(2)).rjust(snoopy1[2]["offset_size_of_file"] - snoopy1[2]["offset_code_alg"], b"\x00")

    id = (hex_format(file_for_codec["id"])).rjust(snoopy1[2]["offset_link"] - snoopy1[2]["offset_id"], b"\x00")

    # получение абсолютного пути файла
    link = str(os.path.abspath(name_file)).encode()
    link = link.rjust(snoopy1[2]["offset_dict_haf"] - snoopy1[2]["offset_link"], b"\x00")

    dict_haf = b''
    for index in encrypt_dict:
        key = hex_format(ord(index))  # запись ключа
        len_code_for_key = (hex_format(len(encrypt_dict[index])))  # запись длины кода для учета единиц
        # записываем кодировку. Если кодировка размером в 1 байт или 2, дописываем в начале нулевой байт
        code_of_key = (hex_format(int(encrypt_dict[index], 2))).rjust(3, b'\x00')
        dict_haf += key + len_code_for_key + code_of_key
    dict_haf = dict_haf.ljust(snoopy1[2]["offset_data"] - snoopy1[2]["offset_dict_haf"], b'\x00')

    # запись данных из изходного файла с соответсвующей позиции
    with open(name_file, "rb") as f2:
        data_read = f2.read()
    data_read = bytes_to_256(data_read)
    data_read, size = bin_to_hex(data_read, encrypt_dict)

    size = (hex_format(size)).rjust(snoopy1[2]["offset_id"] - snoopy1[2]["offset_size_of_file"], b"\x00")

    data_snoopy2 = sig + ver + alg + size + id + link + dict_haf + data_read

    # добавление исходных данных в файл
    return data_snoopy2


def coder_analise(code_alg, list_code_alg):
    prepared_file_for_report()

    if code_alg == 1:
        # перебор указанных файлов
        for name_file in name_files.split():
            data_snoopy2 = coder_without_encryptiion(name_file)
            write_into_file(data_snoopy2)
    elif code_alg == 2:  # шифровании файлов в массее
        encrypt_dict = get_encrypt_dict(name_files)  # Получаем словарь для шифрования

        for name_file in name_files.split():
            data_snoopy2 = coder_with_encryptiion(name_file, encrypt_dict)
            write_into_file(data_snoopy2)

    elif code_alg == 3:  # для каждого файла свой код шифрования
        index = 0  # индекс для перебора значений шифрования для файлов
        # перебор указанных файлов
        for name_file in name_files.split():
            if list_code_alg[index] == 1:
                data_snoopy2 = coder_without_encryptiion(name_file)
                write_into_file(data_snoopy2)
            elif list_code_alg[index] == 2:
                encrypt_dict = get_encrypt_dict(name_file)  # Получаем словарь для шифрования
                data_snoopy2 = coder_with_encryptiion(name_file, encrypt_dict)
                write_into_file(data_snoopy2)

            index += 1

    elif code_alg == 4:
        for name_file in name_files.split():
            encrypt_dict = get_encrypt_dict(name_file)  # Получаем словарь для шифрования
            data_snoopy2 = coder_with_encryptiion(name_file, encrypt_dict)  # хаффман (получение шифрованных данных)

            size_with_haffman = len(data_snoopy2)
            size_wtihout_encryptiion = snoopy1[1]["offset_data"] + os.path.getsize(name_file)
            if size_with_haffman > size_wtihout_encryptiion:
                print(1)
                data_snoopy2 = coder_without_encryptiion(name_file)
            print(name_file)
            write_into_file(data_snoopy2)


def decoder_without_encryptiion(file):
    size = file.read(snoopy1[1]["offset_id"] - snoopy1[1]["offset_size_of_file"])
    size = int_format(size)

    id = file.read(snoopy1[1]["offset_link"] - snoopy1[1]["offset_id"])
    id = int_format(id)

    link = file.read(snoopy1[1]["offset_data"] - snoopy1[1]["offset_link"])
    link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

    link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
    if not os.path.exists(link_abs):
        os.makedirs(link_abs)

    data_snoopy = file.read(size)

    with open(link, "wb") as f5:
        f5.write(data_snoopy)


def decoder_with_encryptiion(file):
    size = file.read(snoopy1[2]["offset_id"] - snoopy1[2]["offset_size_of_file"])
    size = int_format(size)

    id = file.read(snoopy1[2]["offset_link"] - snoopy1[2]["offset_id"])
    id = int_format(id)

    link = file.read(snoopy1[2]["offset_dict_haf"] - snoopy1[2]["offset_link"])
    link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

    link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
    if not os.path.exists(link_abs):
        os.makedirs(link_abs)

    dict_frequency = (file.read(snoopy1[2]["offset_data"] - snoopy1[2]["offset_dict_haf"]))

    encrypt_dict = {}
    for i in range(0, len(dict_frequency), 5):
        s = dict_frequency[i:i + 5]
        if s == b'\x00\x00\x00\x00\x00':
            break
        char = chr(int_format(s[0:1]))
        len_code = int_format(s[1:2])
        str_bytes = str(bin(int_format(s[3:]))[2:])
        encrypt_dict[char] = str_bytes.rjust(len_code, "0")  # восстановление изначальных кодов

    data_snoopy = file.read(size).decode()
    string = str(bin(int(data_snoopy, 16))[2:])
    string = string[1:]  # избавляемся от первой единицы, которая была добавлена при кодирования, чтобы не потерялись нули
    data_snoopy = decoding_haffman(string, encrypt_dict)
    data_snoopy = str_to_bytes(data_snoopy)

    with open(link, "wb") as f5:
        f5.write(data_snoopy)


def decoder_analise():
    size_coder_file = os.path.getsize(name_coder_file)  # размер закодированного файла

    with open(name_coder_file, "rb") as file:
        while file.tell() != size_coder_file:
            bytes_signature = file.read(len(snoopy1[1]["signature"]))
            info = get(bytes_signature)
            if info != "snoopy":
                print("Декодирование невозможно, сигнатура файла не соответсвует описанной")
                break

            ver = file.read(snoopy1[1]["offset_code_alg"] - snoopy1[1]["offset_version"])
            ver = int_format(ver)

            alg = file.read(snoopy1[1]["offset_size_of_file"] - snoopy1[1]["offset_code_alg"])
            alg = int_format(alg)

            if alg == 1:
                decoder_without_encryptiion(file)
            elif alg == 2:
                decoder_with_encryptiion(file)


def decoder_print():
    time.sleep(1)
    print(datetime.datetime.now(), "Запуск декодера")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".", end="\n")
    time.sleep(0.5)
    print(datetime.datetime.now(), "Декодер запущен")
    decoder_analise()
    print(datetime.datetime.now(), "Декодер завершен")
    time.sleep(1)


def coder_print(code_alg, list_code_alg=None):
    time.sleep(1)
    print(datetime.datetime.now(), "Запуск кодера")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".", end="\n")
    time.sleep(0.5)
    print(datetime.datetime.now(), "Кодер запущен")
    coder_analise(code_alg, list_code_alg)
    print(datetime.datetime.now(), "Кодер завершен")
    time.sleep(1)


def main():
    print("Кодер или Декодер?")
    print("1 - Кодер")
    print("2 - Декодер")
    q = int(input())
    if q == 1:
        print("Выберите способ кодирования указанных файлов:")
        print(" 1 - Кодирование файлов как единый исходный текст")
        print(" 2 - Кодирование каждого файла собственным кодом алгоритма (указанным вручную)")
        print(" 3 - Доверить выбор программе ('интеллектуальный' кодер)")
        a = int(input())
        if a == 1:
            print("Выберите способ шифрования:")
            print("1 - без шифрования")
            print("2 - с шифрование")
            count = int(input())
            if count == 1:
                coder_print(1)
            elif count == 2:
                coder_print(2)

        elif a == 2:
            print("Выберите способ шифрования для каждого файла:")
            print("1 - без шифрования")
            print("2 - с шифрованием")
            list_code_alg = []
            for i in name_files.split():
                print("Для файла", os.path.abspath(i), ": ", end="")
                count = int(input())
                while count not in [1, 2]:
                    print("Введите 1 или 2: ", end="")
                    count = int(input())
                list_code_alg.append(count)
            print(list_code_alg)
            coder_print(3, list_code_alg)
        elif a == 3:
            coder_print(4)
    elif q == 2:
        decoder_print()


if __name__ == "__main__":
    main()
