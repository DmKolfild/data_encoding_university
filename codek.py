
import datetime
import time
from snoopy import snoopy
from haffman import decoding_haffman
from rle import coding_rle, decoding_rle
from support_function import *


name_files = "test.txt ..\\test\\test_subset\\56.txt 123.webp J.jpg test2.txt"
# name_files = "test2.txt"
name_coder_file = "my_sig.snoopy"
encryption_dict = ''  # cловарь частот символов


def coder_without_encryptiion(name_file):

    file_for_codec = read_signature_from_file(name_file)

    sig = snoopy[1]["signature"]

    ver = (hex_format_bytes(snoopy[1]["version"])).rjust(snoopy[1]["offset_code_alg"] - snoopy[1]["offset_version"], b"\x00")

    alg = (hex_format_bytes(1)).rjust(snoopy[1]["offset_size_of_file"] - snoopy[1]["offset_code_alg"], b"\x00")

    size = os.path.getsize(name_file)  # получение размера файла
    size = (hex_format_bytes(size)).rjust(snoopy[1]["offset_id"] - snoopy[1]["offset_size_of_file"], b"\x00")

    id = (hex_format_bytes(file_for_codec["id"])).rjust(snoopy[1]["offset_link"] - snoopy[1]["offset_id"], b"\x00")

    # получение абсолютного пути файла
    link = str(os.path.abspath(name_file)).encode()
    link = link.rjust(snoopy[1]["offset_data"] - snoopy[1]["offset_link"], b"\x00")

    # запись данных из изходного файла с соответсвующей позиции
    with open(name_file, "rb") as f2:
        data_read = f2.read()
    data_snoopy2 = sig + ver + alg + size + id + link + data_read

    # добавление исходных данных в файл
    return data_snoopy2


def coder_with_encryptiion_haffman(name_file, encrypt_dict):

    file_for_codec = read_signature_from_file(name_file)

    sig = snoopy[2]["signature"]

    ver = (hex_format_bytes(snoopy[2]["version"])).rjust(snoopy[2]["offset_code_alg"] - snoopy[2]["offset_version"], b"\x00")

    alg = (hex_format_bytes(2)).rjust(snoopy[2]["offset_size_of_file"] - snoopy[2]["offset_code_alg"], b"\x00")

    id = (hex_format_bytes(file_for_codec["id"])).rjust(snoopy[2]["offset_link"] - snoopy[2]["offset_id"], b"\x00")

    # получение абсолютного пути файла
    link = str(os.path.abspath(name_file)).encode()
    link = link.rjust(snoopy[2]["offset_dict_haf"] - snoopy[2]["offset_link"], b"\x00")

    dict_haf = b''
    for index in encrypt_dict:
        key = hex_format_bytes(ord(index))  # запись ключа
        len_code_for_key = (hex_format_bytes(len(encrypt_dict[index])))  # запись длины кода для учета единиц
        # записываем кодировку. Если кодировка размером в 1 байт или 2, дописываем в начале нулевой байт
        code_of_key = (hex_format_bytes(int(encrypt_dict[index], 2))).rjust(3, b'\x00')
        dict_haf += key + len_code_for_key + code_of_key
    dict_haf = dict_haf.ljust(snoopy[2]["offset_data"] - snoopy[2]["offset_dict_haf"], b'\x00')

    # запись данных из изходного файла с соответсвующей позиции
    with open(name_file, "rb") as f2:
        data_read = f2.read()
    data_read = bytes_to_256(data_read)
    data_read, size = bin_to_hex_haffman(data_read, encrypt_dict)

    size = (hex_format_bytes(size)).rjust(snoopy[2]["offset_id"] - snoopy[2]["offset_size_of_file"], b"\x00")

    data_snoopy2 = sig + ver + alg + size + id + link + dict_haf + data_read

    # добавление исходных данных в файл
    return data_snoopy2


def coder_with_encryptiion_rle(name_file):

    file_for_codec = read_signature_from_file(name_file)

    sig = snoopy[3]["signature"]

    ver = (hex_format_bytes(snoopy[3]["version"])).rjust(snoopy[3]["offset_code_alg"] - snoopy[3]["offset_version"], b"\x00")

    alg = (hex_format_bytes(3)).rjust(snoopy[3]["offset_size_of_file"] - snoopy[3]["offset_code_alg"], b"\x00")

    id = (hex_format_bytes(file_for_codec["id"])).rjust(snoopy[3]["offset_link"] - snoopy[3]["offset_id"], b"\x00")

    # получение абсолютного пути файла
    link = str(os.path.abspath(name_file)).encode()
    link = link.rjust(snoopy[3]["offset_data"] - snoopy[3]["offset_link"], b"\x00")


    # запись данных из изходного файла с соответсвующей позиции
    with open(name_file, "rb") as f2:
        data_read = f2.read()

    data_read = bytes_to_256(data_read)
    data_read = coding_rle(data_read)

    size = (hex_format_bytes(len(data_read))).rjust(snoopy[3]["offset_id"] - snoopy[3]["offset_size_of_file"], b"\x00")

    data_snoopy2 = sig + ver + alg + size + id + link + data_read

    # добавление исходных данных в файл
    return data_snoopy2


def coder_analise(code_alg, list_code_alg):
    prepared_file_for_report(name_coder_file, name_files)

    if code_alg == "without_encryptiion":  # шифровании файлов в массее
        # перебор указанных файлов
        for name_file in name_files.split():
            data_snoopy2 = coder_without_encryptiion(name_file)
            write_into_file(data_snoopy2, name_coder_file)

    elif code_alg == "haffman":  # шифровании файлов в массее
        encrypt_dict = get_encrypt_dict_for_haffman(name_files)  # Получаем словарь для шифрования

        for name_file in name_files.split():
            data_snoopy2 = coder_with_encryptiion_haffman(name_file, encrypt_dict)
            write_into_file(data_snoopy2, name_coder_file)

    elif code_alg == "rle":  # шифровании файлов в массее
        # перебор указанных файлов
        for name_file in name_files.split():
            data_snoopy2 = coder_with_encryptiion_rle(name_file)
            write_into_file(data_snoopy2, name_coder_file)

    elif code_alg == "user's choice":  # для каждого файла свой код шифрования
        index = 0  # индекс для перебора значений шифрования для файлов
        # перебор указанных файлов
        for name_file in name_files.split():
            if list_code_alg[index] == "without_encryptiion":
                data_snoopy2 = coder_without_encryptiion(name_file)
                write_into_file(data_snoopy2, name_coder_file)
            elif list_code_alg[index] == "haffman":
                encrypt_dict = get_encrypt_dict_for_haffman(name_file)  # Получаем словарь для шифрования
                data_snoopy2 = coder_with_encryptiion_haffman(name_file, encrypt_dict)
                write_into_file(data_snoopy2, name_coder_file)
            elif list_code_alg[index] == "rle":
                data_snoopy2 = coder_with_encryptiion_rle(name_file)
                write_into_file(data_snoopy2, name_coder_file)
            index += 1

    elif code_alg == "universal":
        for name_file in name_files.split():

            data_snoopy_with_encryptiion = coder_without_encryptiion(name_file)

            encrypt_dict = get_encrypt_dict_for_haffman(name_file)  # Получаем словарь для шифрования
            data_snoopy_haffman = coder_with_encryptiion_haffman(name_file, encrypt_dict)  # хаффман (получение шифрованных данных)

            data_snoopy_rle = coder_with_encryptiion_rle(name_file)

            size_wtihout_encryptiion = len(data_snoopy_with_encryptiion)
            size_with_haffman = len(data_snoopy_haffman)
            size_with_rle = len(data_snoopy_rle)

            data_snoopy2 = b""
            if (size_with_haffman < size_wtihout_encryptiion) and (size_with_haffman < size_with_rle):
                data_snoopy2 = data_snoopy_haffman
            elif (size_wtihout_encryptiion < size_with_haffman) and (size_wtihout_encryptiion < size_with_rle):
                data_snoopy2 = data_snoopy_with_encryptiion
            elif (size_with_rle < size_wtihout_encryptiion) and (size_with_rle < size_with_haffman):
                data_snoopy2 = data_snoopy_rle
            write_into_file(data_snoopy2, name_coder_file)


def decoder_without_encryptiion(file):
    size = file.read(snoopy[1]["offset_id"] - snoopy[1]["offset_size_of_file"])
    size = int_format(size)

    id = file.read(snoopy[1]["offset_link"] - snoopy[1]["offset_id"])
    id = int_format(id)

    link = file.read(snoopy[1]["offset_data"] - snoopy[1]["offset_link"])
    link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

    link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
    if not os.path.exists(link_abs):
        os.makedirs(link_abs)

    data_snoopy = file.read(size)

    with open(link, "wb") as f5:
        f5.write(data_snoopy)


def decoder_with_encryptiion_haffman(file):
    size = file.read(snoopy[2]["offset_id"] - snoopy[2]["offset_size_of_file"])
    size = int_format(size)

    id = file.read(snoopy[2]["offset_link"] - snoopy[2]["offset_id"])
    id = int_format(id)

    link = file.read(snoopy[2]["offset_dict_haf"] - snoopy[2]["offset_link"])
    link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

    link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
    if not os.path.exists(link_abs):
        os.makedirs(link_abs)

    dict_frequency = (file.read(snoopy[2]["offset_data"] - snoopy[2]["offset_dict_haf"]))

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
    data_snoopy = bytearray.fromhex(str_to_bytes(data_snoopy))

    with open(link, "wb") as f5:
        f5.write(data_snoopy)


def decoder_with_encryptiion_rle(file):
    size = file.read(snoopy[3]["offset_id"] - snoopy[3]["offset_size_of_file"])
    size = int_format(size)

    id = file.read(snoopy[3]["offset_link"] - snoopy[3]["offset_id"])
    id = int_format(id)

    link = file.read(snoopy[3]["offset_data"] - snoopy[3]["offset_link"])
    link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

    link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
    if not os.path.exists(link_abs):
        os.makedirs(link_abs)

    data_snoopy = file.read(size)

    data_snoopy = decoding_rle(data_snoopy)

    with open(link, "wb") as f5:
        f5.write(data_snoopy)


def decoder_analise():
    size_coder_file = os.path.getsize(name_coder_file)  # размер закодированного файла

    with open(name_coder_file, "rb") as file:
        while file.tell() != size_coder_file:
            bytes_signature = file.read(len(snoopy[1]["signature"]))
            info = get(bytes_signature)
            if info != "snoopy":
                print("Декодирование невозможно, сигнатура файла не соответсвует описанной")
                break

            ver = file.read(snoopy[1]["offset_code_alg"] - snoopy[1]["offset_version"])
            ver = int_format(ver)

            alg = file.read(snoopy[1]["offset_size_of_file"] - snoopy[1]["offset_code_alg"])
            alg = int_format(alg)

            if alg == 1:
                decoder_without_encryptiion(file)
            elif alg == 2:
                decoder_with_encryptiion_haffman(file)
            elif alg == 3:
                decoder_with_encryptiion_rle(file)


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
            print("2 - с шифрование (алгоритм Хаффмана)")
            print("3 - с шифрование (RLE алгоритм)")
            count = int(input())
            if count == 1:
                coder_print("without_encryptiion")
            elif count == 2:
                coder_print("haffman")
            elif count == 3:
                coder_print("rle")
        elif a == 2:
            print("Выберите способ шифрования для каждого файла:")
            print("1 - без шифрования")
            print("2 - с шифрование (алгоритм Хаффмана)")
            print("3 - с шифрование (RLE алгоритм)")
            list_code_alg = []
            for i in name_files.split():
                print("Для файла", os.path.abspath(i), ": ", end="")
                count = int(input())
                while count not in [1, 2, 3]:
                    print("Введите 1, 2 или 3: ", end="")
                    count = int(input())
                if count == 1:
                    list_code_alg.append("without_encryptiion")
                elif count == 2:
                    list_code_alg.append("haffman")
                elif count == 3:
                    list_code_alg.append("rle")
            coder_print("user's choice", list_code_alg)
        elif a == 3:
            coder_print("universal")
    elif q == 2:
        decoder_print()


if __name__ == "__main__":
    main()
