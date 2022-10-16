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
    string = coding_haffman(string, encryption_dict)
    print(string)
    # string = "1" + string  # дописаваем первую единицу, чтобы при декодировании не отвалился первый ноль (нули)
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


# name_files = "test.txt ..\\test\\test_subset\\56.txt 123.webp J.jpg "
name_files = "test.txt"
name_coder_file = "my_sig.snoopy"
encryption_dict = ''  # словарь частот символов


# code_alg: 1 - без шифрования, 2 - с шифрованием
def coder(code_alg):
    global encryption_dict
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

    # подсчет частот, если файлы рассматриваются в совокупности
    encryption_dict = ''
    if code_alg == 2:
        all_data_from_file = b""
        for name_file in name_files.split():
            with open(name_file, "rb") as file:
                all_data_from_file += file.read()
        str_alphabet = bytes_to_256(all_data_from_file)

        tree = get_tree_haffman(str_alphabet)  # создаем дерево шифрования
        encryption_dict = get_code_haffman(tree)  # Получаем словарь для шифрования
        print(encryption_dict)

    # перебор указанных файлов
    for name_file in name_files.split():
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
        # info - тип файла, соответсвующего сигнатуре
        # print(info)

        # # число байт отводимое под сигнатуру
        # count_byte_in_signature = file_for_codec["signature"][0]
        # count_byte_in_signature = " ".join(['{:02X}'.format(byte) for byte in count_byte_in_signature])
        # byte_signature = len(count_byte_in_signature.split())  # число байт под сигнатуру
        byte_signature = len(file_for_codec["signature"][0])  # замена подсчета количества байт на более простое выражение

        # копирование уже закодированных данных
        with open(name_coder_file, 'rb') as original:
            data_snoopy1 = original.read()
        # кодирование заданного файла
        with open(name_coder_file, "wb") as f1:
            # переход на нужную позицию сигнатуры и записи сигнатуры
            f1.seek(snoopy["offset"])  # 0 - смещение указателя от начала
            f1.write(snoopy["signature"])

            # переход на нужную позицию для версии кодера и запись версии
            f1.seek(snoopy["offset_version"], 0)
            f1.write(hex_format(snoopy["version"]))

            # переход на нужную позицию для номера используемого аллгоритма и запись номера
            f1.seek(snoopy["offset_code_alg"], 0)
            f1.write(hex_format(int(code_alg)))

            # переход на нужную позицию для размера файла и запись размера
            size = os.path.getsize(name_file)  # получение размера файла
            f1.seek(snoopy["offset_size_of_file"], 0)
            f1.seek(snoopy["offset_id"]-snoopy["offset_size_of_file"]-len(hex_format(size)), 1)
            f1.write(hex_format(size))

            # переход на нужную позицию для id соответсвующего изначальной сигнатуре файла и запись id
            f1.seek(snoopy["offset_id"], 0)
            # смещение для прямого порядка следования байт
            f1.seek(snoopy["offset_link"] - snoopy["offset_id"] - len(hex_format(file_for_codec["id"])), 1)
            f1.write(hex_format(file_for_codec["id"]))

            # переход на нужную позицию для абсолютного пути файла и запись пути
            link = str(os.path.abspath(name_file)).encode()
            f1.seek(snoopy["offset_link"], 0)
            f1.seek(snoopy["offset_size_of_file_haffman"] - snoopy["offset_link"] - len(link), 1)
            f1.write(link)

            # запись ключей для расшифровки (Хаффман)
            if code_alg == 2:
                f1.seek(snoopy["offset_dict_haf"], 0)
                for index in encryption_dict:
                    # записываем ключ. Если ключ размером в 1 байт или 2, дописываем в начале нулевые байты
                    f1.write(index.encode().rjust(2, b'\x00'))  # запись ключа
                    print(index.encode(), encryption_dict[index], len(encryption_dict[index]), hex_format(len(encryption_dict[index])))
                    f1.write(hex_format(len(encryption_dict[index])))  # запись длины кода для учета единиц
                    # записываем кодировку. Если кодировка размером в 1 байт или 2, дописываем в начале нулевой байт
                    str_write = (hex_format(int(encryption_dict[index], 2))).rjust(3, b'\x00')
                    f1.write(str_write)


            # запись данных из изходного файла с соответсвующей позиции
            with open(name_file, "rb") as f2:
                # чтение данных расположенных до сигнатуры
                bytes_befor_signature = f2.read(file_for_codec["offset"])
                # чтение данных, расположенных после сигнатуры
                f2.seek(file_for_codec["offset"]+byte_signature, 0)
                bytes_after_signature = f2.read()

                # чтение и запись побайтово
                # byte = "1"
                # f2.seek(byte_signature, 0)
                # while byte:
                #     byte = f2.read(1)
                #     f1.write(byte)

            # шифрование данных
            len_bytes_befor_signature = 0
            if code_alg == 2:
                # шифрование хаффмана
                if bytes_befor_signature != b"":
                    bytes_befor_signature = bytes_to_256(bytes_befor_signature)

                    bytes_befor_signature, len_bytes_befor_signature = bin_to_hex(bytes_befor_signature, encryption_dict)
                if bytes_after_signature != b"":
                    bytes_after_signature = bytes_to_256(bytes_after_signature)
                    bytes_after_signature, len_bytes_after_signature = bin_to_hex(bytes_after_signature, encryption_dict)
                f1.seek(snoopy["offset_size_of_file_haffman"], 0)
                f1.seek(snoopy["offset_dict_haf"] - snoopy["offset_size_of_file_haffman"] - len(hex_format(len(bytes_after_signature+bytes_befor_signature))), 1)
                print(len_bytes_befor_signature)
                print(bytes_befor_signature, bytes_after_signature)
                f1.write(hex_format(len(bytes_after_signature+bytes_befor_signature)))

            if code_alg == 1:
                f1.seek(snoopy["offset_data"], 0)
                f1.write(bytes_befor_signature)
                f1.write(bytes_after_signature)
            elif code_alg == 2:
                f1.seek(snoopy["offset_data"], 0)
                f1.write(hex_format(len_bytes_befor_signature))  # дописываем размер данных до сигнатуры, чтобы не потерять первые нули при декодировании и чтобы можно было различить их с данными полсе сигнатуры
                f1.write(bytes_befor_signature)
                f1.write(bytes_after_signature)

        # копирование данных, уже записанных в файл
        with open(name_coder_file, 'rb') as original:
            data_snoopy2 = original.read()

        # запись старых и новых данных в один файл
        with open(name_coder_file, 'wb') as modified:
            modified.write(data_snoopy1 + data_snoopy2)


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
    write_into_file(data_snoopy2)


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
    write_into_file(data_snoopy2)


def coder_analise(code_alg, code_alg_additional):
    prepared_file_for_report()

    if code_alg == 1:
        # перебор указанных файлов
        for name_file in name_files.split():
            coder_without_encryptiion(name_file)
    elif code_alg == 2:
        # шифровании файлов в массее
        if code_alg_additional == 1:  # для всех файлов один код шифрования

            # подсчет частот, если файлы рассматриваются в совокупности
            all_data_from_file = b""
            for name_file in name_files.split():
                with open(name_file, "rb") as file:
                    all_data_from_file += file.read()
            str_alphabet = bytes_to_256(all_data_from_file)

            tree = get_tree_haffman(str_alphabet)  # создаем дерево шифрования
            encrypt_dict = get_code_haffman(tree)  # Получаем словарь для шифрования

            print(encrypt_dict)

            for name_file in name_files.split():
                coder_with_encryptiion(name_file, encrypt_dict)

        elif code_alg_additional == 2: # для каждого файла свой код шифрования
            pass


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

def decoder():
    global encryption_dict

    with open(name_coder_file, "rb") as file:
        info = get(file.read(128))

    size_coder_file = os.path.getsize(name_coder_file)  # размер закодированного файла

    with open(name_coder_file, "rb") as file:
        while file.tell() != size_coder_file:
            qwe = file.read(len(snoopy["signature"]))
            info = get(qwe)
            if info != "snoopy":
                print("Декодирование невозможно, сигнатура файла не соответсвует описанной")
                break

            ver = file.read(snoopy["offset_code_alg"] - snoopy["offset_version"])
            ver = int_format(ver)

            alg = file.read(snoopy["offset_size_of_file"] - snoopy["offset_code_alg"])
            alg = int_format(alg)

            size = file.read(snoopy["offset_id"] - snoopy["offset_size_of_file"])
            size = int_format(size)

            id = file.read(snoopy["offset_link"] - snoopy["offset_id"])
            id = int_format(id)
            print("id = ", id)

            link = file.read(snoopy["offset_size_of_file_haffman"] - snoopy["offset_link"])
            link = link.lstrip(b"\x00").decode()  # удаляем нунжные нули вначале и декодируем

            size_haffman = file.read(snoopy["offset_dict_haf"] - snoopy["offset_size_of_file_haffman"])
            size_haffman = int_format(size_haffman)

            # раскодироваие словаря частот элементов
            dict_frequency = {}  # словарь с частотами
            dict_code_len = {}  # словарь с частотами и исходными длинами кодировок
            dict_haffman = file.read(snoopy["offset_data"] - snoopy["offset_dict_haf"])
            for index in range(0, len(dict_haffman), 6):
                s = dict_haffman[index:index+6]
                if s == b'\x00'*6:
                    break
                if s[0:1] == b'\x00':
                    char = s[1:2].decode()
                else:
                    char = s[0:2].decode()
                len_code = int_format(s[2:3])
                str_bytes = " ".join(['{:02X}'.format(byte) for byte in s[4:]])
                frequency = ""
                for i in str_bytes.split():
                    frequency += str(bin(int(i, 16)))
                frequency = frequency.replace("0b00b", "")  # избавляемся от первых ненужных нулей и префиксов (для случаев 0b00b123)
                frequency = frequency.replace("0b", "")  # окончательно избавляемся от префиксов
                dict_frequency[char] = frequency.rjust(len_code, "0")  # восстановление изначальных кодов
            print(dict_frequency)
            if alg == 1:
                if id != 1:  # проверка на txt
                    data_inf_befor_signature = file.read(data[id]["offset"])
                    data_inf_after_signature = file.read(size - len(data[id]["signature"][0]) - data[id]["offset"])
                else:
                    data_inf_befor_signature = b""
                    data_inf_after_signature = file.read(size)
            elif alg == 2:
                if id != 1:  # проверка на txt
                    data_inf_before_after_signature = file.read(size_haffman)
                    len_data_inf_before_after_signature = int_format(data_inf_before_after_signature[0:1])

                    data_inf_before_after_signature = data_inf_before_after_signature[1:]
                    str_haffman_decode = str(bin(int(data_inf_before_after_signature.decode(), 16)))[2:]
                    # убираем первую единицу, которая была добавлена при кодировании, чтобы не потерялись первые нули

                    data_inf_befor_signature = decoding_haffman(str_haffman_decode[0:len_data_inf_before_after_signature], dict_frequency)
                    data_inf_after_signature = decoding_haffman(str_haffman_decode[len_data_inf_before_after_signature:0], dict_frequency)
                    print(data_inf_befor_signature)

                    time.sleep(10)
                    # data_inf_before_after_signature = decoding_haffman(str_haffman_decode, dict_frequency)
                    #
                    # data_inf_before_after_signature = data_inf_before_after_signature.encode()
                    # data_inf_befor_signature = data_inf_before_after_signature[:data[id]["offset"]]
                    # data_inf_after_signature = data_inf_before_after_signature[data[id]["offset"]:]

                else:
                    data_inf_befor_signature = b""
                    data_inf_after_signature = file.read(size_haffman)
                    str_bytes = "".join(['{:02X}'.format(byte) for byte in data_inf_after_signature])
                    s = ""
                    for i in str_bytes.split():
                        s += str(bin(int(i, 16)))[2:]
                    # ДОБАВИТЬ ПРОВЕРКУ НА ПУСТОЙ ФАЙЛ

                    str_haffman_decode = str(bin(int(data_inf_after_signature.decode(), 16)))[2:]
                    # убираем первую единицу, которая была добавлена при кодировании, чтобы не потерялись первые нули
                    str_haffman_decode = str_haffman_decode[1:]
                    data_inf_after_signature = (decoding_haffman(str_haffman_decode, dict_frequency)).encode()

            # Подправить обработку txt (пусть декодируется вместе со всеми)

            link_abs = link[0:link.rfind("\\") - len(link)]  # абсолютный путь без названия файла
            if not os.path.exists(link_abs):
                os.makedirs(link_abs)

            with open(link, "wb") as f5:
                f5.write(data_inf_befor_signature)
                if id != 1:  # проверка на txt
                    f5.write(data[id]["signature"][0])  # запись сигнатуры
                f5.write(data_inf_after_signature)  # запись информации



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
    # decoder()
    decoder_analise()
    print(datetime.datetime.now(), "Декодер завершен")
    time.sleep(1)


def coder_print(code_alg, code_alg_additional=0):
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
    # coder(code_alg)
    coder_analise(code_alg, code_alg_additional)
    print(datetime.datetime.now(), "Кодер завершен")
    time.sleep(1)

# if not os.path.exists("D:\\otik\\test\\test_subset"):
#     os.makedirs("D:\\otik\\test\\test_subset")
#
# with open("..\\test\\test_subset\\q.txt", "r") as f:
#     print(os.path.abspath("..\\test\\test_subset\\q.txt"))
#     s = f.read()
#     print(s)


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
                coder_print(2, 1)

        elif a == 2:
            print("Выберите способ шифрования для каждого файла:")
            print("1 - без шифрования")
            print("2 - с шифрованием")
            list_alg = []
            for i in name_files.split():
                print("Для файла", os.path.abspath(i), ": ", end="")
                count = int(input())
                while count not in [1, 2]:
                    print("Введите 1 или 2: ", end="")
                    count = int(input())
                list_alg.append(count)
            print(list_alg)

        elif a == 3:
            pass
    elif q == 2:
        decoder_print()


if __name__ == "__main__":
    main()
