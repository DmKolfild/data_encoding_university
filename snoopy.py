snoopy = {1: {"extension": "snoopy", "offset": 0, "signature": b"\xAA\xAA\xAA\xAA", "version": 1, "offset_version": 4,
               "offset_code_alg": 5, "offset_size_of_file":  6, "offset_id": 12, "offset_link": 14, "offset_data": 46},
          2: {"extension": "snoopy", "offset": 0, "signature": b"\xAA\xAA\xAA\xAA", "version": 1, "offset_version": 4,
               "offset_code_alg": 5, "offset_size_of_file": 6, "offset_id": 12, "offset_link": 14,
               "offset_dict_haf": 46, "offset_data": 1326},
          3: {"extension": "snoopy", "offset": 0, "signature": b"\xAA\xAA\xAA\xAA", "version": 1, "offset_version": 4,
               "offset_code_alg": 5, "offset_size_of_file":  6, "offset_id": 12, "offset_link": 14, "offset_data": 46},
          }

# offset - смщение указанного параметра
# Распределение байт:
# (offset_version - offset) - число байт под сигнатуру
# (offset_code_alg - offset_version) - число байт под нимер версии программы
# (offset_size_of_file - offset_code_alg) - число байт под номер кода алгоритма, используемого при шифровании
# (offset_id - offset_size_of_file) - число байт под запись рамера исходного файла
# (offset_link - offset_id) - число байт под id, соответсвующего сигнатуре исходного файла
# (offset_size_of_file_haffman - offset_link) - число байт под запись абсолютного пути исходного файла
# (offset_dict_haf - offset_size_of_file_haffman) - число байт под размер файла зашифрованного при помощи Хаффмана

# (offset_data - offset_dict_haf) - число байт под словарь ключей.
# Хаффман: 1 байта - ключ, 1 байт - длина исходной кодировки, 3 байта - кодировка
# Арифметическое кодирование: 1 байта - ключ, 3 байта - частота

# offset_data - смещение для записи данных исходного файла
