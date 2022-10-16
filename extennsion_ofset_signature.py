# словарь анализируемых сигнатур
# При анализе файлов будут сверка на данные из этого файла
# Список допустимых сигнатур можно расширить
data = [
    {"id": 0, "extension": "mp4", "offset": 4, "signature": [b"\x66\x74\x79\x70\x4D\x53\x4E\x56",
                                                             b"\x66\x74\x79\x70\x69\x73\x6F\x6D"]},
    {"id": 1, "extension": "..ops..", "offset": 8, "signature": [b"\xFF\xFF\xFF\xFF\xFF\xFF"]},
    {"id": 2, "extension": "jpg", "offset": 0, "signature": [b"\xFF\xD8\xFF"]},
    {"id": 3, "extension": "webp", "offset": 8, "signature": [b"\x57\x45\x42\x50"]},
    {"id": 4, "extension": "png", "offset": 0, "signature": [b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"]},
    {"id": 5, "extension": "doc", "offset": 0, "signature": [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                                                             b"\x50\x4B\x03\x04\x14\x00\x06\x00"]},
    {"id": 6, "extension": "pdf", "offset": 0, "signature": [b"\x25\x50\x44\x46"]},
    {"id": 7, "extension": "snoopy", "offset": 0, "signature": [b"\xAA\xAA\xAA\xAA"]}
]
