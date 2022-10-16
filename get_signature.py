from extennsion_ofset_signature import data


# получение сигнатуры файла
def get(obj):

    info = {"extension": dict()}
    hex_bytes = " ".join(['{:02X}'.format(byte) for byte in obj])  # перевод байтов в str 16-bit формат

    for element in data:
        for signature in element["signature"]:
            offset = element["offset"] * 2 + element["offset"]
            signature_decode = " ".join(['{:02X}'.format(byte) for byte in signature])
            if signature_decode == hex_bytes[offset:len(signature_decode) + offset]:
                info["extension"][element["extension"]] = len(signature_decode)

    info["extension"] = [element for element in sorted(info["extension"])]

    if len(info["extension"]) == 0:
        return "txt"
    else:
        return info["extension"][0]
