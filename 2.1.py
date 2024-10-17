from hashlib import sha1
import codecs
import base64
from Crypto.Cipher import AES
import binascii

"""求未知数，是到期日的校验位，根据校验规则计算"""
def Unknown_Number() -> int:
    Unknown_Number = 0
    number = "111116"
    weight = "731"	
    for i in range(0, len(number)):
        Unknown_Number += int(number[i]) * int(weight[i % 3])
    return Unknown_Number % 10


"""计算 k_seed"""
def cal_Kseed() -> str:
    MRZ_information = "12345678<811101821111167"
    # 护照号码+校验位+出生日期+校验位+到期日+校验位(包括"<"符号)
    H_information = sha1(MRZ_information.encode()).hexdigest()
    # 十六进制字符串
    K_seed = H_information[0:32]
    # 最高有效 16 字节用作 K_seed
    return K_seed


def cal_Ka_Kb(K_seed):
    c = "00000001"
    d = K_seed + c
    H_d = sha1(codecs.decode(d, "hex")).hexdigest()
    # 十六进制先变为二进制散列再转换成十六进制
    ka = H_d[0:16]
    kb = H_d[16:32]
    return ka, kb


"""对 Ka 和 Kb 分别进行奇偶校验，得到新的 k1 和 k2"""
def Parity_Check(x):
    k_list = []
    a = bin(int(x, 16))[2:]
    # 16 进制字符串转 2 进制字符串
    for i in range(0, len(a), 8):
        # 7 位一组分块，计算一个校验位，使 1 的个数为偶数
        # 舍弃原来的第 8 位
        if (a[i:i + 7].count("1")) % 2 == 0:
            k_list.append(a[i:i + 7])
            k_list.append('1')
        else:
            k_list.append(a[i:i + 7])
            k_list.append('0')

    k = hex(int(''.join(k_list), 2))
    return k


if __name__ == "__main__":
    K_seed = cal_Kseed()
    ka, kb = cal_Ka_Kb(K_seed)
    # print(ka, kb)
    k_1 = Parity_Check(ka)
    k_2 = Parity_Check(kb)
    # print(k_1, k_2)
    key = k_1[2:] + k_2[2:]
    print(key)

    ciphertext = base64.b64decode(
        "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI"
    )
    IV = '0' * 32

    m = AES.new(binascii.unhexlify(key), AES.MODE_CBC, binascii.unhexlify(IV)).decrypt(ciphertext)
    print(m)
