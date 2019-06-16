import encryptionlib as elib
import time


def get_1vs3_threshold():
    """Gets the point at which the 1letter encryption is faster than 3letter."""
    print("Initialising...")
    points = {1: {}, 3: {}}
    e1 = elib.Encryptor(elsize=1)
    e2 = elib.Encryptor(elsize=3)
    size = 1024**2  # 1 Mebibyte
    modification = 1024**2  # 1KiB
    done = False
    print("Working...")
    while not done:
        print(f"Size: {size}")
        if size in points[1].keys():
            print("Had this size already.")
            return size,points
        data = b"x"*size
        print("Encrypting with lsize=1.")
        s = time.time()
        _ = e1.encryptString(data, "ASDF")
        e = time.time()
        print(f"Time: {round(e-s,2)}s")
        points[1][size] = round(e-s,2)
        print("Encrypting with lsize=3.")
        s = time.time()
        _ = e1.encryptString(data, "ASDF")
        e = time.time()
        print(f"Time: {round(e - s, 2)}s")
        points[3][size] = round(e-s,2)
        if points[1][size] < points[3][size]:
            size -= modification
            modification //= 2
        elif points[1][size] > points[3][size]:
            size += modification
        else:
            return size,points

def get_lvs3_threshold_KiB():
    return get_1vs3_threshold()[0]//1024

def block_size_vs_speed_investigation(lsize):
    print("Init...")
    points = {}
    ec = elib.Encryptor(lsize)
    MiB = 8
    smalldata = b"x"*(1024**2)
    data = smalldata*MiB
    print("1MiB*{}".format(MiB))
    s = time.time()
    for i in range(MiB):
        ec.encryptString(smalldata,"KEY")
    e = time.time()
    points[1] = e-s
    print(f"Time: {round(e-s,2)}s")
    print("{}MiB".format(MiB))
    s = time.time()
    ec.encryptString(data, "KEY")
    e = time.time()
    points[MiB] = e-s
    print(f"Time: {round(e - s, 2)}s")
    return points