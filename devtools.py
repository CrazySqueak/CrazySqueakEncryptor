# These are a set of developer tools for working out various variables in the Encryptor program.
# This may be freely modified, and is exempt from the terms set out in LICENSING.md
# None of the authors accept responsibility for any problems caused by use of this program.
import statistics

import encryptionlib as elib
import time,os


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

def block_size_vs_speed_investigation(lsize,MiB=8):
    print("Init...")
    points = {}
    ec = elib.Encryptor(lsize)
    smalldata = b"x"*(1024**2)
    data = smalldata*MiB
    print("i1MiB*{}".format(MiB))
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

def kilobyte_block_size_investigation(lsize,start=1024,increment=32,reps=5):
    if not os.path.exists("temp2"): os.mkdir("temp2")
    with open("temp2/t.dat","wb") as f:
        f.write(b"x"*((start*1024)*5))
    value = start
    length = -1
    previouslength = -1
    while length <= previouslength or previouslength < 0 or length < 0:
        previouslength = length
        print(f"Size: {value}KiB.")
        v = elib.Vault("temp","temp2",lsize,value*1024,value*2048)
        lens = []
        for i in range(reps):
            print(f"Repeat #{i}.")
            print("Encrypting...")
            s = time.time()
            v.store("ASDF")
            e = time.time()
            print(f"Done. Time: {round(e-s,2)}")
            for root,dirs,files in os.walk("temp",topdown=False):
                for f in files:
                    os.remove(os.path.join(root,f))
                for d in dirs:
                    try:
                        os.remove(os.path.join(root,d))
                    except PermissionError:
                        pass # Frick you windows
            lens.append(e-s)
        length = statistics.mean(lens)
        print(f"Average: {round(length,2)}")
        print(f"Previous Time: {round(previouslength,2)}")
        value -= increment
    return value

def large_size_small_blocks_vs_small_size_large_blocks(size1=3,size2=1,MiB=2,repeats=1):
    pdata = {"l_size_s_block":[],"s_size_l_block":[]}
    e1 = elib.Encryptor(max(size1,size2))
    e2 = elib.Encryptor(min(size1,size2))
    data = b"x"*(1024**2)
    ldata = data*MiB
    for i in range(repeats):
        s = time.time()
        for i in range(MiB):
            e1.encryptString(data,"ASDF")
        e = time.time()
        lssb = round(e-s,2)
        s = time.time()
        e2.encryptString(ldata,"ASDF")
        e = time.time()
        sslb = round(e-s,2)
        pdata["l_size_s_block"].append(lssb)
        pdata["s_size_l_block"].append(sslb)
    return pdata
