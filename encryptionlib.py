# Original Code Copyright CrazySqueak <crazysqueak.wordpress.com>, 2019
# DISCLAIMER: The above authors do not guarantee that your data will be secure using this program.
# Use this at your own risk.
# This program is shareware, as long as you leave the comments above this intact. If you make modifications to the code,
# you may add your own comment above the disclaimer.
import pickle,base64,os,random,hashlib,glob,time,enum

def readFile(file):
    with open(file,"rb") as f:
        fc = base64.b64encode(f.read())
    return fc
def writeFile(file,data):
    fd = base64.b64decode(data)
    with open(file,"wb") as f:
        f.write(fd)

class Encryptor():
    DEFAULT_ENCRYPTION_LETTER_SIZE = 2 #2 characters make up one "letter"
    def __init__(self,elsize=None):
        stime = time.time()
        if elsize == None:
            self.ENCRYPTION_LETTER_SIZE = self.DEFAULT_ENCRYPTION_LETTER_SIZE
        elif type(elsize) == int:
            self.ENCRYPTION_LETTER_SIZE = elsize
        else:
            raise TypeError("Encryption letter size must be an integer. Got: {}.".format(type(elsize)))
        chars = '''QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/=#''' # The hashtag is the padding for encryption when a letter is too short.
        lchars = []
        letteridxes = []
        for i in range(self.ENCRYPTION_LETTER_SIZE):
            letteridxes.append(0)
        letteridxes[-1] = 0

        while letteridxes[0] < len(chars):
            lt = ""
            for lidx_idx in range(len(letteridxes)):
                lt += chars[letteridxes[lidx_idx]]
            lchars.append(lt)
            letteridxes[-1] += 1
            for lidx_idx in range(-2,-len(letteridxes)-1,-1):
                if letteridxes[lidx_idx+1] >= len(chars):
                    letteridxes[lidx_idx+1] = 0
                    letteridxes[lidx_idx] += 1
        
        self.esquare = {}
        self.dsquare = {}
        for char in chars: #Key letters are still single. Therefore, no need to generate dual-letter key entries.
            self.esquare[char] = {}
            self.dsquare[char] = {}
            cnidx = lchars.index(char*self.ENCRYPTION_LETTER_SIZE) #Incompatibility issues
            for c in lchars:
                a = c
                b = lchars[cnidx]
                self.esquare[char][a] = b
                self.dsquare[char][b] = a
                cnidx += 1
                if cnidx >= len(lchars):
                    cnidx -= len(lchars)
        etime = time.time()
        print("Encryptor generated in {}s.".format(round(etime-stime,2)))

    def encryptLetter(self,letter,keyletter):
        return self.esquare[keyletter][letter]
    def decryptLetter(self,letter,keyletter):
        return self.dsquare[keyletter][letter]

    def encryptString(self,string,key):
        if len(key) < 1:
            raise MissingKeyError("Key must be at least 1 character long.")
        s = base64.b64encode(string).decode("utf-8")
        ok = base64.b64encode(key.encode("utf-8")).decode("utf-8")
        k = ""
        while len(k) < len(s):
            k += ok

        if self.ENCRYPTION_LETTER_SIZE == 1:
            result = self._fastencrypt(s,k)
        else:
            result = ""
            kidx = -1
            for chari in range(0,len(s),self.ENCRYPTION_LETTER_SIZE):
                kidx += 1
                lt = s[chari:chari+self.ENCRYPTION_LETTER_SIZE]
                while len(lt) < self.ENCRYPTION_LETTER_SIZE:
                    lt += "#"  # Hashtag is padding.
                result += self.encryptLetter(lt,k[kidx])
        return result
    def _fastencrypt(self,string,key):
        """Internal use only. Speedily encrypts a base64 string with a base64 UTF-8 key. ONLY WORKS IF LETTER SIZE IS 1!"""
        self.kidx = -1
        self.key = key
        return "".join(list(map(self._felet,string)))
    def _felet(self,let):
        self.kidx += 1
        return self.encryptLetter(let,self.key[self.kidx])
    def decryptString(self,string,key):
        if len(key) < 1:
            raise MissingKeyError("Key must be at least 1 character long.")
        s = string.decode("utf-8")
        ok = base64.b64encode(key.encode("utf-8")).decode("utf-8")
        k = ""
        while len(k) < len(s):
            k += ok

        if self.ENCRYPTION_LETTER_SIZE == 1:
            result = self._fastdecrypt(s,k)
        else:
            result = ""
            kidx = -1
            for chari in range(0,len(s),self.ENCRYPTION_LETTER_SIZE):
                kidx += 1
                lt = s[chari:chari+self.ENCRYPTION_LETTER_SIZE] # Encrypted string is always correct length.
                result += self.decryptLetter(lt,k[kidx]).replace("#","") # Remove padding.
        result = base64.b64decode(result.encode("utf-8"))
        return result
    def _fastdecrypt(self,string,key):
        """Internal use only. Speedily decrypts a base64 string with a base64 UTF-8 key. ONLY WORKS IF LETTER SIZE IS 1!"""
        self.kidx = -1
        self.key = key
        return "".join(list(map(self._fdlet,string)))
    def _fdlet(self,let):
        self.kidx += 1
        return self.decryptLetter(let,self.key[self.kidx])

class FileEncryptor():
    def __init__(self,lsize=2):
        self.e = Encryptor(lsize)

    def encryptFromFile(self,file,key):
        fc = readFile(file)
        result = self.e.encryptString(fc,key)
        return result
    def decryptToFile(self,file,data,key):
        result = self.e.decryptString(data,key)
        writeFile(file,result)
    def wipeFile(self,file):
        #Get length
        with open(file,"rb") as f:
            l = len(f.read())
        #Add 10% extra padding.
        l += int(l/10)
        #Wipe file
        with open(file,"wb") as f:
            for i in range(int(l/(1024**2))+1): #Every MegaByte
                f.write(bytes([random.randint(0,255)]*(1024**2)))
        #Remove file from disk
        os.remove(file)

class VaultModes(enum.Enum):
    DOINGNOTHING = 0
    CHECKING = 1
    STORING = 2
    EXTRACTING = 3
    WIPINGFILES = 4
    WIPINGDIRS = 5
    ESTIMATING = 6

class Vault():
    DEFAULT_BLOCKSIZE = (1024**2)*16  # 16MiB
    DEFAULT_SWITCHTHRESHOLD = (1024**2)  # When to switch to fastencrypt.
    def __init__(self,spath,epath,lsize=2,blocksize=None,switchthreshold=None):
        if blocksize == None:
            self.BLOCKSIZE = self.DEFAULT_BLOCKSIZE
        else:
            self.BLOCKSIZE = blocksize
        if switchthreshold == None:
            self.SWITCHTHRESHOLD = self.DEFAULT_SWITCHTHRESHOLD
        else:
            self.SWITCHTHRESHOLD = switchthreshold
        self.e = Encryptor(elsize=lsize)
        if lsize != 1:
            self.se = Encryptor(elsize=1)  # For large files
        else:
            self.se = self.e
        self.fe = FileEncryptor(lsize=1)  # The file encryptor isn't used to encrypt files therefore speed up creation.
        self.sp = spath #Store path
        self.sp_bp = os.path.join(spath,"blocks") #Block folder
        self.ep = epath #Export path
        self.state = VaultModes.DOINGNOTHING
        self.progress = 0
        self.target = 0
        if not os.path.exists(spath):
            os.mkdir(spath)
        if not os.path.exists(epath):
            os.mkdir(epath)
        if not os.path.exists(self.sp_bp):
            os.mkdir(self.sp_bp)

    def getRelativePath(self,path,root):
        path = path.replace("\\","/")
        root = root.replace("\\","/")
        result = path.replace(root,"")
        if result[0] == "/":
            result = result[1:]
        return result
    def store(self,key):
        mdata = {"LetterSize":self.e.ENCRYPTION_LETTER_SIZE,"totalblocks": 0, "blockhashes":{},
                 "switchthreshold": self.SWITCHTHRESHOLD, "files":{}, "dirs":[]}
        blockno = -1
        print("Estimating...")
        self.state = VaultModes.ESTIMATING
        total = 0
        sizes = {}
        for root,dirs,files in os.walk(self.ep):
            for f in files:
                with open(os.path.join(root,f),"rb") as fl:
                    tby = 0
                    data = fl.read(1024**2)
                    while len(data) > 0:
                        tby += 1024**2
                        data = fl.read(1024**2)
                    sizes[f] = tby
                    total += tby//self.BLOCKSIZE
                    if (tby%self.BLOCKSIZE) > 0:
                        total += 1
        print("Estimated size: {} blocks".format(total))
        print("Encrypting...")
        self.state = VaultModes.STORING
        self.progress = 0
        self.target = total
        for root,dirs,files in os.walk(self.ep):
            for d in dirs:
                #print("Directory: {}".format(d))
                dp = os.path.join(root,d)
                rdp = self.getRelativePath(dp,self.ep)
                rdp = self.e.encryptString(rdp.encode("utf-8"),key)
                mdata["dirs"].append(rdp)
            for fn in files:
                #print("File: {}".format(fn))
                fp = os.path.join(root,fn)
                orfp = self.getRelativePath(fp,self.ep)
                rfp = self.e.encryptString(orfp.encode("utf-8"),key)
                mdata["files"][rfp] = []
                with open(fp,"rb") as f:
                    if sizes[fn] < self.BLOCKSIZE:
                        buf = f.read()
                    else:
                        buf = f.read(self.BLOCKSIZE)
                    while len(buf) > 0:
                        blockno += 1
                        mdata["totalblocks"] += 1
                        #print("  Block: {}".format(blockno))
                        mdata["files"][rfp].append(blockno)

                        if len(buf) <= self.SWITCHTHRESHOLD:
                            buf = self.e.encryptString(buf,key).encode("utf-8")
                        else:
                            buf = self.se.encryptString(buf,key).encode("utf-8")  # Encrypt with the 1letter one.
                        
                        hasher = hashlib.sha512()
                        hasher.update(buf)
                        hash = hasher.hexdigest()
                        mdata["blockhashes"][blockno] = hash

                        write = True
                        if os.path.exists(os.path.join(self.sp_bp,"block{}".format(blockno))):
                            with open(os.path.join(self.sp_bp,"block{}".format(blockno)),"rb") as bf:
                                otherblk = bf.read()
                            if buf == otherblk:
                                write = False

                        if write:
                            with open(os.path.join(self.sp_bp,"block{}".format(blockno)),"wb") as bf:
                                bf.write(buf)
                        self.progress += 1
                        buf = f.read(self.BLOCKSIZE)
        print("Writing metadata...")
        with open(os.path.join(self.sp,"MANIFEST"),"wb") as m:
            pickle.dump(mdata,m)
        self.state = VaultModes.DOINGNOTHING
        return mdata
    def extract(self,key):
        print("Checking integrity...")
        self.checkIntegrity()
        print("Preparing to extract...")
        with open(os.path.join(self.sp,"MANIFEST"),"rb") as m:
            mdata = pickle.load(m)
        self.state = VaultModes.EXTRACTING
        self.progress = 0
        self.target = len(mdata["dirs"]) + mdata["totalblocks"]
        self.ost = self.SWITCHTHRESHOLD
        self.SWITCHTHRESHOLD = mdata["switchthreshold"]
        print("Creating directories...")
        for d in mdata["dirs"]:
            d = self.e.decryptString(d.encode("utf-8"),key).decode("utf-8")
            #print("Directory: {}".format(d))
            if not os.path.exists(os.path.join(self.ep, d)):
                os.mkdir(os.path.join(self.ep, d))
            else:
                print("Exists.")
            self.progress += 1
        print("Extracting files...")
        for f in mdata["files"].keys():
            f = f
            df = self.e.decryptString(f.encode("utf-8"),key).decode("utf-8")
            #print("File: {}".format(df))
            open(os.path.join(self.ep,df),"wb").close()
            blks = mdata["files"][f]
            for bn in blks:
                #print("  Block: {}".format(bn))
                with open(os.path.join(self.sp_bp,"block" + str(bn)),"rb") as bf:
                    buf = bf.read()
                if len(buf) <= self.SWITCHTHRESHOLD:
                    buf = self.e.decryptString(buf,key)
                else:
                    buf = self.se.decryptString(buf,key)
                with open(os.path.join(self.ep,df),"ab") as ef:
                    ef.write(buf)
                self.progress += 1
        self.state = VaultModes.DOINGNOTHING
        self.SWITCHTHRESHOLD = self.ost
        del self.ost
    def wipeExtracted(self):
        self.state = VaultModes.WIPINGFILES
        self.progress = 0
        self.target = 0
        for root,dirs,files in os.walk(self.ep, topdown=False):
            for f in files:
                #print(f)
                self.fe.wipeFile(os.path.join(root,f))
        self.state = VaultModes.WIPINGDIRS
        for root,dirs,files in os.walk(self.ep, topdown=False):
            for d in dirs:
                #print(d)
                os.rmdir(os.path.join(root,d))
            for f in files:
                #print(f)
                self.fe.wipeFile(os.path.join(root,f))
        self.state = VaultModes.DOINGNOTHING
    def checkIntegrity(self):
        self.state = VaultModes.CHECKING
        with open(os.path.join(self.sp,"MANIFEST"),"rb") as m:
            mdata = pickle.load(m)
        self.progress = 0
        self.target = mdata["totalblocks"] + len(mdata["files"]) + 1
        print("Checking blocks...")
        if len(glob.glob(os.path.join(self.sp_bp,"*"))) != mdata["totalblocks"]:
            print("INCORRECT AMOUNT OF BLOCKS. {} instead of {}.".format(len(glob.glob(os.path.join(self.sp_bp,"*"))),mdata["totalblocks"]))
            raise BlockAmountMismatch("INCORRECT AMOUNT OF BLOCKS. {} instead of {}.".format(len(glob.glob(os.path.join(self.sp_bp,"*"))),mdata["totalblocks"]))
        self.progress += 1
        for bn in range(mdata["totalblocks"]):
            if not os.path.exists(os.path.join(self.sp_bp,"block{}".format(bn))):
                print("BLOCK {} DOES NOT EXIST.".format(bn))
                raise MissingBlockError("BLOCK {} DOES NOT EXIST.".format(bn))
            with open(os.path.join(self.sp_bp,"block{}".format(bn)),"rb") as f:
                hasher = hashlib.sha512()
                hasher.update(f.read())
                hash = hasher.hexdigest()
                
                exp = mdata["blockhashes"][bn]
                
                print("Block {}".format(bn))
                if not hash == exp:
                    print("NON-MATCHING HASHES.")
                    raise NonMatchingHashError("Expected {} but got {}!".format(exp,hash))
            self.progress += 1
        print("Checking files...")
        for f in mdata["files"].keys():
            print("Checking file {}...".format(f))
            for bn in mdata["files"][f]:
                if bn >= mdata["totalblocks"]:
                    print("NON-EXISTENT BLOCK {} USED BY FILE '{}'.".format(bn,f))
                    raise MissingBlockError("NON-EXISTENT BLOCK {} USED BY FILE '{}'.".format(bn,f))
            self.progress += 1
        self.state = VaultModes.DOINGNOTHING

class CryptographyError(Exception):
    pass
class MissingKeyError(CryptographyError):
    pass

class IntegrityError(Exception):
    pass
class BlockAmountMismatch(IntegrityError):
    pass
class MissingBlockError(IntegrityError):
    pass
class NonMatchingHashError(IntegrityError):
    pass

def dV():
    v = Vault("N:/store","N:/backup")
    def a():
        pass
    v.extract = a
    v.wipeExtracted = a
    return v
def dVe():
    return Vault("N:/store","N:/backup2")

def benchmark_esize(file="D:/Personal/About Me.pptx",sizes=[1,2,3],key="ASDF"):
    print("Loading data...")
    with open(file,"rb") as f:
        data = f.read()
    encryptors = {}
    for s in sizes:
        print("Generating... size={}".format(s))
        encryptors[s] = Encryptor(s)
    for s in encryptors.keys():
        print("Encrypting... size={}".format(s))
        stime = time.time()
        encryptors[s].encryptString(data,key)
        etime = time.time()
        print("Encrypted. Time: {}s".format(round(etime-stime,2)))

def benchmark_esize_amnt(meg=1,sizes=[1,2,3],key="ASDF"):
    print("Generating data...")
    data = b"0"*((1024**2)*meg)
    encryptors = {}
    for s in sizes:
        print("Generating... size={}".format(s))
        encryptors[s] = Encryptor(s)
    for s in encryptors.keys():
        print("Encrypting... size={}".format(s))
        stime = time.time()
        encryptors[s].encryptString(data,key)
        etime = time.time()
        print("Encrypted. Time: {}s".format(round(etime-stime,2)))

def benchmark_vsize(file="D:/Personal/About Me.pptx",sizes=[1,2,3],key="ASDF"):
    encryptors = {}
    print("Generating vaults...")
    for s in sizes:
        encryptors[s] = Vault("temp",file)
    for s in sizes:
        print("Generating... size={}".format(s))
        encryptors[s].e = Encryptor(s)
    for s in encryptors.keys():
        print("Encrypting... size={}".format(s))
        stime = time.time()
        encryptors[s].store(key)
        etime = time.time()
        print("Encrypted. Time: {}s".format(round(etime-stime,2)))
