# Original Code Copyright CrazySqueak <crazysqueak.wordpress.com>, 2019
# DISCLAIMER: The above authors do not guarantee that your data will be secure using this program.
# Use this at your own risk.
# This program is shareware, as long as you leave the comments above this intact. If you make modifications to the code,
# you may add your own comment above the disclaimer.

import tkinter,os,random,sys,pickle,threading,time
from enum import Enum

os.chdir(os.path.dirname(sys.argv[0]))  # Thanks to StackOverflow for this amazing solution.

def loadSettings():
    try:
        with open("settings","rb") as f:
            settings = pickle.load(f)
    except:
        settings = {"defaultroot": "~"}
    return settings
def saveSettings(settings):
    with open("settings","wb") as f:
        pickle.dump(settings,f)
settings = loadSettings()

DEFAULTLETTERSIZE = 3

import encryptionlib as elib
import tkinter.filedialog as fd
import tkinter.messagebox as mb

class ThreadedEncryptionModes(Enum):
    STORE = 1
    EXTRACT = 2
    BACKUP = 3

class EncryptionThread(threading.Thread):
    def __init__(self,spath,epath,key,mode=ThreadedEncryptionModes.STORE,lsize=2):
        threading.Thread.__init__(self)
        self.spath = spath
        self.epath = epath
        self.key = key
        self.mode = mode
        self.lsize = lsize
        self.callback = None
        self.errorback = None
        self.vault = elib.Vault(spath,epath,lsize=1) # Temporary vault for state checks.

    def setCallback(self,f):
        self.callback = f
    def setErrorCallback(self,f):
        self.errorback = f

    def run(self):
        mf = os.path.join(self.spath,"MANIFEST")
        if self.mode == ThreadedEncryptionModes.EXTRACT and os.path.exists(mf):
            with open(mf,"rb") as f:
                data = pickle.load(f)
                if "LetterSize" in data.keys():
                    self.lsize = data["LetterSize"]
                    print("Overriding letter size by order of the manifest. New: {}".format(self.lsize))
                else:
                    print("Overriding letter size due to lack of specification. New: 1")
                    self.lsize = 1
        vault = elib.Vault(self.spath,self.epath,lsize=self.lsize)  # Generate the real vault
        self.vault = vault  # Allow others to access it.
        try:
            if self.mode == ThreadedEncryptionModes.STORE:
                vault.store(self.key)
                vault.wipeExtracted()
            elif self.mode == ThreadedEncryptionModes.EXTRACT:
                vault.extract(self.key)
            elif self.mode == ThreadedEncryptionModes.BACKUP:
                vault.store(self.key)
            else:
                raise ValueError("Unknown mode.")
        except:
            err = sys.exc_info()
            if self.errorback:
                self.errorback(err)
            else:
                raise err[1]
        else:
            self.callback()

class Window:
    def __init__(self):
        self.window = tkinter.Tk("CrazySqueak Encryptor")
        self.window.title("CrazySqueak's Encryptor")
        self.frame = None
        self.vault = None
        self.k = None
        self.pleasewait = False
        self.oldstate = None
        self.stime = 0
        self.thread = EncryptionThread("temp","temp","temp",lsize=1)

    def init(self):
        self.frame = OpenFrame(self.window)
        self.frame.pack()

    def ResetFrame(self):
        self.frame.destroy()
        self.frame = CurrentlyOpenFrame(self.window)
        self.frame.pack()
        self.pleasewait = False
    def ResetOpenFrame(self):
        self.frame.destroy()
        self.frame = OpenFrame(self.window)
        self.frame.pack()
        self.pleasewait = False
    def ResetPleaseWait(self):
        self.frame.destroy()
        self.frame = tkinter.Label(self.window, text="Please wait...")
        self.frame.pack()
        self.oldstate = None
        self.pleasewait = True
        self.window.after(100,self.pleasewaitupdater)
    def ErrorCallback(self,err):
        if err[0] == elib.IntegrityError:
            mb.showerror("Error", "Vault is corrupt. Please check the console for more details.")
            print(err[0], err[1])
            self.ResetOpenFrame()
        else:
            raise err[1]

    def pleasewaitupdater(self):
        if not self.pleasewait:
            return
        else:
            self.window.after(100,self.pleasewaitupdater)

        status = self.thread.vault.state
        target = self.thread.vault.target
        progress = self.thread.vault.progress
        if status != self.oldstate:
            self.stime = time.time()
            self.oldstate = status
        elapsed = time.time()-self.stime
        delapsed = round(elapsed,0)
        if target == progress:
            percent = 100
            speed = 0
            tme = 0
        else:
            percent = round((progress/target)*100,2)
            speed = progress/elapsed  # Speed = distance over time
            if speed != 0:
                tme = target/speed  # Time = distance over speed, provided speed isn't equal to zero.
            else:
                tme = -1  # You're not getting anywhere if you're not moving.
        if tme == -1:
            dtme = "Unknown."
        elif tme < 60:  # Measurable in seconds.
            dtme = "{} seconds".format(int(tme))
        elif tme < 60*10:  # Measurable in minutes and seconds.
            m = tme//60  # Get the minutes
            s = int(tme%60)  # Get the seconds.
            dtme = "{} minutes, and {} seconds.".format(m,s)
        elif tme < 60*60:  # Measurable in minutes
            m = tme//60  # Get the minutes
            dtme = "About {} minutes.".format(m)
        elif tme < (60*60)*10:  # Measurable in hours and minutes.
            h = tme//(60*60)
            m = int(tme%(60*60))
            dtme = "About {} hours, and {} minutes.".format(h,m)
        elif tme < (60*60)*24:  # Less than a day
            h = tme//(60*60)
            dtme = "About {} hours.".format(h)
        else:
            dtme = "Longer than it takes to compute the answer to the ultimate question of life, the universe, and everything."
        if status == elib.VaultModes.DOINGNOTHING:
            self.frame.config(text=f"Please wait...\nTime Elapsed: {delapsed}s")
        elif status == elib.VaultModes.WIPINGFILES:
            self.frame.config(text=f"Wiping (part 1 of 2)...\nTime Elapsed: {delapsed}s")
        elif status == elib.VaultModes.WIPINGDIRS:
            self.frame.config(text=f"Wiping (part 2 of 2)...\nTime Elapsed: {delapsed}s")
        elif status == elib.VaultModes.ESTIMATING:
            self.frame.config(text=f"Estimating block amount...\nTime Elapsed: {delapsed}s")
        elif status == elib.VaultModes.CHECKING:
            self.frame.config(text=f"Checking integrity... ({percent}%)\n{progress} of {target} checks completed.\nTime Elapsed: {delapsed}s\nETA: {dtme}")
        elif status == elib.VaultModes.STORING:
            self.frame.config(text=f"Encrypting files... ({percent}%)\n{progress} of {target} blocks complete.\nTime Elapsed: {delapsed}s\nETA: {dtme}")
        elif status == elib.VaultModes.EXTRACTING:
            self.frame.config(text=f"Extracting files... ({percent}%)\n{progress} of {target} blocks processed.\nTime Elapsed: {delapsed}s\nETA: {dtme}")

    def openVault(self):
        v = self.frame.ent1.get()
        e = self.frame.ent2.get()
        k = self.frame.ent3.get()
        self.k = k
        if not os.path.exists(os.path.join(v,"MANIFEST")):
            mb.showerror("Error","Vault is non-existent, corrupt, or not a vault.")
            return
        elif len(k) < 1:
            mb.showerror("Error","Key must be at least 1 character long.")
            return

        self.ResetPleaseWait()

        esects = os.path.split(e)[:-1]
        settings["defaultroot"] = ""
        for s in esects:
            settings["defaultroot"] += s
        saveSettings(settings)

        self.thread = EncryptionThread(v,e,k,ThreadedEncryptionModes.EXTRACT,lsize=DEFAULTLETTERSIZE)
        self.thread.setCallback(self.ResetFrame)
        self.thread.setErrorCallback(self.ErrorCallback)
        self.thread.start()
        '''self.vault = elib.Vault(v,e)
        try:
            self.vault.extract(k)
        except elib.IntegrityError:
            mb.showerror("Error","Vault is corrupt. Please check the console for more details.")
            ex = sys.exc_info()
            print(ex[0],ex[1])
            l.destroy()
            self.frame = OpenFrame(self.window)
            self.frame.pack()
            return'''
    def closeVault(self):
        if len(self.k) < 1:
            mb.showerror("Error", 'Key must be at least 1 character long. Change it using "Change key"')
            return

        self.ResetPleaseWait()

        v, e = self.thread.spath, self.thread.epath
        k = self.k
        self.thread = EncryptionThread(v, e, k, ThreadedEncryptionModes.STORE,lsize=DEFAULTLETTERSIZE)
        self.thread.setCallback(self.ResetOpenFrame)
        self.thread.setErrorCallback(self.ErrorCallback)
        self.thread.start()
        '''self.vault.store(self.k)
        self.vault.wipeExtracted()

        self.frame.destroy()
        self.frame = OpenFrame(self.window)
        self.frame.pack()'''
    def newVault(self):
        v = self.frame.ent1.get()
        e = self.frame.ent2.get()
        k = self.frame.ent3.get()
        if len(k) < 1:
            mb.showerror("Error", 'Key must be at least 1 character long. Change it and try again.')
            return

        self.ResetPleaseWait()

        self.k = k
        self.thread = EncryptionThread(v,e,k,ThreadedEncryptionModes.BACKUP,lsize=DEFAULTLETTERSIZE)
        self.thread.setCallback(self.ResetFrame)
        self.thread.setErrorCallback(self.ErrorCallback)
        self.thread.start()

    def changeKey(self):
        self.frame.destroy()
        self.frame = ChangeKeyFrame()
        self.frame.pack()
    def changeKeyCallback(self):
        self.k = self.frame.ent1.get()
        self.frame.destroy()
        self.frame = CurrentlyOpenFrame(self.window)
        self.frame.pack()
    def openVaultFolder(self):
        path = self.thread.epath
        try:
            os.startfile(path)
        except:
            os.system("xdg-open '{}'".format(path))

    def mainloop(self):
        self.window.mainloop()
    def destroy(self):
        self.window.destroy()

class ChangeKeyFrame(tkinter.Frame):
    def __init__(self,parent):
        tkinter.Frame.__init__(self,parent)

        lab1 = tkinter.Label(self,text="New Key:")
        ent1 = tkinter.Label(self,width=50)
        but1 = tkinter.Button(self,text="Change",command=win.changeKeyCallback)

        lab1.grid(column=1,row=1)
        ent1.grid(column=2,row=1)
        but1.grid(column=1,row=2,columnspan=2)

class CurrentlyOpenFrame(tkinter.Frame):
    def __init__(self, parent):
        tkinter.Frame.__init__(self, parent)

        lab1 = tkinter.Label(self,text="A vault is currently open.")
        but1 = tkinter.Button(self,text="Change key",command=win.changeKey)
        but2 = tkinter.Button(self,text="Close Vault",command=win.closeVault)
        but3 = tkinter.Button(self,text="Open Folder",command=win.openVaultFolder)

        lab1.grid(column=1,row=1,columnspan=2)
        but1.grid(column=1,row=2)
        but2.grid(column=2,row=2)
        but3.grid(column=3,row=1)


class OpenFrame(tkinter.Frame):
    def __init__(self, parent):
        tkinter.Frame.__init__(self, parent)

        lab1 = tkinter.Label(self,text="Vault directory: ")
        lab2 = tkinter.Label(self,text="Plaintext directory: ")
        lab3 = tkinter.Label(self,text="Encryption Key: ")
        ent1 = tkinter.Entry(self,width=50)
        ent2 = tkinter.Entry(self,width=50)
        ent3 = tkinter.Entry(self,width=50)
        but1 = tkinter.Button(self,text="Browse...",command=self.browse1)
        but2 = tkinter.Button(self,text="Browse...",command=self.browse2)
        butS = tkinter.Button(self,text="Open",command=win.openVault)
        butN = tkinter.Button(self,text="New Vault",command=win.newVault)

        ent2.insert(tkinter.END,os.path.join(settings["defaultroot"],"CsEcTemp{}".format(random.randint(1000,9999))))

        lab1.grid(column=1,row=1)
        lab2.grid(column=1,row=2)
        lab3.grid(column=1,row=3)
        ent1.grid(column=2,row=1)
        ent2.grid(column=2,row=2)
        ent3.grid(column=2,row=3)
        but1.grid(column=3,row=1)
        but2.grid(column=3,row=2)
        butS.grid(column=3,row=4)
        butN.grid(column=1,row=4)

        self.ent1, self.ent2, self.ent3 = ent1, ent2, ent3

    def browse1(self):
        path = fd.askdirectory(parent=self)
        if path:
            self.ent1.delete(0,tkinter.END)
            self.ent1.insert(0,path)
    def browse2(self):
        path = fd.askdirectory(parent=self)
        if path:
            self.ent2.delete(0,tkinter.END)
            self.ent2.insert(0,path)

win = Window()
win.init()
win.mainloop()
sys.exit(0)