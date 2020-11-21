import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

from encodings.aliases import aliases
from base64 import b16encode, b16decode, b64encode, b64decode, b85encode, b85decode
from hashlib import md5, sha1, sha256, sha384, sha512
from zipfile import ZipFile, is_zipfile, ZipInfo
from tarfile import is_tarfile, TarFile, TarInfo
import py_compile, zlib, gzip, bz2, lzma, codecs

from os import getcwd, path, chdir, remove
from subprocess import PIPE, Popen
from threading import Thread
from time import time
import sys, json, re, keyword, string

class Constante :

    def __init__ (self) :
        self.editor_dir = getcwd()
        self.files_path = path.join(self.editor_dir, "files")
        self.config_path = path.join(self.editor_dir, "config")
        self.reopen_files = open(path.join(self.config_path, "lasts.db"), encoding = "utf-8").read().split("\n")
        
        self.get_config()

        if self.config["general"]["use_theme"] :
            self.get_color_themes(self.config["general"]['default_theme'])
        
        self.default_name ()

    def add_reopen_file (self) :
        self.reopen_files = open(path.join(self.config_path, "lasts.db"), encoding = "utf-8").read().split("\n")
        if self.file_full_name not in self.reopen_files and self.file_full_name != "" :
            self.reopen_files.append(self.file_full_name)
            if len(self.reopen_files) >= 5 :
                self.reopen_files = self.reopen_files[-5:]
        with open(path.join(self.config_path, "lasts.db"), "w", encoding = "utf-8") as file :
            file.write("\n".join(self.reopen_files))

    def get_config (self) :
        config_file = path.join(self.config_path, "config.json")
        if path.isfile(config_file) :
            with open(config_file, "r", encoding = "utf-8") as config :
                self.config = json.load(config)
        else :
            self.config = self.default_config()

    def default_config (self) :
        return {
            "general" : {
                "default_theme" : "Sombre",
                "use_theme" : True,
                "default_file_name" : "Untitle",
                "encodings" : ["utf_8", "cp850", "cp1250", "cp1252", "iso-8859-2", "latin1"]
            },

            "font" : {
                "normal" : ["ubuntu", 12, "normal"],
                "string" : ["ubuntu", 12, "italic"],
                "interface" : ["ubuntu", 14, "normal"]
            },

            "color" : {
                "background_text" : "RoyalBlue1",
                "background_interface" : "SlateBlue1",
                "text_normal" : "blue4",
                "text_interface" : "navy"
            },

            "security" : {
                "password_size" : 25
            },

            "syntax" : {
                "python_default" : {
                    "KEYWORD" : { "FONT" : ["ubuntu", 12, "bold"], "COLOR" : "tomato" },
                    "SYNC" : { "FONT" : ["ubuntu", 12, "bold"], "COLOR" : "gold" },
                    "BUILTIN" : { "FONT" : ["ubuntu", 12, "bold"], "COLOR" : "dark orange" },
                    "STRING" : { "FONT" : ["ubuntu", 12, "italic"], "COLOR" : "OrangeRed2" },
                    "COMMENT" : { "FONT" : ["ubuntu", 12, "normal"], "COLOR" : "chocolate3" }
                },

                ".py" : {
                    "OPERATOR" : { 
                        "VALUES" : ["=", "\\+", "\\*", "/", "%", "\\<", "\\>", "\\&", "\\|", "\\^", "-"],
                        "COLOR" : "goldenrod1",
                        "FONT" : ["ubuntu", 12, "normal"]
                    },
                    
                    "NUMBERS" : {
                        "VALUES" : ["[0-9]{1,}\\b", "0x[0-9a-fA-F]{1,}\\b", "\\\\x[0-9a-fA-F]{1,}\\b"],
                        "COLOR" : "red",
                        "FONT" : ["ubuntu", 12, "normal"]
                    },

                    "CONSTANTE" : {
                        "VALUES" : ["[A-Z]{1,}\\b"],
                        "COLOR" : "firebrick1",
                        "FONT" : ["ubuntu", 12, "normal"]
                    }
                }
            }
        }

    def default_name (self) :
        compteur = 0
        self.default_filename = path.join(self.files_path, self.config['general']["default_file_name"])
        while path.exists(f'{self.default_filename}{str(compteur)}.txt') :
            compteur += 1
        self.file_name = f'{self.config["general"]["default_file_name"]}{str(compteur)}.py'
        self.file_full_name = path.join(self.files_path, self.file_name)

    def get_color_themes (self, theme) :
        if theme == "Clair" :
            self.config["color"]["background_text"] = "white"
            self.config["color"]["background_interface"] = "gray75"
            self.config["color"]["text_normal"] = "black"
            self.config["color"]["text_interface"] = "black"
        else :
            self.config["color"]["background_text"] = "gray15"
            self.config["color"]["background_interface"] = "gray26"
            self.config["color"]["text_normal"] = "AntiqueWhite1"
            self.config["color"]["text_interface"] = "snow"

class Menubar:

    def __init__(self, parent):

        menubar = tk.Menu(parent.master)
        self.config(menubar, parent)
        parent.master.config(menu = menubar)

        file_dropdown = tk.Menu(menubar)
        file_dropdown.add_command(label = "Nouveau",
            accelerator = "Ctrl+N", command = parent.new_file)
        file_dropdown.add_command(label = "Ouvrir",
            accelerator = "Ctrl+O", command = parent.ask_file)

        reopen_dropdown = tk.Menu(file_dropdown)
        for file in parent.constante.reopen_files :
            if path.isfile(file) :
                reopen_dropdown.add_command(label = file, 
                    command = lambda file = file : parent.open_file(file))
        self.config(reopen_dropdown, parent)
        file_dropdown.add_cascade(label = "Ré-ouvrir",
            menu = reopen_dropdown)
        
        file_dropdown.add_command(label = "Sauvegarder",
            accelerator = "Ctrl+S", command = parent.save)
        file_dropdown.add_command(label = "Sauvegarder sous...",
            accelerator = "Ctrl+Shift+S", command = parent.save_as)
        
        file_dropdown.add_separator()
        file_dropdown.add_command(label = "info", accelerator = "Ctrl+I",
            command = parent.get_info)
        file_dropdown.add_command(label = "Rechercher", accelerator = "Ctrl+F",
            command = parent.find)
        file_dropdown.add_separator()
        
        file_dropdown.add_command(label = "Quitter",
            command = parent.exit)
        self.config(file_dropdown, parent)

        theme_dropdown = tk.Menu(menubar)
        theme_dropdown.add_command(label = "Sombre",
            command = lambda : self.modif_config(parent, "Sombre"))
        theme_dropdown.add_command(label = "Clair",
            command = lambda : self.modif_config(parent, "Clair"))
        theme_dropdown.add_command(label = "Pas de theme",
            command = lambda : self.modif_config(parent))
        self.config(theme_dropdown, parent)

        crypt_dropdown = tk.Menu(menubar)
        crypt_dropdown.add_command(label = "Cryptage : faible (sans clés)", command = lambda : (f:=open(
            parent.constante.file_full_name+".crypt",'wb'),f.write(b85encode(b16encode(codecs.encode(parent.textarea.get(
                1.0,tk.END),"rot13").encode()))),f.close(),print("Le fichier a été crypté avec succès.")))
        crypt_dropdown.add_command(label = "Cryptage : fort (avec clés)", command = lambda : (key:=simpledialog.askstring(
            "Clef","Clef de cryptage",show="*"),f:=open(parent.constante.file_full_name+".crypt","wb"),f.write(File.XOR(
                parent.textarea.get(1.0,tk.END).encode(),key)),f.close(),print("Le fichier a été crypté avec succès")))
        crypt_dropdown.add_command(label = "Décryptage : faible (sans clés)", command = lambda : (
            file:=filedialog.askopenfilename(defaultextension=".crypt").replace("/", "\\"),f:=open(file,'rb'),code:=f.read(),
            f.close(),f:=open(file+".decrypt","w"),f.write(codecs.decode(b16decode(b85decode(code)).decode(),"rot13")
                ),f.close(),print("Le fichier a été décrypté avec succès.")))
        crypt_dropdown.add_command(label = "Décrypter : fort (avec clés)", command = lambda : (file:=filedialog.askopenfilename(
            defaultextension=".crypt").replace("/", "\\"),key:=simpledialog.askstring("Clef","Clef de cryptage",show="*"),
            f:=open(file,'rb'),code:=File.XOR(f.read(),key),f.close(),f:=open(file+".decrypt",'wb'),f.write(code),f.close(),
            print("Le fichier a été décrypté avec succès.")))
        self.config(crypt_dropdown, parent)

        checksums_dropdown = tk.Menu(menubar)
        checksums_dropdown.add_command(label = "Voir les checksums", command = lambda : (print(f"""SELECT :\n{File.hashs(
            parent.get_select())}""")if parent.get_select()else None,print(f"""FILE :\n{File.hashs(parent.textarea.get(1.0,
                tk.END))}""")))
        checksums_dropdown.add_command(label = "Généré un fichier de checksums", command = lambda : (f:=open(
            parent.constante.file_full_name+".hash","w", encoding = "utf-8"),f.write(File.hashs(parent.textarea.get(1.0,tk.END
                ))),f.close(),print("Le fichier a été créé avec succès.")))
        self.config(checksums_dropdown, parent)

        compress_dropdown = tk.Menu(menubar)
        compress_dropdown.add_command(label = "Compresser le fichier", command = lambda : File.compress(parent.constante))
        compress_dropdown.add_command(label = "Décompresser le fichier", command = lambda : (file:=filedialog.askopenfilename(
            defaultextension=".zip").replace("/", "\\"),pwd:=simpledialog.askstring("Mot de passe",
            "Mot de passe (facultatif) : ",show="*"),File.decompress(file,pwd)))
        self.config(compress_dropdown, parent)

        python_dropdown = tk.Menu(menubar)
        python_dropdown.add_command(label = "Compilation du fichier", command = lambda : (py_compile.compile(
            parent.constante.file_full_name,cfile=parent.constante.file_full_name+"c")if re.match(r"^(.*)\.py$",
            parent.constante.file_full_name)else print("Ce fichier n'est pas un fichier Python..."),
            print("Fin de la compilation")))
        python_dropdown.add_command(label = "Script en 1 ligne", command = lambda : (File.script_one_line(
            parent)if re.match(r"^(.*)\.py$", parent.constante.file_full_name)else print(
            "Ce fichier n'est pas un fichier Python..."),print("Fin de la transformation")))
        self.config(python_dropdown, parent)

        encoding_dropdown = tk.Menu(menubar)
        for encoding in parent.constante.config["general"]["encodings"] :
            encoding_dropdown.add_command(label = encoding, command = lambda enc=encoding : (parent.save(),
                parent.read_file([enc])))
        encoding_dropdown.add_command(label = "Hexadecimal", command = lambda : (parent.save(),
                parent.read_file(["hex"])))
        encoding_dropdown.add_command(label = "Liste des encodings",
            command = lambda : [print(alias) for alias, enc in aliases.items()])
        self.config(encoding_dropdown, parent)

        about_dropdown = tk.Menu(menubar)
        about_dropdown.add_command(label = "Version",
                                   command = self.show_release_notes)
        about_dropdown.add_separator()
        about_dropdown.add_command(label = "A propos...",
                                   command = self.show_about_message)
        self.config(about_dropdown, parent)

        menubar.add_cascade(label = "Fichier", menu = file_dropdown)
        menubar.add_cascade(label = "Themes", menu = theme_dropdown)
        menubar.add_cascade(label = "Encoding", menu = encoding_dropdown)
        menubar.add_cascade(label = "Compression", menu = compress_dropdown)
        menubar.add_cascade(label = "Cryptage", menu = crypt_dropdown)
        menubar.add_cascade(label = "Checksums", menu = checksums_dropdown)
        menubar.add_cascade(label = "Script Python", menu = python_dropdown)
        menubar.add_command(label = "Execute", accelerator = "f5")       
        menubar.add_cascade(label = "A propos", menu = about_dropdown)

    def modif_config (self, parent, theme = None) :
        if theme :
            parent.constante.get_color_themes(theme)
        else :
            parent.constante.get_config()
        restart(parent)

    def show_about_message(self):
        box_title = "A propos de SecurityEditor"
        box_message = "Un éditeur de texte avec des options de sécurité,\nécrit en python."
        messagebox.showinfo(box_title, box_message)

    def show_release_notes(self):
        box_title = "Version"
        box_message = "Version 0.1 - SecurityEditor"
        messagebox.showinfo(box_title, box_message)

    def config (self, menu, parent) :
        menu.config(bg = parent.constante.config["color"]["background_interface"], 
            fg = parent.constante.config["color"]["text_interface"], font = parent.constante.config['font']['interface'], 
            tearoff = 0, activebackground = parent.constante.config["color"]["text_interface"], 
            activeforeground = parent.constante.config["color"]["background_interface"])

class Coloration :

    def remove (parent) :
        for name in parent.textarea.tag_names() :
            parent.textarea.tag_remove(name, '1.0', 'end')

    def build_group (name, alternates):
        return "(?P<%s>" % name + "|".join(alternates) + ")"

    def get_hex_syntax () :
        ascii_ = Coloration.build_group("ASCII", 
            [r"[a-zA-Z0-9\"'/?,:;!(){}_&%#$+*~<=|@>^`.-]{16}\n"]
        )
        hexa = Coloration.build_group("HEXA", [r"([\x20][0-9a-f]{2}){16} "])
        separator = Coloration.build_group("SEPARATOR", [r"\|[\x20]"])
        index = Coloration.build_group("INDEX", [r"[0-9a-f]{10}[ ]"])
        return ascii_ + "|" + hexa + "|" + separator + "|" + index

    def get_python_syntax () :
        kw = Coloration.build_group("KEYWORD", keyword.kwlist) + r"\b"
        builtin = Coloration.build_group("BUILTIN", [str(name) for name in dir(__builtins__)]) + r"\b"
        comment = Coloration.build_group("COMMENT", [r"#[^\n]*"])
        return comment + "|" + kw + "|" + builtin

    def default_syntax () :
        stringprefix = r"(\br|u|ur|R|U|UR|Ur|uR|b|B|br|Br|bR|BR|f|fr|FR|F|fR|Fr)?"
        string = Coloration.build_group("STRING", [stringprefix + r"'[^'\\\n]*(\\.[^'\\\n]*)*'?", 
            stringprefix + r'"[^"\\\n]*(\\.[^"\\\n]*)*"?', stringprefix + r"'''[^'\\]*((\\.|'(?!''))[^'\\]*)*(''')?", 
            stringprefix + r'"""[^"\\]*((\\.|"(?!""))[^"\\]*)*(""")?'])
        return Coloration.build_group("SPECIAL", [r"\\[a-z]"]) + "|" + string

    def create_tags (parent, tags) :
        regex = []
        for name, config in tags.items() :
            regex.append(Coloration.build_group(name, config["VALUES"]))
            parent.textarea.tag_config(name, foreground = config["COLOR"], font = config["FONT"])
        return "|".join(regex)

    def make (parent, texte, line = None) :
        extension = path.splitext(parent.constante.file_full_name)[-1]

        tags = parent.constante.config["syntax"].get(extension)
        regex = Coloration.create_tags(parent, tags if tags else {})
        
        if regex :
            regex += "|" + Coloration.default_syntax()
        else :
            regex = Coloration.default_syntax()

        parent.textarea.tag_config("SPECIAL",
            foreground = parent.constante.config["syntax"]["default"]['SPECIAL']['COLOR'],
            font = parent.constante.config["syntax"]["default"]['SPECIAL']['FONT'])
        parent.textarea.tag_config("STRING",
            foreground = parent.constante.config["syntax"]["default"]['STRING']['COLOR'],
            font = parent.constante.config["syntax"]["default"]['STRING']['FONT'])
        parent.textarea.tag_config("FIND",
            foreground = parent.constante.config["syntax"]["default"]['FIND']['COLOR'],
            font = parent.constante.config["syntax"]["default"]['FIND']['FONT'],
            background = parent.constante.config["syntax"]["default"]['FIND']['BACKGROUNDCOLOR'])

        if extension == ".py" or extension == ".pyw" :
            parent.textarea.tag_config("KEYWORD", 
                foreground = parent.constante.config["syntax"]["python_default"]['KEYWORD']['COLOR'],
                font = parent.constante.config["syntax"]["python_default"]['KEYWORD']['FONT'])
            parent.textarea.tag_config("COMMENT", 
                foreground = parent.constante.config["syntax"]["python_default"]['COMMENT']['COLOR'],
                font = parent.constante.config["syntax"]["python_default"]['COMMENT']['FONT'])
            parent.textarea.tag_config("BUILTIN", 
                foreground = parent.constante.config["syntax"]["python_default"]['BUILTIN']['COLOR'],
                font = parent.constante.config["syntax"]["python_default"]['BUILTIN']['FONT'])
            parent.tags = ["KEYWORD", "COMMENT", "BUILTIN", "SYNC", "STRING"]
            regex += r"|" + Coloration.get_python_syntax()

        elif extension == ".hex" :
            parent.textarea.tag_config("ASCII", 
                foreground = parent.constante.config["syntax"]["hex_default"]['ASCII']['COLOR'],
                font = parent.constante.config["syntax"]["hex_default"]['ASCII']['FONT'])
            parent.textarea.tag_config("HEXA", 
                foreground = parent.constante.config["syntax"]["hex_default"]['HEXA']['COLOR'],
                font = parent.constante.config["syntax"]["hex_default"]['HEXA']['FONT'])
            parent.textarea.tag_config("SEPARATOR", 
                foreground = parent.constante.config["syntax"]["hex_default"]['SEPARATOR']['COLOR'],
                font = parent.constante.config["syntax"]["hex_default"]['SEPARATOR']['FONT'])
            parent.textarea.tag_config("INDEX", 
                foreground = parent.constante.config["syntax"]["hex_default"]['INDEX']['COLOR'],
                font = parent.constante.config["syntax"]["hex_default"]['INDEX']['FONT'])
            regex += r"|" + Coloration.get_hex_syntax()

        if line :
            for name in parent.textarea.tag_names() :
                parent.textarea.tag_remove(name, 'insert linestart', 'insert lineend')

        Coloration.find_regex(regex, texte, parent, line = line)

    def get_position (debut, fin, string, line) :
        if not line :
            ligne = string[:debut].count('\n') + 1
            colonne = len(string[:debut].split('\n')[ligne - 1])
            debut = f"{ligne}.{colonne}"
            ligne = string[:fin].count('\n') + 1
            colonne = len(string[:fin].split('\n')[ligne - 1])
            fin = f"{ligne}.{colonne}"
        else :
            ligne = int(line)
            colonne = len(string[:debut])
            debut = f"{ligne}.{colonne}"
            colonne = len(string[:fin])
            fin = f"{ligne}.{colonne}"
        return debut, fin

    def find (parent, texte, string, casse, regex) :
        if regex :
            regex = string
        elif casse :
            regex = "[" + "][".join(list(string.upper())) + "]"
            texte = texte.upper()
        else :
            regex = "[" + "][".join(list(string)) + "]"
        regex = Coloration.build_group("FIND",[regex])
        Coloration.find_regex(regex, texte, parent)

    def find_regex (regex, texte, parent, line = None) :
        regex_object = re.compile(regex, re.S)
        for tag in regex_object.finditer(texte) :
            debut, fin = Coloration.get_position(tag.start(), tag.end(), texte, line)
            for key, value in tag.groupdict().items() :
                if value :
                    parent.textarea.tag_add(key, debut, fin)
                    break

    # parent.textarea.tag_add("a", "1.0", "2.3") #un tag "a" commence au car 0 de la ligne 1 et fini car 3 de la ligne 2
    # parent.textarea.tag_config("a", background = "yellow", foreground = "red", font = ("arial", 10, "italic"))

class Statusbar:

    def __init__(self, parent):

        self.label = tk.Label(parent.master, text = "SecurityEditor - 0.1 SecurityEditor", 
            bg = parent.constante.config["color"]["background_interface"], 
            fg = parent.constante.config["color"]["text_interface"], font = parent.constante.config['font']['interface'])
        self.label.grid(row = 1, column = 0, pady = 0, padx = 0)

    def update_status(self, etat = None) :
        if isinstance(etat, bool) :
            self.label['text'] = "Le fichier est bien sauvegarder."
        else :
            self.label['text'] = "SecurityEditor - 0.1 SecurityEditor"

class Notifications (object) :

    def __init__ (self, master, config) :
        self.window = tk.Toplevel(master = master)
        self.window.title("Notification")
        self.window.geometry("300x200+650+450")
        try :
            self.window.iconbitmap(r'.\icon\icon.ico')
        except :
            pass

        self.window.protocol("WM_DELETE_WINDOW", self.clean)

        self.text = tk.Text(self.window, font = config['font']['normal'], bg = config["color"]["background_text"], 
            fg = config["color"]["text_normal"], cursor = "pencil", highlightbackground = config["color"]["background_text"], 
            insertbackground = config["color"]["text_normal"], selectbackground = config["color"]["text_normal"], 
            selectforeground = config["color"]["background_text"])
        self.text.pack(expand = 1)

        self.scroll = tk.Scrollbar(self.window, command = self.text.yview)
        self.text.configure(yscrollcommand = self.scroll.set)
        self.text.pack(side = tk.LEFT, fill = tk.BOTH, expand = 1)
        self.scroll.pack(side = tk.RIGHT, fill = tk.Y)

    def clean (self) :
        self.text.config(state = tk.NORMAL)
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, "***! SecurityEditor !***\n\n")
        self.text.config(state = tk.DISABLED)

    def flush (self) :
        pass

    def write (self, texte) :
        self.text.config(state = tk.NORMAL)
        self.text.insert(tk.END, texte)
        self.text.config(state = tk.DISABLED)

class File :

    def XOR (texte, key) :
        key = key.encode()
        cryptage_ = ""
        compteur = 0
        for car in texte :
            cryptage_ += chr(car ^ key[compteur % len(key)])
            compteur += 1
        return cryptage_.encode()

    def hashs (texte) :
        texte = texte.encode()
        return f"""MD5 : {md5(texte).hexdigest()}\nSHA1 : {sha1(texte).hexdigest()}\nSHA256 : {sha256(texte).hexdigest()
        }\nSHA384 : {sha384(texte).hexdigest()}\nSHA512 : {sha512(texte).hexdigest()}"""

    def script_one_line (parent) :
        code = parent.textarea.get(1.0, tk.END)
        file = open(parent.constante.file_full_name[:-3] + "_oneline.py", "w")
        file.write(f"from base64 import b64decode;exec(b64decode({b64encode(code.encode())}))")
        file.close()

    def decompress (file, password = None) :
        if is_zipfile(file) :
            try :
                fileinfo = ZipInfo.from_file(file)
                filetype = fileinfo.compress_type
            except Exception as e :
                filetype = 0
                print(e)
            try :
                ZipFile(file, compression = filetype).extractall(pwd = password.encode())
                print("Le fichier à été extrait avec succès !")
                print("Vous pouvez ouvrir le fichier souhaitez avec le raccourci Ctrl-C ou Menu->Fichier->Ouvrir.")
            except :
                print("Ce mot de passe ne correspond pas.")
        elif is_tarfile(file) :
            try :
                fileinfo = TarInfo.from_file(file)
                filetype = fileinfo.compress_type
            except Exception as e :
                filetype = 0
                print(e)
            try :
                TarFile(file, tarinfo = TarInfo).extractall(pwd = password.encoded())
                print("Le fichier à été extrait avec succès !")
                print("Vous pouvez ouvrir le fichier souhaitez avec le raccourci Ctrl-C ou Menu->Fichier->Ouvrir.")
            except :
                print("Ce mot de passe ne correspond pas.")
        else :
            print("Ce fichier n'est nis un fichier tar ni un fichier zip.")

    def compress (constante) :
        with ZipFile(constante.file_full_name + ".zip", mode = "w") as compress_file :
            compress_file.write(constante.file_full_name, constante.file_name)
        print("Votre fichier est compressé : " + constante.file_full_name + ".zip")

    def get_printable (ligne, index) :
        ligne_hex = ""
        ligne_decrypt = ""
        visibles = string.ascii_letters+string.digits+"\\\"'/.\\?,:;!\\(\\)\\{\\}_-&%#\\$\\+\\*~\\<=\\|@\\>\\^`"

        for car in ligne :
            car_hex = hex(car)[2:]
            ascii_car = chr(car)
            if ascii_car in visibles :
                ligne_decrypt += ascii_car
            else :
                ligne_decrypt += "."
            if len(car_hex) != 2 :
                ligne_hex += "0"
            ligne_hex += f"{car_hex} " 

        index_hex = hex(index)[2:]
        index_printable = "0" * (10 - len(index_hex)) + index_hex

        return ligne_hex, ligne_decrypt, index_printable

class Editor :

    def __init__(self, master, constante) :
        self.constante = constante
        self.encoding = constante.config["general"]["encodings"][0]

        master.title(f"{constante.file_full_name} - SecurityEditor")
        master["bg"] = constante.config["color"]["background_interface"]
        master.geometry("900x600+50+50")
        tk.Grid.rowconfigure(master, 0, weight = 1)
        tk.Grid.columnconfigure(master, 0, weight = 1)
        try :
            master.iconbitmap(r'.\icon\icon.ico')
        except :
            pass

        self.master = master

        self.textarea = tk.Text(master, font = constante.config['font']['normal'], 
            bg = constante.config["color"]["background_text"], 
            fg = constante.config["color"]["text_normal"], cursor = "pencil",
            highlightbackground = constante.config["color"]["background_text"], 
            insertbackground = constante.config["color"]["text_normal"],
            selectbackground = constante.config["color"]["text_normal"], 
            selectforeground = constante.config["color"]["background_text"])
        self.scroll = tk.Scrollbar(master, command = self.textarea.yview)
        self.textarea.configure(yscrollcommand = self.scroll.set)
        self.textarea.grid(row = 0, column = 0, sticky = tk.N + tk.S + tk.E + tk.W)
        self.scroll.grid(row = 0, column = 1, sticky = tk.N + tk.S + tk.E + tk.W)

        self.menubar = Menubar(self)
        self.statusbar = Statusbar(self)

        master.after(30000, self.check_save)
        master.protocol("WM_DELETE_WINDOW", self.exit)

        self.filetypes = [("All Files", "*.*"),
                       ("Text Files", "*.txt"),
                       ("Python Scripts", "*.py"),
                       ("Php Code", "*.php"),
                       ("Markdown Documents", "*.md"),
                       ("JavaScript Files", "*.js"),
                       ("HTML Documents", "*.html"),
                       ("CSS Documents", "*.css")]
        self.last_save = 0
        self.bind_shortcuts()

    def check_save (self) :
        if time() - self.last_save >= 300 :
            self.save()
        self.master.after(480000, self.check_save)

    def save_to_quit (self) :
        if len(self.textarea.get("1.0", tk.END)) > 1 :
            if messagebox.askyesno("Sauvegarde", "Voulez vous sauvegarder votre fichier ?") :
                if self.constante.default_filename in self.constante.file_full_name :
                    self.save_as()
                else :
                    self.save()
            elif path.isfile(self.constante.file_full_name) and path.join(
                self.constante.editor_dir, "files", "Untitle") in self.constante.file_full_name :
                remove(self.constante.file_full_name)

    def exit (self) :
        self.save()
        self.constante.add_reopen_file()
        sys.stdout.window.destroy()
        self.master.destroy()

    def new_file(self, *args):
        self.save_to_quit()
        self.textarea.delete(1.0, tk.END)
        
        self.encoding = "utf-8"
        print("Encoding : utf-8")
        self.constante.default_name()
        self.master.title(self.constante.file_full_name + " - SecurityEditor")

    def find (self, *args) :
        window = tk.Toplevel(master = self.master)
        window.title("Find...")
        window["background"] = self.constante.config["color"]["background_interface"]
        try :
            window.iconbitmap(r'.\icon\icon.ico')
        except :
            pass

        text = tk.Entry(window, font = self.constante.config['font']['interface'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"], 
            cursor = "pencil", highlightbackground = self.constante.config["color"]["background_interface"], 
            insertbackground = self.constante.config["color"]["text_interface"], 
            selectbackground = self.constante.config["color"]["text_interface"], 
            selectforeground = self.constante.config["color"]["background_interface"])
        text.grid(row = 0, column = 0, pady = 10, padx = 10)
        text.insert(0, self.get_select())

        frame = tk.Frame(window, bg = self.constante.config["color"]["background_interface"])
        frame.grid(row = 1, column = 0, pady = 10, padx = 10)

        casse = tk.IntVar()
        casse.set(1)
        regex = tk.IntVar()
        regex.set(0)
        check_casse = tk.Checkbutton(frame, text = "Ne pas respecter la casse", onvalue = 1, offvalue = 0,
            var = casse, bg = self.constante.config["color"]["background_interface"], 
            fg = self.constante.config["color"]["text_interface"], 
            activebackground = self.constante.config["color"]["background_interface"],
            highlightbackground = self.constante.config["color"]["background_interface"],
            highlightcolor = self.constante.config["color"]["text_interface"],
            activeforeground = self.constante.config["color"]["text_interface"],
            selectcolor = self.constante.config["color"]["background_interface"])
        check_regex = tk.Checkbutton(frame, text = "Expression Régulière", onvalue = 1, offvalue = 0,
            var = regex, bg = self.constante.config["color"]["background_interface"], 
            fg = self.constante.config["color"]["text_interface"], 
            activebackground = self.constante.config["color"]["background_interface"],
            highlightbackground = self.constante.config["color"]["background_interface"],
            highlightcolor = self.constante.config["color"]["text_interface"],
            activeforeground = self.constante.config["color"]["text_interface"],
            selectcolor = self.constante.config["color"]["background_interface"])
        find = tk.Button(frame, text = "Rechercher", font = self.constante.config['font']['interface'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"],
            command = lambda : Coloration.find(self, self.textarea.get(1.0, tk.END), text.get(), casse.get(), regex.get()))
        find.grid(row = 0, column = 0, pady = 10, padx = 10)
        delete = tk.Button(frame, text = "Supprimer la recherche", font = self.constante.config['font']['interface'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"],
            command = lambda : self.textarea.tag_remove("FIND", '1.0', 'end'))
        delete.grid(row = 0, column = 1)
        check_casse.grid(row = 1, column = 0, pady = 10, padx = 10)
        check_regex.grid(row = 1, column = 1, pady = 10, padx = 10)

        label = tk.Label(frame, text = "Remplacez tous par :", font = self.constante.config['font']['interface'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"])
        label.grid(row = 2, column = 0, pady = 10, padx = 10)
        entry = tk.Entry(frame, font = self.constante.config['font']['normal'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"], 
            cursor = "pencil", highlightbackground = self.constante.config["color"]["background_interface"], 
            insertbackground = self.constante.config["color"]["text_interface"], 
            selectbackground = self.constante.config["color"]["text_interface"], 
            selectforeground = self.constante.config["color"]["background_interface"])
        entry.grid(row = 2, column = 1, pady = 10, padx = 10)
        replace = tk.Button(window, text = "Remplacez", font = self.constante.config['font']['normal'], 
            bg = self.constante.config["color"]["background_interface"], fg = self.constante.config["color"]["text_interface"],
            command = lambda : (code:=self.textarea.get(1.0,tk.END).replace(text.get(),entry.get()),
            self.textarea.delete(1.0,tk.END),self.textarea.insert(1.0,code),Coloration.make(self,self.textarea.get(1.0,tk.END))))
        replace.grid(row = 2, column = 0, pady = 10, padx = 10)

    def read_file (self, encodings) :
        self.textarea.delete(1.0, tk.END)
        opened = False
        if encodings != ["hex"] :
            for encoding in encodings :
                try :    
                    with codecs.open(self.constante.file_full_name, "r", encoding = encoding) as f:
                        self.textarea.insert(1.0, f.read())
                except :
                    continue
                else :
                    opened = True
                    self.encoding = encoding
                    print("Ouvert avec l'encoding : " + encoding)
                    break
        if not opened :
            self.encoding = "utf-8"
            self.hexa_reader()
        self.master.title(self.constante.file_full_name + " - SecurityEditor")
        Coloration.make(self, self.textarea.get(1.0, tk.END))

    def hexa_reader (self) :
        file = open(self.constante.file_full_name, "rb")
        data = file.read()
        file.close()

        self.constante.file_full_name += ".hex"
        index = 0
        while len(data) >= 16 :
            ligne = list(data[:16])
            ligne_hex, ligne_decrypt, index_printable = File.get_printable(ligne, index)
            self.textarea.insert(tk.END, f'{index_printable} |  {ligne_hex} | {ligne_decrypt}\n')
            data = data[16:]
            index += 1
        ligne = data + b"\x00" * (16 - len(data))
        ligne_hex, ligne_decrypt, index_printable = File.get_printable(ligne, index)
        self.textarea.insert(tk.END, f'{index_printable} |  {ligne_hex} | {ligne_decrypt}\n')

    def ask_file(self, *args):
        file = filedialog.askopenfilename(
            defaultextension = ".py",
            filetypes = self.filetypes).replace("/", "\\")
        self.open_file(file)

    def open_file (self, file) :
        file = file.replace("/", "\\")
        print(file)
        self.save_to_quit()

        if path.isfile(file) :
            self.textarea.delete(1.0, tk.END)
            self.constante.file_full_name = file
            self.read_file(self.constante.config["general"]["encodings"])
        else :
            print("Cela ne semble pas être un fichier...")
    
    def save(self, *args) :
        if self.constante.file_full_name :
            self.write_file(False)
        else :
            self.save_as()

    def write_file (self, force) :
        if len(self.textarea.get(1.0, tk.END)) > 1 or force :
            try :
                with codecs.open(self.constante.file_full_name, "w", encoding = self.encoding) as f :
                    f.write(self.textarea.get(1.0, tk.END))
                self.statusbar.update_status(True)
            except Exception as e :
                print(e)

    def save_as(self, *args) :
        self.constante.file_full_name = filedialog.asksaveasfilename(
            initialfile = "Untitle.py",
            defaultextension = ".py",
            filetypes = self.filetypes).replace("/", "\\")

        self.write_file(True)
        self.master.title(self.constante.file_full_name + " - SecurityEditor")
        Coloration.make(self, self.textarea.get(1.0, tk.END))
        self.constante.add_reopen_file()

    def update (self, *args) :
        self.statusbar.update_status
        Coloration.make(self, self.textarea.get("insert linestart", "insert lineend"), 
            line = self.textarea.index("insert").split(".")[0])

    def bind_shortcuts(self) :
        self.textarea.bind('<Control-n>', self.new_file)
        self.textarea.bind('<Control-o>', self.open_file)
        self.textarea.bind('<Control-s>', self.save)
        self.textarea.bind('<Control-S>', self.save_as)
        self.textarea.bind('<Control-i>', self.get_info)
        self.textarea.bind('<Control-f>', self.find)
        self.textarea.bind('<Key>', self.update)
        self.master.bind('<F5>', lambda event : Execution(self))

    def get_info (self, *args) :
        print("INFORMATIONS : ")
        print("\tNom du fichier : " + self.constante.file_full_name)
        print(f"\tNombre de caractères : {len(self.textarea.get(1.0, tk.END)) - 1}")
        lignes = self.textarea.get(1.0, tk.END).split('\n')
        print(f"\tNombre de lignes : {len(lignes) - 1}")
        selection = len(self.get_select())
        print(f"\tNombre de caractères surlignés : {selection}")
        print(f"Encoding : {self.encoding}")

    def get_select (self) :
        try :
            return self.textarea.selection_get()
        except :
            return ""

class Execution :

    def __init__ (self, parent) :
        self.stdout = ""
        self.stderr = ""
        self.thread = Thread(target = self.execution)
        self.commande = parent.constante.config["execution"].get(path.splitext(parent.constante.file_full_name)[-1]
            ) + [parent.constante.file_full_name]
        self.thread.start()

    def execution (self) :
        Popen(self.commande, shell = True).communicate()

def restart (master) :
    master.exit()
    start(master.constante, True)

def start (constante, opened) :
    master = tk.Tk()
    editor = Editor(master, constante)
    sys.stdout = Notifications(master, constante.config)
    sys.stderr = sys.stdout
    print("*! Bienvenu sur SecurityEditor !*\n")
    if opened :
        editor.ask_file()
    master.mainloop()

if __name__ == "__main__" :
    try :
        constante = Constante()
        start(constante, False)
    except Exception as e :
        sys.stdout = sys.__stdout__
        sys.exit(e)



