from tkinter import *
from simplecrypt import encrypt, decrypt
from tkinter import filedialog
import hashlib 
import os

root = Tk()
root.geometry("400x250")


hex_string = ''

def startDecryption():
    global file_name_entry
    global decryption_text_data
    root.destroy()
 
    decryption_window = Tk()
    decryption_window.geometry("600x500")
    
    decryption_text_data = Text(decryption_window, height=20, width=72)
    decryption_text_data.place(relx=0.5,rely=0.35, anchor=CENTER)
    
    btn_open_file = Button(decryption_window, text="Choose File..", font = 'arial 13',command = dert)
    btn_open_file.place(relx=0.5,rely=0.8, anchor=CENTER)
    
    decryption_window.mainloop()
    
    
def startEncryption():
    global file_name_entry
    global encryption_text_data
    
    root.destroy()
 
    encryption_window = Tk()
    encryption_window.geometry("600x500")
    
    file_name_label = Label(encryption_window, text="File Name: " , font = 'arial 13')
    file_name_label.place(relx=0.1,rely=0.15, anchor=CENTER)
    
    file_name_entry = Entry(encryption_window, font = 'arial 15')
    file_name_entry.place(relx=0.38,rely=0.15, anchor=CENTER)
    
    btn_create = Button(encryption_window, text="Create", font = 'arial 13',command = hexcodeac)
    btn_create.place(relx=0.75,rely=0.15, anchor=CENTER)
    
    encryption_text_data = Text(encryption_window, height=20, width=72)
    encryption_text_data.place(relx=0.5,rely=0.55, anchor=CENTER)
    
    btn_decrypt = Button(encryption_window, text="Decrypt", font = 'arial 13',command = dert)
    btn_decrypt.place(relx=0.5,rely=0.7, anchor=CENTER)
    
    encryption_window.mainloop()
    
    
    
def hexcodeac():
    global hex_string
    message = encryption_text_data.get("1.0",END)
    cyphercode = encrypt('AIM',message)
    hex_string = cyphercode.hex()
    print("Encrypted : " ,hex_string)
    
def dert():
    global hex_string
    byte_str = bytes.fromhex(hex_string)
    original = decrypt('AIM', byte_str)
    final_message  = original.decode("utf-8")        
    print("Decrypt: ",final_message)
    
heading_label = Label(root, text="Encryption & Decryption" , font = 'arial 18 italic')
heading_label.place(relx=0.5,rely=0.2, anchor=CENTER)

btn_start_encryption = Button(root, text="Start Encryption" , font = 'arial 13' , command=startEncryption)
btn_start_encryption.place(relx=0.3,rely=0.6, anchor=CENTER)

btn_start_decryption = Button(root, text="Start Decryption" , font = 'arial 13' ,  command=startDecryption)
btn_start_decryption.place(relx=0.7,rely=0.6, anchor=CENTER)

root.mainloop()

