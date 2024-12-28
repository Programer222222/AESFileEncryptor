import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import os
from PIL import Image, ImageTk
import webbrowser  # To open the PayPal link in the browser
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function to open the PayPal donation page
def open_donation_page():
    webbrowser.open("https://www.paypal.me/ARansome63")  # Use your PayPal link

# Function to select a file
def select_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)

# Function to select a folder
def select_folder():
    folder_path = filedialog.askdirectory(title="Select a Folder")
    entry_folder_path.delete(0, tk.END)
    entry_folder_path.insert(0, folder_path)

# Function to hide a file/folder (Windows-specific)
def hide_file(file_path):
    try:
        os.system(f'attrib +h "{file_path}"')  # Set file/folder as hidden on Windows
    except Exception as e:
        print(f"Error hiding file: {e}")

# Function to unhide a file/folder (Windows-specific)
def unhide_file(file_path):
    try:
        os.system(f'attrib -h "{file_path}"')  # Unhide file/folder
    except Exception as e:
        print(f"Error unhiding file: {e}")

# Function to list all hidden files in a folder
def list_hidden_files(folder_path):
    hidden_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.system(f'attrib "{file_path}"') & 0x2:  # Check if file is hidden
                hidden_files.append(file_path)
    return hidden_files

# Encryption and Decryption Methods
def encrypt_file(file_path, password):
    try:
        cipher = AES.new(pad(password.encode(), AES.block_size), AES.MODE_CBC)
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f_enc:
            f_enc.write(cipher.iv)  # Store the initialization vector at the beginning
            f_enc.write(encrypted_data)

        hide_file(file_path)  # Hide the original file
        return encrypted_file_path

    except PermissionError:
        print(f"Permission error: Unable to access or write to {file_path}. Please check file permissions.")
        return None
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(16)  # First 16 bytes are the IV
            encrypted_data = f.read()

        cipher = AES.new(pad(password.encode(), AES.block_size), AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Decrypting file path
        decrypted_file_path = file_path.replace(".enc", "_decrypted")

        # Check if the decrypted file exists and remove it
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)

        # Write decrypted data to file
        with open(decrypted_file_path, 'wb') as f_dec:
            f_dec.write(decrypted_data)

        unhide_file(file_path)  # Unhide the original file
        return decrypted_file_path

    except PermissionError as e:
        print(f"Permission Error: Unable to write to the file. Please check file permissions for {file_path}")
    except Exception as e:
        print(f"Error during decryption: {e}")

# Folder Lock/Unlock
def lock_folder(folder_path, password, update_progress):
    folder_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)]
    encrypted_files = []

    for idx, file in enumerate(folder_files):
        if os.path.isfile(file):
            encrypted_file = encrypt_file(file, password)
            encrypted_files.append(encrypted_file)

            # Update progress bar after encrypting each file
            progress = (idx + 1) / len(folder_files) * 100
            update_progress(progress)

    # Hide the folder as well
    hide_file(folder_path)

    # Update progress to 100%
    update_progress(100)
    return encrypted_files

def unlock_folder(folder_path, password, update_progress):
    encrypted_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".enc")]
    decrypted_files = []

    for idx, enc_file in enumerate(encrypted_files):
        decrypted_file = decrypt_file(enc_file, password)
        decrypted_files.append(decrypted_file)

        # Update progress bar after decrypting each file
        progress = (idx + 1) / len(encrypted_files) * 100
        update_progress(progress)

    # Unhide the folder itself
    unhide_file(folder_path)

    # Update progress to 100%
    update_progress(100)
    return decrypted_files

# Function to update progress bar
def update_progress(value):
    progress_var.set(value)

# Display the disclaimer message box when the program starts
def show_disclaimer():
    disclaimer_message = (
        "By using this program, you acknowledge that the creator of this software, Andrew Ransome, "
        "is not responsible for any data loss, corruption, or other damages resulting from the use of this software. "
        "Please ensure you have backups of important files before proceeding."
    )
    return messagebox.askyesno("Disclaimer", disclaimer_message)

# Main window setup
root = tk.Tk()
root.title("File/Folder Encrypter AES")
root.geometry("600x400")
root.configure(bg="#2a2a2a")

# Show the disclaimer when the program starts
if not show_disclaimer():
    root.quit()  # Exit if user does not agree to the terms

# Background Image
background_image_path = r"E:\py\Encrypter AES\1961b26a-a7cb-43ff-bf33-50f7d1f23d97.jpeg"
bg_image = Image.open(background_image_path)
bg_image = bg_image.resize((600, 400), Image.Resampling.LANCZOS)
bg_image_tk = ImageTk.PhotoImage(bg_image)

canvas = tk.Canvas(root, width=600, height=400)
canvas.pack(fill="both", expand=True)

canvas.create_image(0, 0, image=bg_image_tk, anchor="nw")

# File Path Input
entry_file_path = tk.Entry(root, width=50)
entry_file_path.place(x=80, y=40)

btn_select_file = tk.Button(root, text="Select File", command=select_file)
btn_select_file.place(x=80, y=70)

# Folder Path Input
entry_folder_path = tk.Entry(root, width=50)
entry_folder_path.place(x=80, y=120)

btn_select_folder = tk.Button(root, text="Select Folder", command=select_folder)
btn_select_folder.place(x=80, y=150)

# Password Input
entry_password = tk.Entry(root, show="*", width=50)
entry_password.place(x=80, y=180)

# Progress Bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=300)
progress_bar.place(x=80, y=200)

# Lock/Unlock Buttons
def encrypt_file_with_password():
    password = entry_password.get()
    if password:
        encrypt_file(entry_file_path.get(), password)
    else:
        print("Password is required")

def decrypt_file_with_password():
    password = entry_password.get()
    if password:
        decrypt_file(entry_file_path.get() + ".enc", password)
    else:
        print("Password is required")

btn_lock_file = tk.Button(root, text="Lock File", command=encrypt_file_with_password)
btn_lock_file.place(x=80, y=250)

btn_unlock_file = tk.Button(root, text="Unlock File", command=decrypt_file_with_password)
btn_unlock_file.place(x=200, y=250)

btn_lock_folder = tk.Button(root, text="Lock Folder", command=lambda: lock_folder(entry_folder_path.get(), entry_password.get(), update_progress))
btn_lock_folder.place(x=80, y=280)

btn_unlock_folder = tk.Button(root, text="Unlock Folder", command=lambda: unlock_folder(entry_folder_path.get(), entry_password.get(), update_progress))
btn_unlock_folder.place(x=200, y=280)

# Hidden Files Manager
def show_hidden_files():
    folder_path = entry_folder_path.get()
    hidden_files = list_hidden_files(folder_path)
    hidden_files_list.delete(0, tk.END)
    for file in hidden_files:
        hidden_files_list.insert(tk.END, file)

# List Box to display hidden files
hidden_files_list = tk.Listbox(root, height=5, width=50)
hidden_files_list.place(x=80, y=320)

btn_show_hidden = tk.Button(root, text="Show Hidden Files", command=show_hidden_files)
btn_show_hidden.place(x=200, y=320)

# Donation Button
btn_donate = tk.Button(root, text="Donate", command=open_donation_page, bg="#28a745", fg="white")
btn_donate.place(x=400, y=350)

# Copyright Label
copyright_label = tk.Label(root, text="Andrew Ransome 2024 ©", fg="white", bg="#2a2a2a")
copyright_label.place(x=220, y=370)

# Start the Application
root.mainloop()
