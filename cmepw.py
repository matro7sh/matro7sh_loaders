#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: @jenaye_fr
# Created on: Mon, 17. Nov 2023
# Description: CMEPW Loader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create CMEPW Tab

import os, sys, subprocess
import threading
import havoc
import havocui
from datetime import datetime

# Configuration
loader_path = "/media/jenaye/data/tools/221b"
loader_path_myph = "/media/jenaye/data/tools/myph"
payload_file_path = "/tmp/payload.bin"

myph_key = ""
baker_key = ""

# Variables & Defaults
shellcode_path = ""

# Colors
havoc_error = "#ff5555" # Red
havoc_success = "#50fa7b" # Green
havoc_comment = "#6272a4" # Greyish blue
havoc_dark = "#555766" # Dark Grey
havoc_info = "#8be9fd" # Cyan
havoc_warning = "#ffb86c" # Orange

if not os.path.exists(loader_path):
    print("[-] Loader not found in: ", loader_path)
    havocui.messagebox("Loader not found in: ", loader_path)
os.chdir(loader_path)

# Create dialog and log widget
dialog = havocui.Dialog("CMEPW Payload Generator", True, 670, 300)
log = havocui.Logger("CMEPW Log")


label_to_replace = f"<b style=\"color:{havoc_error};\">No shellcode selected.</b>"

def change_default_key(k):
    global myph_key
    myph_key = k
    print("[*] Key changed: ", myph_key)


def change_default_key_baker(k):
    global baker_key
    baker_key = k
    print("[*] Key changed: ", baker_key)


def change_shellcode_path():
    global shellcode_path
    global label_to_replace
    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path, ".")
    formatted_shellcode_path = f"<span style=\"color:{havoc_success};\">{shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if shellcode_path != " " else f"<b style=\"color:{havoc_error};\">No shellcode selected.</b>"

# Execute 221b loader and get output
def execute(file):
    log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] Selecting output file path.")

    if baker_key == "":
        log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] No AES key provide it will be this one : '0123456789ABCDEF1123345611111111'")
        os.system(f'{loader_path}/221b bake -m aes -k "0123456789ABCDEF1123345611111111" -s {shellcode_path} -o /tmp/bake.exe')
        print(f'{loader_path}/myph -s {shellcode_path} --out /tmp/myph.exe"')
    else:
        os.system(f'{loader_path}/221b bake -m aes -k {baker_key} -s {shellcode_path} -o /tmp/bake.exe')
        print(f'{loader_path}/myph -k {baker_key} -s {shellcode_path} --out /tmp/bake.exe')


    # Create Log
    log.addText(f"this command has been be executed :  {loader_path}/221b bake -m aes -k '0123456789ABCDEF1123345611111111' -s {shellcode_path} -o /tmp/bake.exe')")
    log.addText(f"<b style=\"color:{havoc_success};\">Payload generated successfully at /tmp/bake.exe using 221b loader. Happy pwn</b>")
    log.setBottomTab()


def execute_myph(file):

    log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] Selecting output file path.")

    if myph_key == "":
        log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] No AES key provide it will be random one.")
        os.system(f'{loader_path_myph}/myph -s {shellcode_path} --out /tmp/myph.exe')
        print(f'{loader_path_myph}/myph -s {shellcode_path} --out /tmp/myph.exe"')
    else:
        os.system(f'{loader_path_myph}/myph -k {myph_key} -s {shellcode_path} --out /tmp/myph.exe')
        print(f'{loader_path_myph}/myph -k {myph_key} -s {shellcode_path} --out /tmp/myph.exe')
    # give the user the option of choosing the key

    # Create Log
    log.addText(f"this command has been be executed :  {loader_path_myph}/myph -s {shellcode_path} -o /tmp/myph.exe)")
    log.addText(f"check client log to see the AES key")
    log.addText(f"<b style=\"color:{havoc_success};\">Payload generated successfully at /tmp/myph.exe using myph loader. Happy pwn</b>")
    log.setBottomTab()


# Generate payload
def run():
    log.setBottomTab()
    log.addText(f"<b style=\"color:{havoc_dark};\">───────────── running 221b ──────────────────</b>")
    log.addText(f"<b style=\"color:{havoc_comment};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")


    if shellcode_path == "":
        havocui.messagebox("Error", "Please specify a valid shellcode path.")
        log.addText(f"[<span style=\"color:{havoc_error};\">-</span>] No shellcode file specified.")
        return
    execute(shellcode_path)

    dialog.close()


def run_myph():
    log.setBottomTab()
    log.addText(f"<b style=\"color:{havoc_dark};\">───────────── running myph ──────────────────</b>")
    log.addText(f"<b style=\"color:{havoc_comment};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")


    if shellcode_path == "":
        havocui.messagebox("Error", "Please specify a valid shellcode path.")
        log.addText(f"[<span style=\"color:{havoc_error};\">-</span>] No shellcode file specified.")
        return
    execute_myph(shellcode_path)

    dialog.close()


def build():
    dialog.clear()

    # Get Listeners
    global listeners
    listeners = havoc.GetListeners()

    # Build Dialog
    dialog.addLabel(f"<b>──────────────────────────── Required Settings for 221 b ────────────────────────────</b>")
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)
    dialog.addLabel("<b>[*] AES key (Default: '0123456789ABCDEF1123345611111111')</b>")
    dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", change_default_key_baker)
    dialog.addButton("Generate", run)
    dialog.exec()



def build_myph():
    dialog.clear()

    # Get Listeners
    global listeners
    listeners = havoc.GetListeners()

    # Build Dialog
    dialog.addLabel(f"<b>──────────────────────────── Required Settings for Myph ─────────────────────────────</b>")
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)
    dialog.addLabel("<b>[*] AES key (Default: random)</b>")
    dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", change_default_key)
    dialog.addButton("Generate", run_myph)
    dialog.exec()

def loader_generator():
    build()

def loader_myph_generator():
    build_myph()


# Create Tab
havocui.createtab("CMEPW", "221b loader", loader_generator, "myph loader", loader_myph_generator)
