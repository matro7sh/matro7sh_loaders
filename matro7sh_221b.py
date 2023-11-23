#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: @jenaye_fr
# Created on: Mon, 17. Nov 2023
# Description: matro7sh 221b Loader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create matro7sh Tab


import os
import shutil
import havoc  # type: ignore
import havocui  # type: ignore
from datetime import datetime

# Configuration
LOADER_PATH = shutil.which("baker")
BAKER_ENCRYPT_TECHNIQUES = ["xor", "chacha20", "aes"]

# Variables & Defaults
baker_shellcode_path = ""
baker_shellcode_encryption_key = ""
baker_shellcode_encryption_kind = "xor"

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
log = havocui.Logger("matro7sh baker Log")


def change_shellcode_encrypt_method(num):
    global baker_shellcode_encryption_kind
    if num:
        baker_shellcode_encryption_kind = BAKER_ENCRYPT_TECHNIQUES[num - 1]
    else:
        baker_shellcode_encryption_kind = "CRT"
    print("[*] Shellcode execution method changed: ", baker_shellcode_encryption_kind)


def change_default_key_baker(k):
    global baker_shellcode_encryption_key
    baker_shellcode_encryption_key = k
    print("[*] Key changed: ", baker_shellcode_encryption_key)


def change_shellcode_path():
    global baker_shellcode_path
    global label_to_replace

    baker_shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", baker_shellcode_path, ".")

    formatted_shellcode_path = f"<span style=\"color:{HAVOC_SUCCESS};\">{baker_shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if baker_shellcode_path != " " else f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>"


# Generate payload
def run():
    def get_build_command() -> str:
        global baker_shellcode_path
        global baker_shellcode_encryption_key
        global baker_shellcode_encryption_kind

        base_cmd = f'{LOADER_PATH} bake'
        if baker_shellcode_path != "":
            base_cmd = f'{base_cmd} --shellPath {baker_shellcode_path}'

        if baker_shellcode_encryption_kind != "":
            base_cmd = f'{base_cmd} --method {baker_shellcode_encryption_kind}'

        if baker_shellcode_encryption_key != "":
            base_cmd = f'{base_cmd} --key {baker_shellcode_encryption_key}'

        base_cmd = f'{base_cmd} --output /tmp/baker.exe'
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
            f"<b style=\"color:{HAVOC_SUCCESS};\">Payload generated successfully at /tmp/baker.exe using baker loader. Happy pwn</b>")
        log.setBottomTab()

    log.setBottomTab()
    log.addText(
        f"<b style=\"color:{HAVOC_DARK};\">───────────────────────────────────────── running baker ─────────────────────────────────────────</b>")
    log.addText(f"<b style=\"color:{HAVOC_COMMENT};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")

    global baker_shellcode_path
    if baker_shellcode_path == "":
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
    dialog.addLabel(f"<b>──────────────────────────── Required Settings for 221b ─────────────────────────────</b>")
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)

    dialog.addLabel("<b>[*] Shellcode encryption method</b>")
    dialog.addCombobox(change_shellcode_encrypt_method, "CRT", *BAKER_ENCRYPT_TECHNIQUES)

    dialog.addLabel("<b>[*] Encryption key (Default: random)</b>")
    dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", change_default_key_baker)

    dialog.addButton("Generate", run)
    dialog.exec()
