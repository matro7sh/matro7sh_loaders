#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: @jenaye_fr (refactored by @djnn1337 <3)
# Created on: Mon, 17. Nov 2023
# Description: CMEPW Loader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create CMEPW Tab


from datetime import datetime
import os
import shutil

import havoc  # type: ignore
import havocui  # type: ignore

# constants
HAVOC_ERROR = "#FF5555" # RED
HAVOC_SUCCESS = "#50FA7B" # GREEN
HAVOC_COMMENT = "#6272A4" # GREYISH BLUE
HAVOC_DARK = "#555766" # DARK GREY
HAVOC_INFO = "#8BE9FD" # CYAN
HAVOC_WARNING = "#FFB86C" # ORANGE


# creating global widgets
dialog = havocui.Dialog("CMEPW Payload Generator", True, 670, 300)
log = havocui.Logger("CMEPW Log")

class LoaderUI(object):
    def __init__(self, loader_name: str) -> None:
        self.exe_path = shutil.which(loader_name)
        self.loader_name = loader_name
        self.enc_key = None
        self.sc_path = None

        if not self.exe_path or not os.path.exists(self.exe_path):
            error_msg = f"[-] error: could not find {loader_name} in system"
            print(error_msg)
            havocui.messagebox(error_msg)  # type: ignore


    def set_key(self, key: str):
        self.enc_key = key
        print(f'[{self.loader_name}] key changed to {self.enc_key}')


    def set_sc_path(self, shellcode_path: str):
        self.sc_path = shellcode_path
        print(f'[{self.loader_name}] shellcode path changed to {self.sc_path}')


    def run_loader(self):
        log.setBottomTab()
        log.addText(f"<b style=\"color:{HAVOC_DARK};\">───────────── running {self.loader_name} ──────────────────</b>")
        log.addText(f"<b style=\"color:{HAVOC_COMMENT};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")

        if not self.sc_path:
            havocui.messagebox("Error", "Please specify a valid shellcode path.")
            log.addText(f"[<span style=\"color:{HAVOC_ERROR};\">-</span>] No shellcode file specified.")
            return

        log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] Selecting output filepath.")

        if not self.enc_key:
            log.addText(f"[<span style=\"color:{HAVOC_INFO};\">*</span>] No AES key provided. it will be this one : '0123456789ABCDEF1123345611111111'")
            self.enc_key = '0123456789ABCDEF1123345611111111'

        if self.loader_name == 'myph':
            cmd = f"{self.exe_path} -s {self.sc_path} -k {self.enc_key} --out /tmp/myph.exe "
        else:
            cmd = f'{self.exe_path} bake -m aes -k "{self.enc_key}" -s {self.sc_path} -o /tmp/bake.exe'

        log.addText(f'Command to be executed: {cmd}')
        os.system(cmd)

        log.addText(f'[+] Done.')
        log.addText(f"<b style=\"color:{HAVOC_SUCCESS};\">Payload generated successfully using {self.loader_name} loader. Happy pwn</b>")
        log.setBottomTab()

        dialog.close()


    def setup_builder(self):
        dialog.clear()

        # Build Dialog
        dialog.addLabel(f"<b>──────────────────────────── Required settings for {self.loader_name} ─────────────────────────────</b>")
        dialog.addButton("Choose shellcode", self.set_sc_path)

        if not self.sc_path:
            dialog.addLabel(f"<b style=\"color:{HAVOC_ERROR};\">No shellcode selected.</b>")
        else:
            dialog.addLabel(f"<span style=\"color:{HAVOC_SUCCESS};\">{self.sc_path}</span>")

        dialog.addLabel("<b>[*] AES key (Default: random)</b>")
        dialog.addLineedit("e.g. 0123456789ABCDEF1123345611111111", self.set_key)

        dialog.addButton("Generate", self.run_loader)
        dialog.exec()


#
# actual script
#
myph_ui = LoaderUI('myph')
twotwooneb_ui = LoaderUI('221b')

havocui.createtab("CMEPW", "221b loader", twotwooneb_ui.setup_builder, "myph loader", myph_ui.setup_builder)
