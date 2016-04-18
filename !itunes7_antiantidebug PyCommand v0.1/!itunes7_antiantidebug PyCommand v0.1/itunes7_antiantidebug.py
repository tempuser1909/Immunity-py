#!/usr/bin/env python
"""
Hook after iTunes.checkForDebuggers() returns
Set AL=0x00 (EAX=0xXXXXXX00)

Rhys Kidd <rhyskidd@gmail.com>

Rather than merely hooking on IsDebuggerPresent(), and still allowing 
both SoftICE detection techniques to complete, this method adjusts the 
relevant register after the wrapper function iTunes.checkForDebuggers() 
returns, thus preventing a call to Kernel32.ExitProcess(0).
"""

import immlib
from immlib import LogBpHook
import immlib


class iTunes_checkForDebuggers(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
                
    def run(self,regs):
        imm = immlib.Debugger()
        imm.Log("Setting AL=0x00")
        imm.setReg("EAX",0x00)
        imm.Log("Done!...")
        imm.Run()

def main(): 
    imm = immlib.Debugger()
    bp_address=0x004EA31C	# iTunes 7.3.2.6

    #004EA300  /$ 56             PUSH ESI
    #004EA301  |. FF15 D023EB00  CALL DWORD PTR DS:[<&KERNEL32.GetTickCou>; [GetTickCount
    #004EA307  |. 8BF0           MOV ESI,EAX
    #004EA309  |. A1 20F51F01    MOV EAX,DWORD PTR DS:[11FF520]
    #004EA30E  |. 05 60EA0000    ADD EAX,0EA60
    #004EA313  |. 3BF0           CMP ESI,EAX
    #004EA315  |. 76 17          JBE SHORT iTunes.004EA32E
    #004EA317  |. E8 44D0F2FF    CALL <iTunes.checkForDebuggers>          ;  Check for SoftICE device, SoftICE Registry entries & IsDebuggerPresent()
    #004EA31C  |. 84C0           TEST AL,AL					  ;  Hook here, and set AL=0x00
    #004EA31E  |. 74 08          JE SHORT iTunes.004EA328
    #004EA320  |. 6A 00          PUSH 0                                   ; /ExitCode = 0
    #004EA322  |. FF15 BC23EB00  CALL DWORD PTR DS:[<&KERNEL32.ExitProces>; \ExitProcess
    #004EA328  |> 8935 20F51F01  MOV DWORD PTR DS:[11FF520],ESI
    #004EA32E  |> 5E             POP ESI
    #004EA32F  \. C3             RETN
    
    logbp_hook = iTunes_checkForDebuggers()
    logbp_hook.add("iTunes_checkForDebuggers",bp_address)
    imm.Log("Placed hook: iTunes_checkForDebuggers")