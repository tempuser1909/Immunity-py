from immlib import *
import struct

DESC = """Patches the kernel32.GetTickCount() routine."""

#############################################################################
class ret_hooks(LogBpHook):
   
    
    def __init__(self):
        LogBpHook.__init__(self)
    
    def run(self,regs):    

        imm = Debugger()
        
        imm.Log("GetTickCount Return Value -> %08x" % regs['EAX'])
        tick_counter = imm.getKnowledge("tickcounter")
        imm.setReg("EAX", tick_counter)
        imm.addKnowledge("tickcounter", tick_counter + 0x01)
        
        
#############################################################################
class set_hooks(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
                
    #########################################################################
    def run(self,regs):
        imm = Debugger() 
        
        esp_ptr = imm.readMemory(regs['ESP'],4)
        esp_ptr = struct.unpack("<L", esp_ptr)
        imm.Log("ESP -> %08x " % esp_ptr[0])
        # Now we hook [esp]
        ret_hook = ret_hooks()
        ret_hook.add("%08x" % esp_ptr[0],esp_ptr[0])
        
# The main routine that gets run when you type !tickcount
def main(args):

    imm = Debugger()
    imm.ignoreSingleStep("CONTINUE")
    hooker = set_hooks()

    imm.addKnowledge("tickcounter",0x100000)
    tickcount_addr     = imm.getAddress("kernel32.GetTickCount")
    
    
    hooker.add("gettickcount",        tickcount_addr)
          
        
    return "Hooked GetTickCount"