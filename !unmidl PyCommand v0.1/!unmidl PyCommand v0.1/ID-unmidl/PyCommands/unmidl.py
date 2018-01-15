#!/usr/bin/env python
"""
Immunity Debugger Unmidl

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

Released under GPLv2.0
"""




import immlib
import getopt
import sys
import os
sys.path.append("../Libs")
from midlutil import *
import struct
#from msrpc import uuid2uuidstr
from midlconst import *


DESC="Goes through an executable and gets the IDL file from it that MIDL compiled into it."
output_dir="UNMIDL_RESULTS"
def usage(imm):
    imm.log("!unmidl -m module",focus=1)
    
#we assume we've compiled it with /robust (i.e. 2k)
assume_robustflag=1
debug=0


def dprint(astring):
    "little debug printer"
    if debug:
        print astring
    return

def dbuf(myPE,off):
    dprint("Debug Buffer: %s"%hexprint(myPE.getbuf(off)[:16]))
    
def getsizefromtype(basetype):
    "int is 4, etc"
    if basetype in [FC_BYTE,FC_CHAR]:
        return 1
    elif basetype in [FC_SMALL, FC_USMALL,FC_WCHAR,FC_SHORT,FC_USHORT]:
        return 2
    elif basetype in [FC_LONG,FC_ULONG]:
        return 4
    #blah blah...
    else:
        dprint("Unknown type %x"%basetype)
        

class VAL_REF:
    def __init__(self):
        self.attrib=0
        self.function=0
        self.value=0
        
    
    def display(self,refname,element_list,element):
        ret=""
        prefix=""
        suffix=""
        value=self.value
        if self.function==FC_CALLBACK:
            return ""
        
        if self.attrib & 0x0f ==0:
            if self.attrib >> 4 == 4:
                #FC_CONSTANT_CONFORMANCE
                if element.ptr_level >0 or element.base_type==0:
                    #subsequent 3 bytes are the actual value
                    #We've saved this as <function><value (swapped)>
                    #this is correct, but the value is actually multiplied by the size of the structure size.
                    #so if you have a 12 byte structure, and you have 4 of them, this is 0x30 (48 bytes)
                    #print "FC_CONST: Attrib: %x function %x value %2.2x"%(self.attrib,self.function,self.value)
                    #print "element.type.size=%d"%element.type.size
                    #element is a pointer to element.type. So element.type.size is what we want here
                    self.value=self.value/element.type.size
                    #It's not a pointer, it's an array
                    if element.base_type==0:
                        element.ptr_level+=1
                else:
                    #Array of some type, not sure what!
                    self.value=self.value/getsizefromtype(element.base_type)
                    #because it's an array, there's no pointer reference, so
                    #we have to add one
                    element.ptr_level+=1
                ret+="[%s(%d)] "%(refname,self.value)
                return ret
            return "[%s(UNKNOWN)]"%refname
        else:

            if self.function==FC_DIV_2:
                suffix= "/2"
            elif self.function==FC_MULT_2:
                suffix="*2"
            elif self.function==FC_SUB_1:
                suffix="-1"
            elif self.function==FC_ADD_1:
                suffix="+1"
            elif self.function==FC_DEREFERENCE:
                prefix="*"
            elif self.function==0:
                pass
            else:
                if debug:
                    print "Whoa! Totally unknown function code %x dude with value %x and attrib %x."%(self.function,self.value,self.attrib)
            
            if self.attrib >> 4 == 0:
                value+=element.offset
   
            #print "Type of element_list is %s"%type(element_list)
            if type(element_list)==type([]):
                #print "Length of list is %d. Value is %d"%(len(element_list),value)
                subelem=None
                for e in element_list:
                    #print "e.offset=%d"%e.offset
                    if e.offset==value:
                        subelem=e
            else:
                subelem=element_list.element_by_offset(value)
            
            if subelem!=None:
                ret="[%s(%s%s%s)] "%(refname,prefix,subelem.name,suffix)
                return ret
            
        return "Some kind of error!"

    
                
        
        
g_elementnum=1 #start at 1, weirdly
def get_next_element():
    global g_elementnum
    ret=g_elementnum
    g_elementnum+=1
    return ret

class ELEMENT_INFO:
    """
    An element can be a parameter or a part of a structure
    """
    def __init__(self):
        self.flags=0
        self.base_type=0 #default to struct/etc
        self.ptr_level=0
        self.simple_ref=0
        self.switch_is=VAL_REF()
        self.size_is=VAL_REF()
        self.length_is=VAL_REF()
        self.id=-1
        self.offset=0
        self.case_val=0
        self.name="element_%s"%get_next_element()
        self.type=None #for struct/union/etc
        self.range_low=None
        self.range_high=None
        
    def typename(self):
        star=""
        range=""
        if self.ptr_level==0: star=" *"
        if self.range_low!=None:
            range="[range(%d,%d)] "%(self.range_low,self.range_high)

        if self.base_type==FC_BYTE:
            return range+"byte"
        elif self.base_type==FC_LONG:
            return range+"long"
        elif self.base_type== FC_ULONG:
             return range+"unsigned long"
        elif self.base_type== FC_ENUM32:
            return "/* enum */ unsigned long"
        elif self.base_type== FC_SHORT:
            return range+"short"
        elif self.base_type== FC_USHORT:
            return range+"unsigned short"
        elif self.base_type== FC_ENUM16:
            return "/* enum */ unsigned short"
        elif self.base_type== FC_CHAR:
            return range+"char"
        elif self.base_type== FC_WCHAR:
            return "wchar_t"
        #Conformant string types - we know the size...
        elif self.base_type== FC_C_CSTRING:
            return "[string] char"+star
        elif self.base_type== FC_C_WSTRING:
            return "[string] wchar_t"+star
        elif self.base_type== FC_HYPER:
            return "hyper"
        elif self.base_type== FC_ERROR_STATUS_T:
            return "error_status_t"
        elif self.base_type== FC_IGNORE:
            return "/* [ignore] void * */ long"
        elif self.base_type== VOID_TYPE:
            return "void"
        elif self.base_type== UNKNOWN_TYPE:
            return UNKNOWN
        elif self.base_type==0:
            #struct/union/etc
            #return "TYPE_%d"%self.id
            if self.type!=None:
                return self.type.type_name()
            else:
                return "???"
        return "Unknown_TYPE(%s)"%self.base_type
    
    def get_attrib(self,elements):
        s=""
        if self.flags & EF_SIZE_IS:
            s+=self.size_is.display("size_is",elements,self)

        if self.flags & EF_BYTE_COUNT:
            self.get_val_ref("byte_count")
        
        if self.flags & EF_LENGTH_IS:
            self.length_is.display("length_is", elements, self)
            
        if self.flags & EF_SWITCH_IS:
            self.switch_is.display("switch_is",elements,self)
            
        #we need range() here as well, and these things can be
        #wacky functions basically...which we don't handle yet :<

        if self.flags & FLAG_IN and self.flags & FLAG_OUT:
            s+="[in,out] "
        elif self.flags & FLAG_IN:
            s+="[in] "
        elif self.flags & FLAG_OUT:
            s+="[out] "
        
        if self.ptr_level > 0:
            if self.flags & FLAG_CONTEXT:
                s+="[context_handle] "
            if self.flags & FLAG_REFPTR:
                s+="[ref] "
            #print "%x"%(self.flags )
            if self.flags & FLAG_UNIQUEOBJECT or self.flags & FLAG_UNIQUEPTR:
                s+="[unique] " 
        return s

    def printme(self):
        s=self.get_attrib()
        
        return s
    
    def isretval(self):
        #print "self.flags=%x (need %x)"%(self.flags,FLAG_RETVAL)
        if self.flags & FLAG_RETVAL:
            return 1
        return 0
            

class TYPE_INFO:
    """Functions are a kind of TYPE_INFO, as are Structures and types of that sort"""
    def __init__(self):
        self.id=-1
        self.base_type=-1
        self.flags=0
        self.source=""
        self.size=0
        self.elements=[] #here we store our types and parameters, etc
        self.num=0
        self.switch_is=None
        
    def type_name(self):
        return "TYPE_%d"%self.id
    
    def function_print(self,outbuf):
        self.outbuf=outbuf
        paramstr=""
        #print out a function
        ftype="void"
        fname=""
        foundretval=0
        function=self
        for e in function.elements:
            if e.isretval():
                function.returnelement=e
                ftype=e.typename()
                fname="*"*e.ptr_level
                #print "Found return value: %s"%e.typename()
                function.elements.remove(e)
                foundretval=1
                break #there can be only one return value ...

        #in the case that retval flag was not set on any of them, we just use the last one!
        if not foundretval:
            e=function.elements[-1]
            function.elements.remove(e)
            ftype=e.typename()
            fname="*"*e.ptr_level
            #print "Found return value: %s"%e.typename()
            foundretval=1

        #The following loop prevents a comma from going on the end of the last argument
        i=len(function.elements)
        for e in function.elements:
            if i!=1: 
                comma=","
            else:
                comma=""
            paramstr+=e.get_attrib(function.elements)+" %s %s %s%s\n"%(e.typename(),"*"*e.ptr_level,e.name,comma)
            i=i-1
            
        #print "%s %s Function_%2.2x( %s );\n"%(ftype,fname,self.num,paramstr)
        self.outbuf+="%s %s Function_%2.2x( %s );\n"%(ftype,fname,self.num,paramstr)
        
    def display_type(self,outbuf):
        self.outbuf=outbuf
        #print "  typedef  ",
        self.outbuf+="  typedef  \n"
        #print "base type:%x"%self.base_type
        if self.base_type==FC_STRUCT:
            #print "struct {"
            self.outbuf+="struct {\n"
            if len(self.elements):
                self.display_struct_elements(self.elements)
        elif self.base_type==FC_NON_ENCAPSULATED_UNION:
            #print "[switch_type(long)] union {"
            self.outbuf+="[switch_type(long)] union {\n"
            if len(self.elements):
                self.display_union_elements(self.elements)
        elif self.base_type==FC_ENCAPSULATED_UNION:
            #an encapsulated union is a union entirely contained within a structure
            """
            struct { 
            int i;
            [switch_is(i)] union {
            ...
            };
            """
            #print "Need work here"
            #print "[%s] union (%s %s) { "%(self.switch_is.display("switch_is",self.elements,self),self.type_name_of(), self.name) #no idea what I want here.
            self.outbuf+="[%s] union (%s %s) { \n"%(self.switch_is.display("switch_is",self.elements,self),self.type_name_of(), self.name) #no idea what I want here.
            self.display_union_elements(self.elements)
        else:
            #print "UNKNOWN TYPE (%x) {"%self.base_type
            self.outbuf+="UNKNOWN TYPE (%x) {\n"%self.base_type
        #print " } %s;"%self.type_name()
        self.outbuf+=" } %s;\n"%self.type_name()
            
        
    def display_struct_elements(self,elements):
        for e in elements:
            #print "  %s%s %s%s;"%(e.get_attrib(self),e.typename(),"*"*e.ptr_level,e.name)
            self.outbuf+="  %s%s %s%s;\n"%(e.get_attrib(self),e.typename(),"*"*e.ptr_level,e.name)
        return
    
    def display_union_elements(self,elements):
        for i in range(0,len(elements)-1):
            e=elements[i]
            #this is not correct - case(%d) should be ... something.
            #print "%s"%e
            #print "  [case(%d)] %s%s %s%s;"%(e.case_val,e.get_attrib(self),e.typename(),"*"*e.ptr_level,e.name)
            self.outbuf+="  [case(%d)] %s%s %s%s;\n"%(e.case_val,e.get_attrib(self),e.typename(),"*"*e.ptr_level,e.name)
        return
    
    def append(self,obj):
        #just a wrapper function to save typing
        self.elements.append(obj)
        return
    
    def element_by_offset(self,offset):
        #print "looking for offset %d"%offset
        for e in self.elements:
            #print "e.offset=%d"%e.offset
            if e.offset==offset:
                return e
        return None
    
        
    
        
def check_direction(type):
    if type in [FC_IN_PARAM,FC_IN_PARAM_BASETYPE]:
        return FLAG_IN
    elif type==FC_OUT_PARAM:
        return FLAG_OUT
    elif type==FC_IN_OUT_PARAM:
        return FLAG_IN | FLAG_OUT
    
    return 0

        
class IFID:
    def __init__(self):
        self.ifid=""
        self.versionmajor=-1
        self.versionminor=-1
        self.ndr_version=-1
        self.functions=[]
        self.types=[]
        self.next_type_id=1
        return
    
    def parse_error(self,mystr,myPE,off):
        print "PARSE_ERROR: %s"%mystr
        print hexprint(myPE.data[off:off+20])
        
    def printIDL(self):
        print "[ uuid(%s),"%self.ifid
        self.outbuf+="[ uuid(%s),\n"%self.ifid
        print "  version(%d.%d) ] interface myinterface"%(self.versionmajor,self.versionminor)
        self.outbuf+="  version(%d.%d) ] interface myinterface\n"%(self.versionmajor,self.versionminor)
        
    def get_type(self,base_type,source,size):
        #source is a string
        #muddle is used to having this return 0 on success (found type)
        #and 1 in the case that it made a new type
        dprint("get_type(%s,%s,%s)"%(base_type,hexprint(source[:8]),size))
        for t in self.types:
            if t.source==source:
                return 0,t
        t=TYPE_INFO()
        t.id=self.next_type_id
        self.next_type_id+=1
        if debug:
            print "Setting size=*%s*"%prettyprint(size)
        t.size=size
        t.source=source
        t.base_type=base_type
        #print "***adding type of base_type=%x"%t.base_type
        self.types.append(t)
        return 1,t

    def update_offset(self,elem,offset):
        dprint("update_offset: offset=*%s*"%offset)
        #this isn't quite right
        if elem.ptr_level>0:
            dprint("upate_offset found pointer so returning size of 4")
            size=4 #pointers are +4
        elif elem.base_type in [FC_BYTE,FC_CHAR,FC_USMALL,FC_SMALL]:
            size=1
        elif elem.base_type in [FC_WCHAR,FC_USHORT,FC_SHORT,FC_ENUM16]:
            size=2
        elif elem.base_type in [FC_HYPER,FC_DOUBLE]:
            size=8
        elif elem.base_type==0:
            if elem.type:
                size=elem.type.size #structures, etc.
                dprint("Structure/Union size of %d"%size)
            else:
                size=0 #OOPS!
        else:
            dprint("base type of %x, defaulting to 4"%elem.base_type)
            size=4
            #should we do this for length is as well?
            if elem.size_is.value!=0:
                #found an array!
                dprint("Found array, using size of %x instead"%elem.size_is.value)
                size=elem.size_is.value
                
        if size==2:
            offset=(offset+1) & 0xfffe
        elif size==4:
            offset=(offset+3) & 0xfffc
        elem.offset=offset
        if debug:
            print "size=*%s*"%prettyprint(size)
        offset+=size
        return offset
    
            
    def decode_procs(self,myPE,ptypes,procs,size):
        self.outbuf=myPE.outbuf
        opcode=0
        if debug:
            print "Decoding procs: size=%d"%size
        for i in range(0,size):
            if debug:
                print "\n\nParsing function 0x%x with ndr version %x"%(i,self.ndr_version)
            if self.ndr_version==2:
                f,procs,ptypes=self.parse_function_v2(myPE,procs,ptypes)
            elif self.ndr_version==1:
                f,procs,ptypes=self.parse_function_v1(myPE,procs,ptypes)
            else:
                #Sinan's IMMServ.exe is actually ndr_version 0, but decodes as version 2
                if debug:
                    print "(weird not 1 or 2) Self.ndr_version==%d"%self.ndr_version
                f,procs,ptypes=self.parse_function_v2(myPE,procs,ptypes)
            if f==None:
                if i<size:
                    dprint("Found %x functions when looking for %x"%(i,size))
                    dprint("Most likely a v1 function we didn't understand")
                #continue #used to be break
                break
            f.num=i
            self.functions.append(f)
        #print "//IDL"
        self.outbuf+="//IDL\n"
        self.printIDL()
        #print "//Displaying TYPES"
        self.outbuf+="//Displaying TYPES\n"
        self.display_all_types(self.outbuf)
        #print "//Display Functions"
        self.outbuf+="//Display Functions\n"
        
        for f in self.functions:
            f.function_print(self.outbuf)
                
    def parse_function_v2(self,myPE,procs,ptypes):
        off=procs
        if debug:
            print "parse_function_v2: procs: %s ptypes: %s"%(procs,ptypes)
            print "Data=%s"%hexprint(myPE.getbuf(procs)[:50])
        type,off=myPE.getbyte(off)
        if debug:
            print "Type=%x"%type
        if type not in [FC_EXPLICIT_HANDLE,FC_BIND_PRIMITIVE,FC_AUTO_HANDLE]:
            print "Warning: Unknown bind type!"
            return None, None, None
        attrib,off=myPE.getbyte(off)
        if attrib==0:
            return None,None,None #end of proc table
        
        if attrib & 0x08:
            rpcflags,off=myPE.getint(off)
        
        g_opcode,off=myPE.getshort(off)
        stack,off=myPE.getshort(off)
        if type==FC_EXPLICIT_HANDLE:
            type,off=myPE.getbyte(off)
            #need to figure out wtf is going on here
            if type==FC_BIND_PRIMITIVE:
                off+=3
            else: #FC_BIND_CONTEXT, GENERIC
                off+=5
            
        off+=4 #wtf.
        
        attrib,off=myPE.getbyte(off)
        nparams,off=myPE.getbyte(off)
        if attrib & PF_ASYNCHANDLE:
            off+=8 #ignore async handle
            
        function=TYPE_INFO()

        for i in range(0,nparams):
            if debug:
                print "\nParsing parameter %d"%i
            flags,off=myPE.getshort(off)
            stack,off=myPE.getshort(off)
            if flags & PF_BASETYPE:
                if debug:
                    print "Basetype found"
                type,off=myPE.getbyte(off)
                new_param,off=self.parse_simple(myPE,off,type)
                if flags & PF_SIMPLEREF:
                    if debug:
                        print "Simple ref found"
                    new_param.ptr_level+=1
                    new_param.simple_ref=1
                off+=1 #align it
            else:
                #not a basetype
                if debug:
                    print "Complex found"
                nptr_type,off=myPE.getshort(off)
                ptr_type=ptypes+nptr_type #an offset into the buffer
                new_param,ptr_type=self.parse_complex(myPE,ptr_type)
                
            if flags & PF_IN:
                new_param.flags |= FLAG_IN
                
            if flags & PF_OUT:
                new_param.flags |= FLAG_OUT
                
            if flags & PF_RETURN:
                new_param.flags |= FLAG_RETVAL
                
            if not flags & PF_BYVAL:
                if new_param.base_type==0:
                    new_param.ptr_level+=1
            
            new_param.offset=stack
            function.append(new_param)
        if debug:
            print "Done with v2 function"
        return function,off,ptypes

    
    def display_all_types(self,outbuf):
        for t in self.types:
            t.display_type(outbuf)
            
    def parse_function_v1(self,myPE,off,ptypes):
        function=TYPE_INFO()
        done=0
        offset=0
        while not done:
            handled=0
            type,off=myPE.getbyte(off)
            returnparam=0
            if debug:
                print "Parsing: %x"%type
            if type==FC_AUTO_HANDLE:
                off+=9 #need to learn how to parse this thing
                handled=1
                        
            if type==FC_RETURN_PARAM:
                done=1
                handled=1
                returnparam=1
            if type in [FC_IN_PARAM,FC_IN_OUT_PARAM, FC_OUT_PARAM]:
                stack,off=myPE.getbyte(off)
                pt_off,off=myPE.getshort(off)
                pt=ptypes+pt_off
                new_param,pt=self.parse_complex(myPE,pt)
                new_param.flags |= check_direction(type)
                new_param.offset = offset
                offset +=4*stack
                function.elements.append(new_param)
                handled=1            
            if type==FC_RETURN_PARAM_BASETYPE:
                done=1
                handled=1            
            if type in [FC_IN_PARAM_BASETYPE, FC_RETURN_PARAM_BASETYPE]:
                primtype,off=myPE.getbyte(off)
                new_param,off=self.parse_simple(myPE,off,primtype)
                new_param.flags |= check_direction(type)
                new_param.offset = offset
                offset +=4
                function.elements.append(new_param)
                handled=1                
            if type in [FC_BIND_GENERIC,FC_BIND_CONTEXT]:
                off+=5 #attribs, stack, handle param, pad
                handled=1                
            if type==FC_END:
                new_param=ELEMENT_INFO()
                new_param.base_type=VOID_TYPE
                function.elements.append(new_param)
                done=1
                handled=1
            if type==FC_PAD:
                handled=1
            
            if type==0:
                b,off=myPE.getbyte(off)
                if b!=0x40:
                    #error?
                    dprint("Found 0x40 in our getbyte, returning None!")
                    dbuf(myPE,off)
                    #off+=7
                    return None,off, ptypes
                self.g_opcode,off=myPE.getshort(off)
                off+=2 #stack size
                handled=1
                
            if returnparam:
                #print "FOUND RETURNPARAM!"
                new_param.flags|=FLAG_RETVAL
                
            if not handled:
                self.parse_error("Unknown token %8.8x"%type,myPE,off-2)
        if debug:
            print "Done with function!"
        
        return function,off,ptypes
       
    def parse_simple(self,myPE,off,type):
        if debug:
            print "Parsing simple of type %x at %8.8x"%(type,off)
        if type==FC_EMBEDDED_COMPLEX:
            attrib,off=myPE.getbyte(off) #this is actually memory padding
            ptype=myPE.OFFSET(off)
            dprint("Ptype offset: %x off=%x"%(ptype,off))
            ptype+=off #add current offset
            dprint("Embedded complex attrib %x ptype: %x"%(attrib,ptype))
            new_param,ptype=self.parse_complex(myPE,ptype)
            off+=2
        else:
            if type==0:
                if debug:
                    print "***Warning: we have no idea how to handle a type 0 here..."
            if debug:
                print "Not an embeded complex."
            new_param=ELEMENT_INFO()
            new_param.base_type=type
            
        return new_param,off
     
    def parse_complex(self,myPE,off):
        dprint("Parsing complex at %8.8x"%off)
        dbuf(myPE,off)
        type,off=myPE.getbyte(off)
        originaltype=type
        dprint("Complex type=%2.2x"%type)
        if type in [FC_RP,FC_UP,FC_FP]:
            if debug:
                print "parse_ptr calling..."
            return self.parse_ptr(myPE,off,type)
        elif type in [FC_LONG]:
            #this is probably a struct * _bob, but it encodes as a long
            if debug:
                print "Included a FC_LONG as a complex."
            return self.parse_simple(myPE,off,type)
        elif type in [FC_ENCAPSULATED_UNION,FC_NON_ENCAPSULATED_UNION]:
            if debug:
                print "parse_union calling..."
            return self.parse_union(myPE,off,type)
        elif type in [FC_STRUCT,FC_CSTRUCT,FC_PSTRUCT,FC_CPSTRUCT,FC_BOGUS_STRUCT]:
            if debug:
                print "parse_struct calling with type %x"%type
            return self.parse_struct(myPE,off,type)
        elif type in [FC_CARRAY,FC_CVARRAY,FC_SMFARRAY,FC_BOGUS_ARRAY]:
            if debug:
                print "Parsing array"
            return self.parse_array(myPE,off,type)
        new_param=ELEMENT_INFO()
        if type in [FC_WSTRING,FC_C_WSTRING]:
            if debug:
                print "!!!String type of %x"%type
            #new_param.ptr_level+=1
            new_param.base_type=FC_C_WSTRING
        elif type in [FC_CSTRING,FC_C_CSTRING]:
            if debug:
                print "String type 2"
            if type == FC_CSTRING:
                new_param.ptr_level+=1
            new_param.base_type=FC_C_CSTRING
        elif type==FC_BIND_CONTEXT:
            new_param.base_type=VOID_TYPE
            new_param.ptr_level+=1
            new_param.flags|=FLAG_CONTEXT
        elif type==FC_BYTE_COUNT_POINTER:
            if debug:
                print "****BYTE COUNT POINTER"
            off+=3
            size,off=myPE.getshort(off)
            ptype=myPE.OFFSET(off)
            new_param,ptype=self.parse_complex(myPE,ptype)
            new_param.ptr_level+=1
            new_param.size_is.attrib=0x40 #???
            new_param.size_is.function=0
            new_param.size_is.value=size
            new_param.flags |= EF_BYTE_COUNT
        elif type==FC_RANGE_INTEGER:
            if debug:
                print "Ranged integer found"
            unknown_flag,off=myPE.getbyte(off)
            from_int,off=myPE.getint(off)
            to_int,off=myPE.getint(off)
            paramtype,off=myPE.getbyte(off)
            new_param,off=self.parse_simple(myPE,off,unknown_flag)
            new_param.range_high=to_int
            new_param.range_low=from_int
        elif type==FC_FORWARD_REFERENCE:
            #WTH is this stuff!!!
            dprint("FC_FORWARD_REFERENCE?")
            new_param,off=self.parse_struct(myPE,off,FC_STRUCT)
            #If I get a 0 here, then I just got a pointer to the very start of the 
            #__MIDL_TypeFormatString + 2 bytes. Not sure why yet.
            #flag,off=myPE.getbyte(off)
            #size,off=myPE.getshort(off)
            
        else:
            if debug:
                print "Unknown complex type %8.8x"%type
                print "Buffer: %s"%prettyhexprint(myPE.getbuf(off)[:16])


        if type in [FC_C_CSTRING,FC_C_WSTRING]:
            if debug:
                print "Conformant string found: parsing conformance description"
            string_size,off=myPE.getbyte(off)
            if string_size!=FC_STRING_SIZED:
                if debug:
                    print "weird: string_size=%x (should be 0x44!)"%string_size
            else:
                size_is,off=self.parse_val_ref(myPE,off)
                new_param.size_is=size_is
                new_param.flags |= EF_SIZE_IS
                #print "Set size_is to non-Null"
        return new_param,off
    
    def parse_ptr(self,myPE,off,ptr_type):
        dprint("parse_ptr(offset %x,ptr_type %x)"%(off,ptr_type))
        attrib,off=myPE.getbyte(off)
        dprint("Pointer attributes %x"%attrib)
        if attrib & PA_SIMPLE:
            #this is where we end up without a size_is
            type, off=myPE.getbyte(off)
            dprint("PA_SIMPLE type %x"%type)
            element,off=self.parse_simple(myPE,off,type)
        else:
            #this is where we end up if we have an attribute of some kind
            if debug:
                print "There is an attribute here we need to parse"
                print "parse_ptr offset=%d"%myPE.OFFSET(off)
            ptype=off+myPE.OFFSET(off)
            if debug:
                print "ptype=%x"%ptype
            element,ptype=self.parse_complex(myPE,ptype)
            off+=2
            
        element.ptr_level+=1
        if ptr_type== FC_RP:
            element.flags |= FLAG_REFPTR
        if ptr_type==FC_UP:
            element.flags |= FLAG_UNIQUEPTR 
        if ptr_type==FC_FP:
            element.flags |= FLAG_FULLPOINTER

        #uncomment this when we figure out FP_OP
        #if ptr_type==FP_OP:
        #   element.flags |= FLAG_UNIQUEOBJECT
            
        return element,off
    
    def parse_union(self,myPE,off,union_type):
        dprint("Parsing Union at offset %x type %x"%(off,union_type))
        switch_is=VAL_REF()
        if union_type== FC_NON_ENCAPSULATED_UNION:
            attrib,off=myPE.getbyte(off)
            switch_is,off=self.parse_val_ref(myPE,off)
            sw_type=switch_is.attrib & 0x0f
            
            #if self.ndr_version >=2:
            #    off+=2
            off+=myPE.OFFSET(off) #offset to body of union
        else:
            sw_type,off=myPE.getbyte(off)
            switch_is.attrib=sw_type
            switch_is.function=0
            switch_is.value=0

        unionsize,off=myPE.getshort(off)
        numarms,off=myPE.getshort(off)
        numarms=numarms & 0xff #flags in high byte?
        instance=ELEMENT_INFO()
        instance.switch_is=switch_is
        instance.flags |= EF_SWITCH_IS
        if debug:
            print "Setting switch is flag."
        source=myPE.get_string(off)
        ret,instance.type=self.get_type(union_type,source,unionsize)
        if ret==0:
            return instance,off
        
        thistype=instance.type
        
        while numarms:
            numarms-=1
            caseno,off=myPE.getint(off)
            if debug:
                print "Caseno=%d"%caseno
            newelem,off=self.parse_union_arm(myPE,off,caseno)
            thistype.append(newelem)
            if debug:
                print "Union arm=%d"%newelem.case_val
            
        tmp=myPE.OFFSET(off)
        if debug:
            print "tmp=%d"%tmp
        if tmp not in [-1,0]:
            newelem,off=self.parse_union_arm(myPE,off,0)
            newelem.flags|=FLAG_DEFAULT
            thistype.append(newelem)

        instance.switch_is=switch_is
        newelem=ELEMENT_INFO()
        newelem.base_type=sw_type & 0x0f
        thistype.append(newelem)
        dprint("*"*50)
        return instance,off
   
    def parse_array(self,myPE,off,array_type):
        dprint("parse_array at %8x with array_type=%x"%(off,array_type))
        attributes,off=myPE.getbyte(off)
        size_is=VAL_REF()
        length_is=VAL_REF()
        flags=0
        
        if array_type==FC_SMFARRAY:
            size_is.attrib=0x40
            size_is.function=0
            size_is.value,off=myPE.getshort(off)
            dprint("size_is.value=%x"%size_is.value)
        elif array_type==FC_CARRAY:
            element_size,off=myPE.getshort(off)
            dprint("Conformant array element size: %x"%element_size)
            dbuf(myPE,off)
            dprint("off=%x"%off)
            #conformance description
            size_is,off=self.parse_val_ref(myPE,off)
            dprint("off2 (should be +6)=%x"%off)            
        elif array_type==FC_CVARRAY:
            element_size,off=myPE.getshort(off)
            dprint("Conformant Varrying array element size: %x"%element_size)
            #conformance description
            size_is,off=self.parse_val_ref(myPE,off)
            #varience description
            varience_is,off=self.parse_val_ref(myPE,off)            
        else:
            element_size,off=myPE.getshort(off)
            size_is,off=self.parse_val_ref(myPE,off)
            #if self.ndr_version>=2:
            #    off+=2 # No idea what this is for
                #It's probably the /robust flags
            
            length_is,off=self.parse_val_ref(myPE,off)
            if length_is.attrib!=0xff:
                flags= EF_LENGTH_IS

        #this is handle in parse_val_ref now.
        #if self.ndr_version>=2:
        #    off+=2
        #another exciting /robust flag
        dprint("off3=%x"%off)        
        dbuf(myPE,off)
        type,off=myPE.getbyte(off)
        if type==FC_PP:
            pointer_dict,off=self.parse_pointer_layout(myPE,off-1)
            dprint("Pointer layout in parse_array=%s"%pointer_dict.keys())
            #off=self.skip_fixup_table(myPE,off)
            type,off=myPE.getbyte(off)
        else:
            dprint("No pointer layout in array %x?"%type)
            dbuf(myPE,off-4)
        newelem,off=self.parse_simple(myPE,off,type)
        newelem.flags|=EF_SIZE_IS | flags
        newelem.size_is=size_is
        newelem.length_is=length_is
        dprint("Finished parsing array")
        return newelem, off

    def parse_one_pointer(self,myPE,off):
        "When we find a pointer in a complex structure, we need to parse it"
        dprint("Pointer Buffer: %s"%hexprint(myPE.getbuf(off)[:16]))
        #this is a raw pointer descriptor
        type,off=myPE.getbyte(off) #pointer type
        #attribute,off=myPE.getbyte(off)
        if type not in [FC_RP,FC_UP,FC_FP]: #FC_OP as well, but we don't know what that is
            dprint("Error: Did not recognize pointer type %x"%type)
            #it's just a pointer to a complex type of some kind, annoyingly
            newtype,off=self.parse_complex(myPE,off-1)
            return newtype,off
        
        newtype,off=self.parse_ptr(myPE,off,type)
        pad,off=myPE.getbyte(off)
        return newtype,off
        
    def parse_pointer_instance(self,myPE,off):
        #these offsets are signed
        offset_to_pointer_in_memory,off=myPE.getshort(off)
        offset_to_pointer_in_buffer,off=myPE.getshort(off)
        dprint("memoffset %x buffofset %x"%(offset_to_pointer_in_memory,offset_to_pointer_in_buffer))
        type,off=myPE.getbyte(off) #pointer type
        newelement,off=self.parse_ptr(myPE,off,type)
        offset=offset_to_pointer_in_memory
        return offset,newelement,off
        
    def parse_pointer_layout(self,myPE,off):
        "Returns a dictionary of pointers and their offsets"
        dprint("Parsing pointers")
        dprint("Parse Pointer Layout Buffer: %s"%hexprint(myPE.getbuf(off)[:32]))
        fcpp,off=myPE.getbyte(off)
        if fcpp!=FC_PP:
            dprint("fcpp is not FC_PP! %x"%fcpp)
        fcpad,off=myPE.getbyte(off)        
        if fcpad!=FC_PAD:
            dprint("fcpad!=FC_PAD! %x"%fcpad)
        type,off=myPE.getbyte(off)
        newelements={}
        #dictionary of [offset]=newelement
        while type!=FC_END:
            dprint("Pointer type not FC_END %x"%type)
            if type==FC_NO_REPEAT:
                #single instance of a pointer to a simple type, like a long, for example
                dprint("FC_NO_REPEAT: Single instance of a pointer to a simple")
                fcpad,off=myPE.getbyte(off)
                if fcpad!=FC_PAD:
                    dprint("fcpad!=FC_PAD! %x"%fcpad)
                #now a pointer instance (8 bytes)
                poffset,newelement,off=self.parse_pointer_instance(myPE,off)
                newelements[poffset]=newelement
            elif type==FC_FIXED_REPEAT:
                dprint("FC_FIXED_REPEAT pointers")
                fcpad,off=myPE.getbyte(off)
                if fcpad!=FC_PAD:
                    dprint("fcpad!=FC_PAD! %x"%fcpad)
                iterations,off=myPE.getshort(off)
                increment,off=myPE.getshort(off)
                offset_to_array,off=myPE.getshort(off)
                dprint("Offset to array: %x"%off)
                number_of_pointers,off=myPE.getshort(off)
                dprint("Number of pointers=%x"%number_of_pointers)
                #pointer instances
                #not quite right yet. We'll deal.
                for i in range(0,number_of_pointers):
                    poffset,newelement,off=self.parse_pointer_instance(myPE,off)
                    newelements[poffset]=newelement
      
            elif type==FC_VARIABLE_REPEAT:
                dprint("FC_VARIABLE_REPEAT...")
                #FC_FIXED_OFFSET or FC_VARIABLE_OFFSET
                subtype,off=myPE.getbyte(off)
                dprint("subtype=%x"%subtype)
                increment,off=myPE.getshort(off)
                dprint("increment=%x"%increment)
                offset_to_array,off=myPE.getshort(off)
                dprint("Offset to array: %x"%off)
                number_of_pointers,off=myPE.getshort(off)
                dprint("number_of_pointers: %x"%number_of_pointers)
                #pointer instances
                #we should probably handle offset to array and that stuff too...
                for i in range(0,number_of_pointers):
                    poffset,newelement,off=self.parse_pointer_instance(myPE,off)
                    newelements[poffset]=newelement

            #next iteration here...quit on FC_END
            type,off=myPE.getbyte(off)
        
        return newelements,off
    
    def parse_member_layout(self,myPE,off,pointer_off=None,pointer_dict=None):
        "A member layout of a structure (or union?)"
        if pointer_off:
            s_pointer_off="%x"%pointer_off
        else:
            s_pointer_off="None"
        dprint("parse_member_layout: pointer offset=%s, pointer_dict=%s"%(s_pointer_off,pointer_dict))
        thistype=[]
        done=0
        offset=0
        while not done:
            dprint("**Parse_member_layout offset: %x"%offset)
            subtype,off=myPE.getbyte(off)
            dprint("Subtype in struct is %x"%subtype)
            if subtype==FC_PP:
                if debug:
                    print "Parsing pointer layout instance"
                pfixup=off+1
                off=off+1
                #this is always wrong
                #off=self.skip_fixup_table(myPE,off)
                pointer_dict,off=self.parse_pointer_layout(myPE,off-2)
            elif subtype==FC_END:
                done=1
            elif subtype==FC_PAD:
                pass
            elif subtype==FC_ALIGNM2:
                offset=(offset+1) & 0xfffe
            elif subtype==FC_ALIGNM4:
                offset=(offset+1) & 0xfffc
            elif subtype in [FC_STRUCTPAD1,FC_STRUCTPAD2,FC_STRUCTPAD3,FC_STRUCTPAD4,
                             FC_STRUCTPAD5,FC_STRUCTPAD6,FC_STRUCTPAD7]:
                offset += subtype - FC_STRUCTPAD1 + 1
            elif subtype== FC_POINTER:
                dprint("About to parse FC_POINTER complex in parse_struct at offset %x"%off)
                dprint("Buffer: %s"%hexprint(myPE.getbuf(off)[:16]))
                if pointer_off!=None:
                    #complex structure parsing
                    dprint("pointer_off not None")
                    newelem,pointer_off=self.parse_one_pointer(myPE,pointer_off)
                    thistype.append(newelem)
                    continue
                else:
                    dprint("Pointer off is None")
                    newelem,off=self.parse_complex(myPE,off)
                    newelem.offset=offset
                    #this is broken!
                    offset+=4 #pointers are always 4 bytes long
                    count+=1
                    thistype.append(newelem)
                
                b=FC_PAD #initialize it
                while b==FC_PAD:
                    b,off=myPE.getbyte(off)                        
                        
            else:
                dprint("Parsing simple while in parse_member_layout...subtype=%x"%subtype)
                if subtype==FC_LONG and pointer_dict!=None and offset in pointer_dict.keys():
                    dprint("offset=%x keys: %s"%(offset,pointer_dict.keys()))
                    newelem=pointer_dict[offset]
                else:
                    newelem,off=self.parse_simple(myPE,off,subtype)
                #I do need this, but not for now
                offset=self.update_offset(newelem,offset)
                #count+=1
                #I've got some sort of element (be it a integer or whatever)
                #and I need to append it to my type
                thistype.append(newelem)
        
        return thistype,off
        
    def parse_struct(self,myPE,off,type):
        """Parses one of many types of structures and returns a 
        new ELEMENT_INFO() with a .type.elements[] array
        """
        #Our new instance of something
        instance=ELEMENT_INFO()
        #where it comes from...
        source=myPE.getbuf(off)
        alignment,off2=myPE.getbyte(off)
        memorysize,off2=myPE.getshort(off2)
        dprint("Parsing struct at off %x"%off)
        ret,instance.type=self.get_type(FC_STRUCT,source,memorysize)
        if ret==0:
            return instance,off
        
        if type in [FC_STRUCT]:
            dprint("parsing simple struct")
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            newmembers,off=self.parse_member_layout(myPE,off)
            instance.type.elements+=newmembers
            
        elif type in [FC_PSTRUCT]:
            dprint("Parsing simple struct with pointers")
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            pointer_dict,off=self.parse_pointer_layout(myPE,off)
            #instance.type.elements+=newmembers
            dprint("%d new members that were pointers"%len(pointer_dict.keys()))
            newmembers,off=self.parse_member_layout(myPE,off,pointer_dict=pointer_dict)
            dprint("%d new members total"%len(newmembers))
            instance.type.elements+=newmembers

        elif type in [FC_CSTRUCT]:
            dprint("Parsing conformant structure")
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            offset_to_array_descriptor,off=myPE.getshort(off)
            newmembers,off=self.parse_member_layout(myPE,off)
            #probably should parse this array as well
            dprint("Error: We didn't parse the array here...probably wrong result")
        elif type in [FC_CPSTRUCT]:
            if debug:
                print "Parsing conformant structure with pointers"
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            offset_to_array_descriptor,off=myPE.getshort(off)
            pointer_dict,off=self.parse_pointer_layout(myPE,off)
            newmembers,off=self.parse_member_layout(myPE,off,pointer_dict=pointer_dict)
        elif type in [FC_CVSTRUCT]:
            dprint("Parsing Conformant varying structure with or without pointers")
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            offset_to_array_descriptor,off=myPE.getshort(off)
            dprint("Error: did not parse a conformant varrying array")
            #optional pointer layout
            #I'm not sure how this really works here
        elif type in [FC_HARD_STRUCTURE]:
            dprint("Hard structure parsing")
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            reserved,off=myPE.getlong(off)
            enum_offset,off=myPE.getshort(off)
            copy_size,off=myPE.getshort(off)
            mem_copy_incr,off=myPE.getshort(off)
            union_description_offset,off=myPE.getshort(off)
            newmembers,off=self.parse_member_layout(myPE,off)
        elif type in [FC_BOGUS_STRUCT]:
            dprint("Complex structure parsing time")
            dprint("Complex Structure Check Buffer: %s"%hexprint(myPE.getbuf(off)[:16]))                            
            #dbuf(myPE,off)
            alignment,off=myPE.getbyte(off)
            memorysize,off=myPE.getshort(off)
            dprint("memorysize of complex structure: %x"%memorysize)
            offset_to_conformant_array,off=myPE.getshort(off)
            dprint("offset to conformant array:%x"%offset_to_conformant_array)
            off2=offset_to_conformant_array
            if offset_to_conformant_array:
                off2=off2+off-2
                array_type,off2=myPE.getbyte(off2)
                newstuff,off2=self.parse_array(myPE,off2,array_type)
                #we should probably do something with this. :>
            else:
                dprint("No conformant array in this structure")

            offset_to_pointer_layout,off=myPE.getshort(off)
            dprint("Offset to pointer layout: %x"%offset_to_pointer_layout)
            off2=None
            if offset_to_pointer_layout:
                #we don't have pointers other than our own in our pointer_layout, unlike the other structures
                #we don't have the first FC_PP or any of the usual information
                #We don't know how many there are, until we reach FC_POINTER members in our member structure
                off2=offset_to_pointer_layout+off-2 #as far as I know this equation is correct
                dbuf(myPE,off2)
                #newstuff2,off2=self.parse_pointer_layout(myPE,off2)
            else:
                dprint("No pointer layout in this structure")
                dprint("Theoretically, this means there are no pointers in the structure")
            newmembers,off=self.parse_member_layout(myPE,off,pointer_off=off2)
            instance.type.elements+=newmembers
        else:
            dprint("Error: Did not recognize structure type %x"%type)
            
        #What should I return here?
        return instance,off
            
            
    def parse_struct_old(self,myPE,off,type):
        if debug:
            print "Parse Struct at offset %x type %x"%(off,type)
            
        
            
        count=0
        #this code needs to track the byte offset within the structure of each
        #element - this is used later for matching val_ref's with particular
        #elements in the structure.
        offset=0
        parray=None
        pfixup=None
        
        attrib,off=myPE.getbyte(off)
        if debug:
            print "Structure alignment=%x"%attrib
            
        structsize,off=myPE.getshort(off)
        if debug:
            print "Structure memory size is %x"%structsize

        #this is some pretty crufty code right here
        instance=ELEMENT_INFO()
        source=myPE.get_string(off)
        ret,instance.type=self.get_type(FC_STRUCT,source,structsize)
        if ret==0:
            return instance,off
        
        thistype=instance.type
        alignment=0 #1 byte sometimes, but whatever
        #ending here
        
        if type==FC_BOGUS_STRUCT:
            #complex structure
            off+=alignment 
            memorysize,off=myPE.getshort(off)
            pptrs=off+myPE.OFFSET(off) #should be conformant array ptrs
            pointer_layout_offset=off+2+myPE.OFFSET(off+2) #???
            off+=2
            if debug:
                print "pointer_layout_offset=%x"%pointer_layout_offset
            #a bogus struct is used inside an encapsulated union...
        elif type==FC_PSTRUCT:
            #simple structure with pointers
            #memorysize, pointer layout, member layout
            #self.parse_pointer_layout(myPE,off)
            pass
        elif type in [FC_CSTRUCT, FC_CPSTRUCT]:
            #if it's a conformant structure
            parray=off+myPE.OFFSET(off)
            off+=2
            
        
        done=0
        while not done:
            subtype,off=myPE.getbyte(off)
            if debug:
                print "Subtype in struct is %x"%subtype
            if subtype==FC_PP:
                if debug:
                    print "Parsing pointer layout instance"
                pfixup=off+1
                off=off+1
                off=self.skip_fixup_table(myPE,off)
            elif subtype==FC_END:
                done=1
            elif subtype==FC_PAD:
                pass
            elif subtype==FC_ALIGNM2:
                offset=(offset+1) & 0xfffe
            elif subtype==FC_ALIGNM4:
                offset=(offset+1) & 0xfffc
            elif subtype in [FC_STRUCTPAD1,FC_STRUCTPAD2,FC_STRUCTPAD3,FC_STRUCTPAD4,
                             FC_STRUCTPAD5,FC_STRUCTPAD6,FC_STRUCTPAD7]:
                offset += subtype - FC_STRUCTPAD1 + 1
            elif subtype== FC_POINTER:
                if pptrs==None:
                    pass #!?!?!
                else:
                    if debug:
                        print "About to parse complex in parse_struct at offset %x"%off
                    
                    newelem,off=self.parse_complex(myPE,off)
                    newelem.offset=offset
                    offset+=4 #pointers are always 4 bytes long
                    count+=1
                    thistype.elements.append(newelem)
                    
                    b=FC_PAD #initialize it
                    while b==FC_PAD:
                        b,off=myPE.getbyte(off)                        
                        
            else:
                if debug:
                    print "Parsing simple while in struct...subtype=%x"%subtype
                newelem,off=self.parse_simple(myPE,off,subtype)
                offset=self.update_offset(newelem,offset)
                count+=1
                #I've got some sort of element (be it a integer or whatever)
                #and I need to append it to my type
                thistype.append(newelem)
                 
        if parray!=None:
            if debug:
                print "parry!=None: About to parse complex in parse_struct at offset %x"%off
            newelem,off=self.parse_complex(myPE,off)
            newelem.offset=offset
            thistype.elements.append(newelem)

        if pfixup!=None:
            #b_pfixup=FC_END+1 #anything but FC_END
            b_pfixup,_=myPE.getbyte(pfixup)

            while b_pfixup!= FC_END and count >0:
                if debug:
                    print "pfixup!=None - parsing complex (count=%d)!"%count
                #print "buf=%s"%hexprint(myPE.getbuf(pfixup)[:20])

                count-=1
                pfixup+=4 #skip over FC_NO_REPEAT, FC_PAD, offset
                if type==FC_CPSTRUCT:
                    pfixup+=6 #repeat info
                    
                offset,pfixup=myPE.getshort(pfixup)
                if debug:
                    print "Structure Offset (pfixup)=%4x"%offset
                #pfixup+=2

                newelem,pfixup=self.parse_complex(myPE,pfixup)
                thistype.append(newelem)
                #this is a messy little code block below. Sorry.
                #need to understand wtf this is doing to really create it...
                #I probably fucked it up.
                if 0:
                    for i in range(0,len(thistype.elements)):
                        if thistype.elements[i].offset==offset:
                            thistype.elements[i]=newelem
                            newelem.offset=offset
                    
                b_pfixup,_=myPE.getbyte(pfixup)
                while b_pfixup==FC_PAD:
                    b_pfixup,pfixup=myPE.getbyte(pfixup)
                b_pfixup,_=myPE.getbyte(pfixup)
                    
        instance.base_type
        
        return instance,off

     
    def parse_val_ref(self,myPE,off):
        "parse a validator reference"
        dprint("Parsing a val_ref")
        ret=VAL_REF()
        ret.attrib,off=myPE.getbyte(off)
        ret.function,off=myPE.getbyte(off)
        ret.value,off=myPE.getshort(off)
        if self.ndr_version>=2:
            off+=2
        dprint("Val_ref.value=%x"%ret.value)
        return ret, off
    
    def skip_fixup_table(self,myPE,off):
        dprint("skipping fixup table. This is always the wrong thing to do.")
        byte=""
        while byte!=FC_END:
            byte,off=myPE.getbyte(off)
        off+=1
        return off
    
    def parse_union_arm(self,myPE,off,case_val):
        offset=myPE.OFFSET(off)
        if offset< -32512:
            type=offset+32768 #??
            if debug:
                print "About to parse simple in a union arm"
            newelem,off=self.parse_simple(myPE,off,type)
        else:
            ptype=off+offset
            if debug:
                print "about to parse complex in a union arm"
            newelem,ptype=self.parse_complex(myPE,ptype)
        off+=2
        newelem.case_val=case_val
        return newelem,off
    
class SECTION:
    def __init__(self):
        self.name=""
        self.peoffset=-1
        self.vaddr_beg=-1
        self.vaddr_end=-1
    
    
class PEEXE:
    def __init__(self,exedata):
        self.data=exedata
        self.sections=[]
        self.outbuf=[]
        self.parse_pe_header()
        return
    
    def getchar(self,offset):
        return self.data[offset],offset+1
    
    def getbyte(self,offset):
        """returns a one byte int"""
        return ord(self.data[offset]),offset+1
    
    def getint(self,offset):
        ret=istr2int(self.data[offset:offset+4])
        #print "Ret(%8.8x)=%8.8x"%(offset,ret)
        return ret,offset+4

    def getlong(self,offset):
        #just a quick wrapper to make our lives easier
        return self.getint(offset)
    
    def getshort(self,offset):
        "A signed short"
        ret=istr2halfword(self.data[offset:offset+2])
        ret=signedshort(ret)
        #print "Ret(%8.8x)=%8.8x"%(offset,ret)
        return ret,offset+2
    
    def get_string(self,offset):
        "Returns the rest of the buffer until the first null character"
        ret=""
        while self.data[offset]!="\x00":
            ret+=self.data[offset]
            offset+=1
        return ret

    def getstring(self,offset):
        return self.get_string(offset)
    
    def getbuf(self,offset=0):
        "Returns the rest of the buffer."
        return self.data[offset:]
    
    def get_buf(self,offset=0):
        return self.getbuf(offset)
    
    def OFFSET(self,offset):
        ret,_=self.getshort(offset)
        ret=signedshort(ret)
        return ret

    def parse_pe_header(self):
        """
        Parse out the PE header from self.data and record some information about it
        """
        hdroffset=istr2int(self.data[15*4:]) #15 words in we have the exe header offset
        
        fs="<4sHHLLLHH"
        size=struct.calcsize(fs)
        tup=struct.unpack(fs,self.data[hdroffset:hdroffset+size])
        if debug:
            print "hdr=%s"%str(tup)
        magic,machine,num_sections,timestamp,ptr_symtab,num_symbols,size_opthdr,flags=tup
        if debug:
            print "Size of Optheader=%d"%size_opthdr
        if size_opthdr!=0:
            opt_header=self.data[hdroffset+size:hdroffset+size+size_opthdr]
            optfs="<HHLLLLLLL"
            magic,linkerver,codesize,datasize,bsssize,entrypoint,codebase,database,imagebase=struct.unpack(optfs,opt_header[:struct.calcsize(optfs)])
            #we may cut some information off the end of opthdr there...oh well
        else:
            imagebase=0
            
        #now load the section header
        sectfs="<8sLLLLLLHHL"
        sectsize=struct.calcsize(sectfs)
        sect_header=self.data[hdroffset+size+size_opthdr:hdroffset+size+size_opthdr+sectsize*num_sections]
        for i in range(0,num_sections):
            if debug:
                print "Sect header length=%d"%len(sect_header)
            newSEC=SECTION()
            tup=struct.unpack(sectfs,sect_header[:struct.calcsize(sectfs)])
            name,vsize,vaddr,size,offset,ptr_relocs,ptr_lineno,num_relocs,num_lineno,flags=tup
            #print "Added section: %s"%name 
            newSEC.name=name.replace("\x00","")
            newSEC.vaddr_beg=imagebase+vaddr
            newSEC.vaddr_end=imagebase+vaddr+size
            newSEC.peoffset=offset
            self.sections.append(newSEC)
            sect_header=sect_header[struct.calcsize(sectfs):]
        if debug:
            print "Total length: %8.8x"%len(self.data)
        for sect in self.sections:
            if debug:
                print "%s at %8.8x: %8.8x -> %8.8x"%(sect.name,sect.peoffset,sect.vaddr_beg,sect.vaddr_end)
        #ok, now we've loaded all the sections we need
        
        
        
    def map_offset_to_virtual_address(self,offset):
        """
        Take an offset into the PE file and map it into a real memory address
        """
        for sect in self.sections:
            if offset>=sect.offset and offset<=(sect.offset+sect.vaddr_end-sect.vaddr_beg):
                #I am in this section
                return sect.vaddr_beg+offset-sect.peoffset
            
        #FAILED
        return None
    
    def map_virt_to_offset(self,addr):
        """
        Takes an address in "memory" and returns where in the pe file this is
        """
        for sect in self.sections:
            if addr>=sect.vaddr_beg and addr<=sect.vaddr_end:
                #I am in this section
                return addr-sect.vaddr_beg+sect.peoffset
        #FAILED
        print "mapping virt to offset failed for %8.8x"%addr
        for sect in self.sections:
            if debug:
                print "%s: %8.8x -> %8.8x"%(sect.name,sect.vaddr_beg,sect.vaddr_end)
        return None
    
    def decode_interface(self,offset):
        
        #offset is a virtual address
        if debug:
            print "Decoding interface at offset %8.8x"%offset
        ifid=uuid2uuidstr(self.data[offset+4:])
        versionmajor=istr2halfword(self.data[offset+20:])
        versionminor=istr2halfword(self.data[offset+22:])
        #print "Data=%s"%hexprint(self.data[offset+30:offset+60])
        ptr_dispatch=istr2int(self.data[offset+4+20+20:])
        #print "ptr_dispatch=%x"%ptr_dispatch
        if ptr_dispatch==0:
            #client side routines, skip...
            
            print "Client routines found"
            self.outbuf+="Client routines found\n"
            return
            #pass #decode them anyways
        
        myIFID=IFID()
        myIFID.ifid=ifid
        myIFID.versionmajor=versionmajor
        myIFID.versionminor=versionminor
        ptr_interp_info=istr2int(self.data[offset+4+20+20+16:])
        if ptr_interp_info!=0:
            stub2=self.map_virt_to_offset(ptr_interp_info)
            if stub2==0:
                return #weird error?
            stub=self.map_virt_to_offset(istr2int(self.data[stub2:]))
        else:
            stub=offset+0x44+4
            dprint("Used calced stub %x"%stub)
        #now stub points to a STUB_INFO structure in self.data
        ptr_ifinfo=self.map_virt_to_offset(istr2int(self.data[stub:]))
        if ptr_ifinfo!=offset:
            #print "ptr_ifinfo=%s (from %s)"%(ptr_ifinfo,hexprint(self.data[ptr_interp_info:ptr_interp_info+4]))
            self.outbuf+="ptr_ifinfo=%s (from %s)\n"%(ptr_ifinfo,hexprint(self.data[ptr_interp_info:ptr_interp_info+4]))
            if ptr_ifinfo==None:
                ptr_ifinfo=0
            #print "Something's wrong, stub (%8.8x) is not pointing to ifinfo (%8.8x)!"%(ptr_ifinfo,offset)
            self.outbuf+="Something's wrong, stub (%8.8x) is not pointing to ifinfo (%8.8x)!\n"%(ptr_ifinfo,offset)
            return 
        stubfs="<LLLLLLLLLLLLLLL20s"
        tup=struct.unpack(stubfs,self.data[stub:stub+struct.calcsize(stubfs)])
        ptr_ifinfo,fn_alloc,fn_free,binding_info,rundown_fns,binding_fns,expr_eval,xmit_quintuple,ptr_types,check_bounds,ndr_version,malloc_info,midl_version,fault_offsets,user_marshal,reserved=tup
        ptypes=self.map_virt_to_offset(ptr_types)
        #psize=istr2int(self.data[self.map_virt_to_offset(ptr_dispatch):])
        if debug:
            print "pointer_dispatch=%8.8x"%ptr_dispatch
        ptr_dispatch_offset=self.map_virt_to_offset(ptr_dispatch)
        if debug:
            print "ptr_dispatch_offset=%8.8x"%ptr_dispatch_offset
        dbuf(self,ptr_dispatch_offset)
        psize,_=self.getint(ptr_dispatch_offset)
        
        if ptr_interp_info!=0:
            interp=self.map_virt_to_offset(ptr_interp_info)
            if debug:
                print "interp=%8.8x"%interp

            self.print_interp_info(interp)
            procs_virt,_=self.getint(interp+8)
            if debug:
                print "procs_virt=%8.8x"%procs_virt
            procs=self.map_virt_to_offset(procs_virt) #ptr_procs
        else:
            # find the information like muddle would...
            procs = stub + 0x50
            if debug:
                print "procs=%8.8x"%procs
                
            if binding_fns != 0:
                procs += 8
                if debug:
                    print "binding: procs=%8.8x"%procs
                  
            if expr_eval != 0:
                func,_ = self.getint(procs)
                while func != 0:
                    if debug:
                        print "eval: procs=%8.8x, func is %8.8x"%(procs, func)
                    procs += 4
                    func,_ = self.getint(procs)
                
            func,_ = self.getint(procs)
            while func == 0:
                if debug:
                    print "skip: procs=%8.8x, func is %8.8x"%(procs, func)
                procs += 4
                func,_ = self.getint(procs)

            procs += 2
            print "procs=%8.8x"%procs
            self.outbuf+="procs=%8.8x\n"%procs

        if debug:
            print "Success so far..."
        #print "//NDR Version = %4.4x"%(ndr_version & 0xffff)
        self.outbuf+="//NDR Version = %4.4x\n"%(ndr_version & 0xffff)
        myIFID.ndr_version=ndr_version & 0xffff
        
        myIFID.decode_procs(self,ptypes,procs,psize)
        return
    
    def print_interp_info(self,off):
        if debug:
            print "print_interp_info: %8.8x"%off
        interp_info_fs="<LLLLLLLL"
        tup=struct.unpack(interp_info_fs,self.data[off:off+struct.calcsize(interp_info_fs)])
        stub_desc,dispatch_table,ptr_procs,format_offset,thunk_table,local_types,local_procs,local_format_offset=tup
        if debug:
            print "tup=%s"%str(tup)

def unmidlexe(filename):
    outname=filename.split("\\")
    outname=outname[len(outname)-1]
    exedata=file(filename,"rb").read()
    myPE=PEEXE(exedata)
    #num_sections=myPE.hdr.num_sections
    #etc
    data=myPE.data
    total_offset=0
    while data!="":
        interface_offset=data.find(TRANSFER_SYNTAX_MAGIC)
        if interface_offset==-1:
            break
        #print "//Found interfaces at %x"%interface_offset
        
        myPE.outbuf+="//Found interfaces at %x\n"%interface_offset
        #print "Data=%s"%hexprint(data[interface_offset-6*4:interface_offset+10])
        if istr2int(data[interface_offset-6*4:])==0x44:
            #double check to see if 0x44 is there, cause it should always be there
            offset=interface_offset+total_offset-6*4
            if debug:
                #print "Offset=0x%8.8x"%offset
                f.write("Offset=0x%8.8x"%offset)
            
            myPE.decode_interface(offset)
        total_offset+=interface_offset+4    
        data=data[interface_offset+4:]
    try:
        os.makedirs(output_dir)
    except OSError, err:
        pass
    f=open(output_dir+"\\"+outname+"-unmidl.txt","w+")
    f.write("// unmidl.py version 1.0 by Dave Aitel www.immunityinc.com\n")
    for a in myPE.outbuf:
        f.write(a)
    f.close()
    
def main(args):
    imm = immlib.Debugger()
    mod_unmidl=None
    if not args:
        mod=[]
        allmodules=imm.getAllModules()
        if not allmodules: return "No modules available at this time"
        for key in allmodules.keys():
            mod.append(allmodules[key].getPath())
        mod_unmidl = imm.comboBox("Please choose module to unmidl", mod)
        imm.log("Module to unmidl : %s" % mod_unmidl)
                
    
    try:
        opts, argo = getopt.getopt(args, "m:s")
    except getopt.GetoptError:
        if not mod_unmidl:
            usage(imm)
            return "Bad unmidl argument %s" % args[0]
        else : pass
    type=None
    for o,a in opts:
        if o == "-m":
            try:
                tmp=open(a,"r")
                tmp.close()
                mod_unmidl=a
            except:
                return "Module doesnt exists: %s" % a
    
    exedata=file(mod_unmidl,"rb").read()
    unmidlexe(mod_unmidl)
    outname=mod_unmidl.split("\\")
    outname=outname[len(outname)-1]
    full_output=output_dir+"\\"+outname+"-unmidl.txt"
    imm.openTextFile(full_output)
    return "Unmidl finished, results at %s" %full_output
        

            
