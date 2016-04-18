#!/usr/bin/python 
"""
midlutil.py - utilities for unmidl.py

Copyright Immunity, 2005

Released under GPLv2.0

"""

import sys
goodchars=".()~!#$%^&*()-=_/\\:<>"
#let's not mess up our tty
def prettyprint(instring):
    instring=str(instring)
    tmp=[]
    for ch in instring:
        if (ch.isalnum() or ch in goodchars) and ord(ch)<127:
            tmp+=[ch]
        else:
            value="%2.2x" % ord(ch)
            tmp+=["["+value+"]"]
        
    return "".join(tmp)


def prettyhexprint(s):
    """
    A nicely displayed hexdump as a string
    """
    tmp=[]
    i=1
    for c in s:
        tmp+=["%2.2x "%ord(c)]
        if i%8==0:
            tmp+=["\n"]
        i+=1
    return "".join(tmp)


#wee little function for printing strings nicely
def hexprint(s):
    tmp=[]
    for c in s:
        tmp+=["[0x%2.2x]"%ord(c)]
    return "".join(tmp)


#int to intelordered string conversion
def intel_order(myint):
    str=""
    a=chr(myint % 256)
    myint=myint >> 8
    b=chr(myint % 256)
    myint=myint >> 8
    c=chr(myint % 256)
    myint=myint >> 8
    d=chr(myint % 256)
    
    str+="%c%c%c%c" % (a,b,c,d)

    return str

#just a nice short wrapper
def istr2int(astring):
    #print "istr2int(%s)"%astring
    
    return intel_str2int(astring)

#returns the integer that the 4 byte string represents
#Note: If you are getting OverflowError in this function, you need to upgrade to Python
#2.2. !!
def intel_str2int(astring):
        (a,b,c,d)=(ord(astring[0]),ord(astring[1]),ord(astring[2]),ord(astring[3]))
        #print "%x:%x:%x:%x"%(a,b,c,d)
        result=a
        result=result+b*256
        result=result+c*65536
        result=result+d*16777216
        #change 2 int type, if long
        result=big2int(result)
        return result



def big2int(big):
    """
    Changes a long that has been wrapped over into a normal
    int (as if it was unsigned)
    """
    if big>sys.maxint:
        return int(big-sys.maxint-sys.maxint-2)
    else:
        return big

def uuid2uuidstr(uuid):
    u=uuid
    uuidstr="%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"%(uint32(istr2int(u[:4])),
                                                                istr2halfword(u[4:6]),
                                                                istr2halfword(u[6:8]),
                                                                ord(u[8]),
                                                                ord(u[9]),
                                                                ord(u[10]),
                                                                ord(u[11]),
                                                                ord(u[12]),
                                                                ord(u[13]),
                                                                ord(u[14]),
                                                                ord(u[15]))
    return uuidstr

def istr2halfword(astring):
    """
    opposite is: halfword2istr()
    2 bytes in intel order into a short
    """
    (a,b)=(ord(astring[0]),ord(astring[1]))
    result=a
    result=result+b*256
    return result


def uint32(c):
    #might return a long, if it's a large positive value which would not fit into an int
    #print "c=%x"%c
    if c<0:
        #print "C<0"
        c=abs(0xffffffffL+c+1)
    elif c>0xffffffffL:
        #print "C>maxint"
        c=int(c-0xffffffffL-1)
    else:
        #print "C within range"
        pass
        
    return c

def signedshort(myint):
    #myint is 0xffe8 then it needs to be negative -24. Geddit?
    if myint>0x8000:
        myint=myint-65535-1
    return myint
