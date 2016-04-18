###GPL v2.0
#used in unmidl.py

from midlutil import intel_order

TRANSFER_SYNTAX_MAGIC=intel_order(0x8a885d04L) #+intel_order(0x44)

#/* Internal flags and values */
FLAG_IN     =     1
FLAG_OUT    =     2
FLAG_RETVAL =     4
FLAG_REFPTR  =    8
FLAG_OUTPUT  =    16
FLAG_DEFAULT =    32
FLAG_CONTEXT  =   64
EF_SWITCH_IS  =   128
EF_SIZE_IS    =   256
EF_LENGTH_IS  =   512
EF_BYTE_COUNT =   1024
FLAG_UNIQUEPTR = 2**11
FLAG_FULLPOINTER = 2**12
FLAG_UNIQUEOBJECT = 2**13 # a unique pointer in an object interface

OFFSET_PREV  =    32767

UNKNOWN        = "\?\?\?"

UNKNOWN_TYPE    =0xff
VOID_TYPE       =0xfe

#/* Token values */
FC_EXPLICIT_HANDLE              =0x00
FC_BYTE                         =0x01
FC_CHAR                         =0x02
FC_SMALL                        =0x03
FC_USMALL                       =0x04
FC_WCHAR                        =0x05
FC_SHORT                        =0x06
FC_USHORT                       =0x07
FC_LONG                         =0x08
FC_ULONG                        =0x09
FC_FLOAT                        =0x0a
FC_HYPER                        =0x0b
FC_DOUBLE                       =0x0c
FC_ENUM16                       =0x0d
FC_ENUM32                       =0x0e
FC_IGNORE                       =0x0f
FC_ERROR_STATUS_T               =0x10
FC_RP                           =0x11
FC_UP                           =0x12
FC_FP                           =0x14
FC_STRUCT                       =0x15
FC_PSTRUCT                      =0x16
FC_CSTRUCT                      =0x17
FC_CPSTRUCT                     =0x18
FC_CVSTRUCT                     =0x19
FC_BOGUS_STRUCT                 =0x1a
FC_CARRAY                       =0x1b
FC_CVARRAY                      =0x1c
FC_SMFARRAY                     =0x1d
FC_HARD_STRUCTURE = 0x20 #I can only guess at this value
FC_BOGUS_ARRAY                  =0x21
FC_C_CSTRING                    =0x22
FC_STRING_SIZED              =0x44
FC_C_WSTRING                    =0x25
FC_CSTRING                      =0x26
FC_WSTRING                      =0x29
FC_ENCAPSULATED_UNION           =0x2a
FC_NON_ENCAPSULATED_UNION       =0x2b
FC_BYTE_COUNT_POINTER           =0x2c
FC_BIND_CONTEXT                 =0x30
FC_BIND_GENERIC                 =0x31
FC_BIND_PRIMITIVE               =0x32
#//added by dave
FC_AUTO_HANDLE                  =0x33
FC_CALLBACK_HANDLE              =0x34 #//no idea either

FC_POINTER                      =0x36
FC_ALIGNM2                      =0x37
FC_ALIGNM4                      =0x38
FC_STRUCTPAD1                   =0x3d
FC_STRUCTPAD2                   =0x3e
FC_STRUCTPAD3                   =0x3f
FC_STRUCTPAD4                   =0x40
FC_STRUCTPAD5                   =0x41
FC_STRUCTPAD6                   =0x42
FC_STRUCTPAD7                   =0x43
FC_NO_REPEAT                    =0x46
FC_FIXED_REPEAT =0x47
FC_VARIABLE_REPEAT              =0x48
FC_FIXED_OFFSET                 =0x49
FC_PP                           =0x4b
FC_EMBEDDED_COMPLEX             =0x4c
FC_IN_PARAM                     =0x4d
FC_IN_PARAM_BASETYPE            =0x4e
FC_IN_OUT_PARAM                 =0x50
FC_OUT_PARAM                    =0x51
FC_RETURN_PARAM                 =0x52
FC_RETURN_PARAM_BASETYPE        =0x53
FC_DEREFERENCE                  =0x54
FC_DIV_2                        =0x55
FC_MULT_2                       =0x56
FC_ADD_1                        =0x57
FC_SUB_1                        =0x58
FC_CALLBACK                     =0x59
FC_END                          =0x5b
FC_PAD                          =0x5c

FC_RANGE_INTEGER = 0xb7

#/* Pointer attributes */
PA_ALLOC_ON_STACK               =0x04
PA_SIMPLE                       =0x08

#/* Procedure flags (MSNDR 2.0) */
PF_SRVMUSTSIZE                  =0x01
PF_CLIMUSTSIZE                  =0x02
PF_HASRETURN                    =0x04
PF_HASPIPES                     =0x08
PF_ASYNCHANDLE                  =0x40

#/* Parameter flags (MSNDR 2.0) */
PF_MUSTSIZE                     =0x0001
PF_MUSTFREE                     =0x0002
PF_PIPE                         =0x0004
PF_IN                           =0x0008
PF_OUT                          =0x0010
PF_RETURN                       =0x0020
PF_BASETYPE                     =0x0040
PF_BYVAL                        =0x0080
PF_SIMPLEREF                    =0x0100
PF_SRVALLOC8                    =0x2000

FC_NORMAL_CONFORMANCE = 0x00
FC_POINTER_CONFORMANCE = 0x10
FC_TOP_LEVEL_CONFORMANCE = 0x20
FC_TOP_LEVEL_MULTID_CONFORMANCE = 0x80
FC_CONSTANT_CONFORMANCE = 0x40

FC_FORWARD_REFERENCE = 0x00