//--------------------------------------------------------------
//Author: Fatal (Team FOFF)
//Version: 1.1
//Date: 2/1/2008
//Changes:
//	- made the script search for ret instruction if it
//	is found the script will debfuscate till the end of the function
//	- added removal of prefix rep and prefix repne
//----------------------------------------------------------------

	var code_base
	var code_size
	var upper_limit
	var addr

	mov code_base, eip
	gmemi eip, MEMORYSIZE
	mov code_size, $RESULT

	add upper_limit, code_base
	add upper_limit, code_size

	findop code_base, #C3#
	cmp $RESULT, 0
	je deop_loop
	mov upper_limit, $RESULT
	msg "End of Function Found!!"

deop_loop:
	findop code_base, #EB01#
	cmp $RESULT, 0
	je continue1
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 3, 90
	jmp deop_loop

continue1:
	findop code_base, #??EB01#
	cmp $RESULT, 0
	je continue2
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 4, 90
	jmp deop_loop

continue2:
	findop code_base, #??EB02#
	cmp $RESULT, 0
	je continue3
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 5, 90
	jmp deop_loop

continue3:
	findop code_base, #F3#
	cmp $RESULT, 0
	je continue4
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 1, 90
	jmp deop_loop

continue4:
	findop code_base, #F2#
	cmp $RESULT, 0
	je continue5
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 1, 90
	jmp deop_loop

continue5:
	findop code_base, #EB02#
	cmp $RESULT, 0
	je finished
	cmp $RESULT, upper_limit
	jge finished
	mov addr, $RESULT
	fill addr, 4, 90
	jmp deop_loop


finished:
	ret
