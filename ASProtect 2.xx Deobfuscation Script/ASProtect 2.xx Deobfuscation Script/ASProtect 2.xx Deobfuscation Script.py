	var code_base
	var code_size
	var upper_limit
	var addr

	mov code_base, eip
	gmemi eip, MEMORYSIZE
	mov code_size, $RESULT

	add upper_limit, code_base
	add upper_limit, code_size

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
