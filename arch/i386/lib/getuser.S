/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */

/*
 * __get_user_X
 *
 * Inputs:	%eax contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *		%edx contains zero-extended value
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */
//在task_struct结构中位移12处为当前进程用户空间地址的上限.
addr_limit = 12

.text
.align 4
.globl __get_user_1
__get_user_1:
//先将当前进程的内核空间堆栈指针与8KB对齐,从而取得当前进程的task_struct结构指针.
	movl %esp,%edx
	andl $0xffffe000,%edx
//在task_truct结构中位移12处为当前进程用户空间地址的上限,所以作为参数传过来的地址不得高于这个上限.
	cmpl addr_limit(%edx),%eax
	jae bad_get_user
//如果地址没有超过范围就从用户空间把其内容读入寄存器dx,并将eax清0作为返回的函数值.
1:	movzbl (%eax),%edx
	xorl %eax,%eax
	ret

.align 4
.globl __get_user_2
__get_user_2:
	addl $1,%eax
	movl %esp,%edx
	jc bad_get_user
	andl $0xffffe000,%edx
	cmpl addr_limit(%edx),%eax
	jae bad_get_user
2:	movzwl -1(%eax),%edx
	xorl %eax,%eax
	ret

.align 4
.globl __get_user_4
__get_user_4:
	addl $3,%eax
	movl %esp,%edx
	jc bad_get_user
	andl $0xffffe000,%edx
	cmpl addr_limit(%edx),%eax
	jae bad_get_user
3:	movl -3(%eax),%edx
	xorl %eax,%eax
	ret

bad_get_user:
	xorl %edx,%edx
	movl $-14,%eax
	ret

.section __ex_table,"a"
	.long 1b,bad_get_user
	.long 2b,bad_get_user
	.long 3b,bad_get_user
.previous
