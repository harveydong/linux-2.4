/*
 *  linux/fs/binfmt_aout.c
 *
 *  Copyright (C) 1991, 1992, 1996  Linus Torvalds
 */

#include <linux/module.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/a.out.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/malloc.h>
#include <linux/binfmts.h>
#include <linux/personality.h>
#include <linux/init.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>

static int load_aout_binary(struct linux_binprm *, struct pt_regs * regs);
static int load_aout_library(struct file*);
static int aout_core_dump(long signr, struct pt_regs * regs, struct file *file);

extern void dump_thread(struct pt_regs *, struct user *);

//a.out格式的linux_binfmt数据结构
//装载和投入运行a.out格式目标文件的函数为load_aout_binary

static struct linux_binfmt aout_format = {
	NULL, THIS_MODULE, load_aout_binary, load_aout_library, aout_core_dump, PAGE_SIZE
};

//为可执行代码的bss段分配空间并建立起页面映射.
static void set_brk(unsigned long start, unsigned long end)
{
	start = PAGE_ALIGN(start);
	end = PAGE_ALIGN(end);
	if (end <= start)
		return;
	do_brk(start, end - start);
}

/*
 * These are the only things you should do on a core-file: use only these
 * macros to write out all the necessary info.
 */

static int dump_write(struct file *file, const void *addr, int nr)
{
	return file->f_op->write(file, addr, nr, &file->f_pos) == nr;
}

#define DUMP_WRITE(addr, nr)	\
	if (!dump_write(file, (void *)(addr), (nr))) \
		goto end_coredump;

#define DUMP_SEEK(offset) \
if (file->f_op->llseek) { \
	if (file->f_op->llseek(file,(offset),0) != (offset)) \
 		goto end_coredump; \
} else file->f_pos = (offset)

/*
 * Routine writes a core dump image in the current directory.
 * Currently only a stub-function.
 *
 * Note that setuid/setgid files won't make a core-dump if the uid/gid
 * changed due to the set[u|g]id. It's enforced by the "current->dumpable"
 * field, which also makes sure the core-dumps won't be recursive if the
 * dumping of the process results in another error..
 */

static int aout_core_dump(long signr, struct pt_regs * regs, struct file *file)
{
	mm_segment_t fs;
	int has_dumped = 0;
	unsigned long dump_start, dump_size;
	struct user dump;
#if defined(__alpha__)
#       define START_DATA(u)	(u.start_data)
#elif defined(__arm__)
#	define START_DATA(u)	((u.u_tsize << PAGE_SHIFT) + u.start_code)
#elif defined(__sparc__)
#       define START_DATA(u)    (u.u_tsize)
#elif defined(__i386__) || defined(__mc68000__)
#       define START_DATA(u)	(u.u_tsize << PAGE_SHIFT)
#endif
#ifdef __sparc__
#       define START_STACK(u)   ((regs->u_regs[UREG_FP]) & ~(PAGE_SIZE - 1))
#else
#       define START_STACK(u)   (u.start_stack)
#endif

	fs = get_fs();
	set_fs(KERNEL_DS);
	has_dumped = 1;
	current->flags |= PF_DUMPCORE;
       	strncpy(dump.u_comm, current->comm, sizeof(current->comm));
#ifndef __sparc__
	dump.u_ar0 = (void *)(((unsigned long)(&dump.regs)) - ((unsigned long)(&dump)));
#endif
	dump.signal = signr;
	dump_thread(regs, &dump);

/* If the size of the dump file exceeds the rlimit, then see what would happen
   if we wrote the stack, but not the data area.  */
#ifdef __sparc__
	if ((dump.u_dsize+dump.u_ssize) >
	    current->rlim[RLIMIT_CORE].rlim_cur)
		dump.u_dsize = 0;
#else
	if ((dump.u_dsize+dump.u_ssize+1) * PAGE_SIZE >
	    current->rlim[RLIMIT_CORE].rlim_cur)
		dump.u_dsize = 0;
#endif

/* Make sure we have enough room to write the stack and data areas. */
#ifdef __sparc__
	if ((dump.u_ssize) >
	    current->rlim[RLIMIT_CORE].rlim_cur)
		dump.u_ssize = 0;
#else
	if ((dump.u_ssize+1) * PAGE_SIZE >
	    current->rlim[RLIMIT_CORE].rlim_cur)
		dump.u_ssize = 0;
#endif

/* make sure we actually have a data and stack area to dump */
	set_fs(USER_DS);
#ifdef __sparc__
	if (verify_area(VERIFY_READ, (void *) START_DATA(dump), dump.u_dsize))
		dump.u_dsize = 0;
	if (verify_area(VERIFY_READ, (void *) START_STACK(dump), dump.u_ssize))
		dump.u_ssize = 0;
#else
	if (verify_area(VERIFY_READ, (void *) START_DATA(dump), dump.u_dsize << PAGE_SHIFT))
		dump.u_dsize = 0;
	if (verify_area(VERIFY_READ, (void *) START_STACK(dump), dump.u_ssize << PAGE_SHIFT))
		dump.u_ssize = 0;
#endif

	set_fs(KERNEL_DS);
/* struct user */
	DUMP_WRITE(&dump,sizeof(dump));
/* Now dump all of the user data.  Include malloced stuff as well */
#ifndef __sparc__
	DUMP_SEEK(PAGE_SIZE);
#endif
/* now we start writing out the user space info */
	set_fs(USER_DS);
/* Dump the data area */
	if (dump.u_dsize != 0) {
		dump_start = START_DATA(dump);
#ifdef __sparc__
		dump_size = dump.u_dsize;
#else
		dump_size = dump.u_dsize << PAGE_SHIFT;
#endif
		DUMP_WRITE(dump_start,dump_size);
	}
/* Now prepare to dump the stack area */
	if (dump.u_ssize != 0) {
		dump_start = START_STACK(dump);
#ifdef __sparc__
		dump_size = dump.u_ssize;
#else
		dump_size = dump.u_ssize << PAGE_SHIFT;
#endif
		DUMP_WRITE(dump_start,dump_size);
	}
/* Finally dump the task struct.  Not be used by gdb, but could be useful */
	set_fs(KERNEL_DS);
	DUMP_WRITE(current,sizeof(*current));
end_coredump:
	set_fs(fs);
	return has_dumped;
}

/*
 * create_aout_tables() parses the env- and arg-strings in new user
 * memory and creates the pointer tables from them, and puts their
 * addresses on the "stack", returning the new stack pointer value.
 */
static unsigned long * create_aout_tables(char * p, struct linux_binprm * bprm)
{
	char **argv, **envp;
	unsigned long * sp;
	int argc = bprm->argc;
	int envc = bprm->envc;

	sp = (unsigned long *) ((-(unsigned long)sizeof(char *)) & (unsigned long) p);
#ifdef __sparc__
	/* This imposes the proper stack alignment for a new process. */
	sp = (unsigned long *) (((unsigned long) sp) & ~7);
	if ((envc+argc+3)&1) --sp;
#endif
#ifdef __alpha__
/* whee.. test-programs are so much fun. */
	put_user(0, --sp);
	put_user(0, --sp);
	if (bprm->loader) {
		put_user(0, --sp);
		put_user(0x3eb, --sp);
		put_user(bprm->loader, --sp);
		put_user(0x3ea, --sp);
	}
	put_user(bprm->exec, --sp);
	put_user(0x3e9, --sp);
#endif
	sp -= envc+1;
	envp = (char **) sp;
	sp -= argc+1;
	argv = (char **) sp;
#if defined(__i386__) || defined(__mc68000__) || defined(__arm__)
	put_user((unsigned long) envp,--sp);
	put_user((unsigned long) argv,--sp);
#endif
	put_user(argc,--sp);
	current->mm->arg_start = (unsigned long) p;
	while (argc-->0) {
		char c;
		put_user(p,argv++);
		do {
			get_user(c,p++);
		} while (c);
	}
	put_user(NULL,argv);
	current->mm->arg_end = current->mm->env_start = (unsigned long) p;
	while (envc-->0) {
		char c;
		put_user(p,envp++);
		do {
			get_user(c,p++);
		} while (c);
	}
	put_user(NULL,envp);
	current->mm->env_end = (unsigned long) p;
	return sp;
}

/*
 * These are the functions used to load a.out style executables and shared
 * libraries.  There is no binary dependent code anywhere else.
 */


/*
struct exec {
	unsigned long a_info;//这个分为两个部分,其高１６位是一个代表目标CPU类型的代码.对于i386cpu这部分的值为100(0x64);低16位就是magic number. 不过a.out文件的magic number并不像在有的格式中那样是可打印字符,而是表示某些属性的编码,一共4种,即ZMAGIC, OMAGIC, QMAGIC, NMAGIC.
	unsigned a_text;
	unsigned a_data;
	unsigned a_bss;
	unsigned a_syms;
	unsigned a_entry;
	unsigned a_trsize;
	unsigned a_drsize;
}

*/
static int load_aout_binary(struct linux_binprm * bprm, struct pt_regs * regs)
{
	struct exec ex;
	unsigned long error;
	unsigned long fd_offset;
	unsigned long rlim;
	int retval;
//首先检查目标文件的格式,看看是否对上号.
//所有a.out格式可执行文件(二进制代码)的开头都应该是一个exec数据结构.在include/asm-i386/a.out.h定义的
	ex = *((struct exec *) bprm->buf);		/* exec-header */
	if ((N_MAGIC(ex) != ZMAGIC && N_MAGIC(ex) != OMAGIC &&
	     N_MAGIC(ex) != QMAGIC && N_MAGIC(ex) != NMAGIC) ||
	    N_TRSIZE(ex) || N_DRSIZE(ex) ||
	    bprm->file->f_dentry->d_inode->i_size < ex.a_text+ex.a_data+N_SYMSIZE(ex)+N_TXTOFF(ex)) {
		return -ENOEXEC;
	}
//各种a.out格式的文件因目标文件的特性不同,其正文的起始位置也就不同.因此,下面的宏根据代码的特性取得正文在目标文件中的起始位置
	fd_offset = N_TXTOFF(ex);

	/* Check initial limits. This avoids letting people circumvent
	 * size limits imposed on them by creating programs with large
	 * arrays in the data or bss.
	 */
	rlim = current->rlim[RLIMIT_DATA].rlim_cur;
	if (rlim >= RLIM_INFINITY)
		rlim = ~0;

//目标文件所确定的data和bss两个”段“的总和不能超过进程的DATA资源限制
	if (ex.a_data + ex.a_bss > rlim)
		return -ENOMEM;


//顺利通过了检验后就表示具备了执行该目标文件的条件.所以就到了”与过去告别“的时候.
//这种”告别过去“意味着放弃从父进程”继承“下来的全部用户空间.
//不管是通过复制还是通过共享继承下来的.
	/* Flush all traces of the currently running executable */
//在fs/exec.c中
	retval = flush_old_exec(bprm);
	if (retval)
		return retval;


//到这里,当前进程已经完成了与过去告别,准备迎接新的使命了.
	/* OK, This is the point of no return */
#if !defined(__sparc__)
	set_personality(PER_LINUX);
#else
	set_personality(PER_SUNOS);
#if !defined(__sparc_v9__)
	memcpy(&current->thread.core_exec, &ex, sizeof(struct exec));
#endif
#endif

	current->mm->end_code = ex.a_text +
		(current->mm->start_code = N_TXTADDR(ex));
	current->mm->end_data = ex.a_data +
		(current->mm->start_data = N_DATADDR(ex));
	current->mm->brk = ex.a_bss +
		(current->mm->start_brk = N_BSSADDR(ex));

	current->mm->rss = 0;
	current->mm->mmap = NULL;

//确定进程在开始执行新的目标代码以后所具有的权限. 这是根据bprm中的内容和当前的权限确定的.
	compute_creds(bprm);
 	current->flags &= ~PF_FORKNOEXEC;
#ifdef __sparc__
	if (N_MAGIC(ex) == NMAGIC) {
		loff_t pos = fd_offset;
		/* Fuck me plenty... */
		/* <AOL></AOL> */
		error = do_brk(N_TXTADDR(ex), ex.a_text);
		bprm->file->f_op->read(bprm->file, (char *) N_TXTADDR(ex),
			  ex.a_text, &pos);
		error = do_brk(N_DATADDR(ex), ex.a_data);
		bprm->file->f_op->read(bprm->file, (char *) N_DATADDR(ex),
			  ex.a_data, &pos);
		goto beyond_if;
	}
#endif

	if (N_MAGIC(ex) == OMAGIC) {
		unsigned long text_addr, map_size;
		loff_t pos;

		text_addr = N_TXTADDR(ex);

#if defined(__alpha__) || defined(__sparc__)
		pos = fd_offset;
		map_size = ex.a_text+ex.a_data + PAGE_SIZE - 1;
#else
		pos = 32;
		map_size = ex.a_text+ex.a_data;
#endif

		error = do_brk(text_addr & PAGE_MASK, map_size);
		if (error != (text_addr & PAGE_MASK)) {
			send_sig(SIGKILL, current, 0);
			return error;
		}

		error = bprm->file->f_op->read(bprm->file, (char *)text_addr,
			  ex.a_text+ex.a_data, &pos);
		if (error < 0) {
			send_sig(SIGKILL, current, 0);
			return error;
		}
			 
		flush_icache_range(text_addr, text_addr+ex.a_text+ex.a_data);
	} else {
//在a.out格式的可执行文件中,除OMAGIC以外其它三种均为纯代码;也就是所谓的"可重入"代码.
//此类代码中,不但其正文段的执行代码在运行时不会改变,其数据段的内容也不会在运行时改变.
//所以,内核干脆将可执行文件映射到了进程的用户空间中,这样连通常swap所需的盘上空间也省了.
//在这三种类型的可执行文件中。除NMAGE以外都要求正文段以及数据段的长度与页面大小对齐.
//如果发现没有对齐就要通过printk发出警告信息.但是,发出警告信息太频繁也不好.所以就设置了一个静态变量erro_time2.
		static unsigned long error_time, error_time2;
		if ((ex.a_text & 0xfff || ex.a_data & 0xfff) &&
		    (N_MAGIC(ex) != NMAGIC) && (jiffies-error_time2) > 5*HZ)
		{
			printk(KERN_NOTICE "executable not page aligned\n");
			error_time2 = jiffies;
		}

		if ((fd_offset & ~PAGE_MASK) != 0 &&
		    (jiffies-error_time) > 5*HZ)
		{
			printk(KERN_WARNING 
			       "fd_offset is not page aligned. Please convert program: %s\n",
			       bprm->file->f_dentry->d_name.name);
			error_time = jiffies;
		}
//接下来的操作取决于具体的文件系统是否提供mmap,就是将一个已打开文件映射到虚存空间的操作.
//以及正文段和数据段的长度是否与页面大小对齐.
//如果不满足映射的条件,就分配空间并且将正文段和数据段一起读入至进程的用户空间.
//这次是从文件中位移为fd_offset,即N_TXTOFF(ex)的地方开始,读入到由文件的头部所指定的地址N_TXTADDR(ex),长度为两段的总和.
		if (!bprm->file->f_op->mmap||((fd_offset & ~PAGE_MASK) != 0)) {
			loff_t pos = fd_offset;
			do_brk(N_TXTADDR(ex), ex.a_text+ex.a_data);
			bprm->file->f_op->read(bprm->file,(char *)N_TXTADDR(ex),
					ex.a_text+ex.a_data, &pos);
			flush_icache_range((unsigned long) N_TXTADDR(ex),
					   (unsigned long) N_TXTADDR(ex) +
					   ex.a_text+ex.a_data);
			goto beyond_if;
		}

//如果满足映射的条件,那就更好了.那就通过do_mmap分别将文件的正文段和数据段映射到进程的用户空间中,映射的地址则与装入的地址一致.
//调用mmap之前无需分配空间,那已经包含在mmap之中了.
		down(&current->mm->mmap_sem);
		error = do_mmap(bprm->file, N_TXTADDR(ex), ex.a_text,
			PROT_READ | PROT_EXEC,
			MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE,
			fd_offset);
		up(&current->mm->mmap_sem);

		if (error != N_TXTADDR(ex)) {
			send_sig(SIGKILL, current, 0);
			return error;
		}

		down(&current->mm->mmap_sem);
 		error = do_mmap(bprm->file, N_DATADDR(ex), ex.a_data,
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE,
				fd_offset + ex.a_text);
		up(&current->mm->mmap_sem);
		if (error != N_DATADDR(ex)) {
			send_sig(SIGKILL, current, 0);
			return error;
		}
	}

//到此,正文段和数据段都已转入就绪了,接下来就是bss段和堆栈段了.
beyond_if:
//在fs/exec.c中
	set_binfmt(&aout_format);

	set_brk(current->mm->start_brk, current->mm->brk);



//接着,还要在用户空间的堆栈区顶部为进程建立起一个虚存区间,并将执行参数以及环境变量所占的物理页面与此虚存区间建立起映射.
	retval = setup_arg_pages(bprm); 
	if (retval < 0) { 
		/* Someone check-me: is this error path enough? */ 
		send_sig(SIGKILL, current, 0); 
		return retval;
	}

//设置完了参数和环境变量后,在这些页面的下方,就是函数调用的用户空间堆栈了.
//任何程序的入口main,有连个参数argc和argv.其中参数argv[]是字符指针数组,argc则为数组的大小.但是实际上还有个隐藏着的字符指针数组envp[]用来传递环境变量
//只是不在用户程序的"视野"之内而已. 所以,用户空间堆栈中从一开始就要设置好三项数据.即envp[], argv[], argc.
//此外,还要将保存着(字符串形式的)参数和环境变量复制到用户空间的顶端.
	current->mm->start_stack =
		(unsigned long) create_aout_tables((char *) bprm->p, bprm);
#ifdef __alpha__
	regs->gp = ex.a_gpvalue;
#endif

//到这里,堆栈顶端的argv[]和argc都已经准备好了.


//这个是个宏,在include/asm-i385/processor.h中
//这里regs,指向保留在当前进程内核空间堆栈中的各个寄存器副本,当进程从系统调用返回时,这些数值就会被"恢复"到CPU的各个寄存器中. 所以
//到时候堆栈指针将是current->mm->start_stack；而返回地址,也就是EIP的内容,则将是ex.a_entry.
	start_thread(regs, ex.a_entry, current->mm->start_stack);
	if (current->ptrace & PT_PTRACED)
		send_sig(SIGTRAP, current, 0);
//到此,可执行代码的装入和投入运行已经完成.而do_execve在调用了search_binary_handler以后也就结束了.
//当cpu从系统调用返回到用户空间时,就会从由ex.a_entry确定的地址开始执行.
	return 0;
}

static int load_aout_library(struct file *file)
{
	struct inode * inode;
	unsigned long bss, start_addr, len;
	unsigned long error;
	int retval;
	struct exec ex;

	inode = file->f_dentry->d_inode;

	retval = -ENOEXEC;
	error = kernel_read(file, 0, (char *) &ex, sizeof(ex));
	if (error != sizeof(ex))
		goto out;

	/* We come in here for the regular a.out style of shared libraries */
	if ((N_MAGIC(ex) != ZMAGIC && N_MAGIC(ex) != QMAGIC) || N_TRSIZE(ex) ||
	    N_DRSIZE(ex) || ((ex.a_entry & 0xfff) && N_MAGIC(ex) == ZMAGIC) ||
	    inode->i_size < ex.a_text+ex.a_data+N_SYMSIZE(ex)+N_TXTOFF(ex)) {
		goto out;
	}

	if (N_FLAGS(ex))
		goto out;

	/* For  QMAGIC, the starting address is 0x20 into the page.  We mask
	   this off to get the starting address for the page */

	start_addr =  ex.a_entry & 0xfffff000;

	if ((N_TXTOFF(ex) & ~PAGE_MASK) != 0) {
		static unsigned long error_time;
		loff_t pos = N_TXTOFF(ex);

		if ((jiffies-error_time) > 5*HZ)
		{
			printk(KERN_WARNING 
			       "N_TXTOFF is not page aligned. Please convert library: %s\n",
			       file->f_dentry->d_name.name);
			error_time = jiffies;
		}

		do_brk(start_addr, ex.a_text + ex.a_data + ex.a_bss);
		
		file->f_op->read(file, (char *)start_addr,
			ex.a_text + ex.a_data, &pos);
		flush_icache_range((unsigned long) start_addr,
				   (unsigned long) start_addr + ex.a_text + ex.a_data);

		retval = 0;
		goto out;
	}
	/* Now use mmap to map the library into memory. */
	down(&current->mm->mmap_sem);
	error = do_mmap(file, start_addr, ex.a_text + ex.a_data,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE,
			N_TXTOFF(ex));
	up(&current->mm->mmap_sem);
	retval = error;
	if (error != start_addr)
		goto out;

	len = PAGE_ALIGN(ex.a_text + ex.a_data);
	bss = ex.a_text + ex.a_data + ex.a_bss;
	if (bss > len) {
		error = do_brk(start_addr + len, bss - len);
		retval = error;
		if (error != start_addr + len)
			goto out;
	}
	retval = 0;
out:
	return retval;
}

static int __init init_aout_binfmt(void)
{
	return register_binfmt(&aout_format);
}

static void __exit exit_aout_binfmt(void)
{
	unregister_binfmt(&aout_format);
}

EXPORT_NO_SYMBOLS;

module_init(init_aout_binfmt);
module_exit(exit_aout_binfmt);
