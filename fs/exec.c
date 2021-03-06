/*
 *  linux/fs/exec.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * #!-checking implemented by tytso.
 */
/*
 * Demand-loading implemented 01.12.91 - no need to read anything but
 * the header into memory. The inode of the executable is put into
 * "current->executable", and page faults do the actual loading. Clean.
 *
 * Once more I can proudly say that linux stood up to being changed: it
 * was less than 2 hours work to get demand-loading completely implemented.
 *
 * Demand loading changed July 1993 by Eric Youngdale.   Use mmap instead,
 * current->executable is only used by the procfs.  This allows a dispatch
 * table to check for several different types  of binary formats.  We keep
 * trying until we recognize the file or we run out of supported binary
 * formats. 
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/a.out.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#define __NO_VERSION__
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif

static struct linux_binfmt *formats;
static rwlock_t binfmt_lock = RW_LOCK_UNLOCKED;

int register_binfmt(struct linux_binfmt * fmt)
{
	struct linux_binfmt ** tmp = &formats;

	if (!fmt)
		return -EINVAL;
	if (fmt->next)
		return -EBUSY;
	write_lock(&binfmt_lock);
	while (*tmp) {
		if (fmt == *tmp) {
			write_unlock(&binfmt_lock);
			return -EBUSY;
		}
		tmp = &(*tmp)->next;
	}
	fmt->next = formats;
	formats = fmt;
	write_unlock(&binfmt_lock);
	return 0;	
}

int unregister_binfmt(struct linux_binfmt * fmt)
{
	struct linux_binfmt ** tmp = &formats;

	write_lock(&binfmt_lock);
	while (*tmp) {
		if (fmt == *tmp) {
			*tmp = fmt->next;
			write_unlock(&binfmt_lock);
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&binfmt_lock);
	return -EINVAL;
}

static inline void put_binfmt(struct linux_binfmt * fmt)
{
	if (fmt->module)
		__MOD_DEC_USE_COUNT(fmt->module);
}

/*
 * Note that a shared library must be both readable and executable due to
 * security reasons.
 *
 * Also note that we take the address to load from from the file itself.
 */
asmlinkage long sys_uselib(const char * library)
{
	struct file * file;
	struct nameidata nd;
	int error;

	error = user_path_walk(library, &nd);
	if (error)
		goto out;

	error = -EINVAL;
	if (!S_ISREG(nd.dentry->d_inode->i_mode))
		goto exit;

	error = permission(nd.dentry->d_inode, MAY_READ | MAY_EXEC);
	if (error)
		goto exit;

	file = dentry_open(nd.dentry, nd.mnt, O_RDONLY);
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;

	error = -ENOEXEC;
	if(file->f_op && file->f_op->read) {
		struct linux_binfmt * fmt;

		read_lock(&binfmt_lock);
		for (fmt = formats ; fmt ; fmt = fmt->next) {
			if (!fmt->load_shlib)
				continue;
			if (!try_inc_mod_count(fmt->module))
				continue;
			read_unlock(&binfmt_lock);
			error = fmt->load_shlib(file);
			read_lock(&binfmt_lock);
			put_binfmt(fmt);
			if (error != -ENOEXEC)
				break;
		}
		read_unlock(&binfmt_lock);
	}
	fput(file);
out:
  	return error;
exit:
	path_release(&nd);
	goto out;
}

/*
 * count() counts the number of arguments/envelopes
 */
static int count(char ** argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			char * p;
			int error;

			error = get_user(p,argv);
			if (error)
				return error;
			if (!p)
				break;
			argv++;
			if(++i > max)
				return -E2BIG;
		}
	}
	return i;
}

/*
 * 'copy_strings()' copies argument/envelope strings from user
 * memory to free pages in kernel mem. These are in a format ready
 * to be put directly into the top of new user memory.
 */
int copy_strings(int argc,char ** argv, struct linux_binprm *bprm) 
{
	while (argc-- > 0) {
		char *str;
		int len;
		unsigned long pos;

		if (get_user(str, argv+argc) || !str || !(len = strnlen_user(str, bprm->p))) 
			return -EFAULT;
		if (bprm->p < len) 
			return -E2BIG; 

		bprm->p -= len;
		/* XXX: add architecture specific overflow check here. */ 

		pos = bprm->p;
		while (len > 0) {
			char *kaddr;
			int i, new, err;
			struct page *page;
			int offset, bytes_to_copy;

			offset = pos % PAGE_SIZE;
			i = pos/PAGE_SIZE;
			page = bprm->page[i];
			new = 0;
			if (!page) {
				page = alloc_page(GFP_HIGHUSER);
				bprm->page[i] = page;
				if (!page)
					return -ENOMEM;
				new = 1;
			}
			kaddr = kmap(page);

			if (new && offset)
				memset(kaddr, 0, offset);
			bytes_to_copy = PAGE_SIZE - offset;
			if (bytes_to_copy > len) {
				bytes_to_copy = len;
				if (new)
					memset(kaddr+offset+len, 0, PAGE_SIZE-offset-len);
			}
			err = copy_from_user(kaddr + offset, str, bytes_to_copy);
			kunmap(page);

			if (err)
				return -EFAULT; 

			pos += bytes_to_copy;
			str += bytes_to_copy;
			len -= bytes_to_copy;
		}
	}
	return 0;
}

/*
 * Like copy_strings, but get argv and its values from kernel memory.
 */
int copy_strings_kernel(int argc,char ** argv, struct linux_binprm *bprm)
{
	int r;
	mm_segment_t oldfs = get_fs();
	set_fs(KERNEL_DS); 
	r = copy_strings(argc, argv, bprm);
	set_fs(oldfs);
	return r; 
}

/*
 * This routine is used to map in a page into an address space: needed by
 * execve() for the initial stack and environment pages.
 */
void put_dirty_page(struct task_struct * tsk, struct page *page, unsigned long address)
{
	pgd_t * pgd;
	pmd_t * pmd;
	pte_t * pte;

	if (page_count(page) != 1)
		printk("mem_map disagrees with %p at %08lx\n", page, address);
	pgd = pgd_offset(tsk->mm, address);
	pmd = pmd_alloc(pgd, address);
	if (!pmd) {
		__free_page(page);
		force_sig(SIGKILL, tsk);
		return;
	}
	pte = pte_alloc(pmd, address);
	if (!pte) {
		__free_page(page);
		force_sig(SIGKILL, tsk);
		return;
	}
	if (!pte_none(*pte)) {
		pte_ERROR(*pte);
		__free_page(page);
		return;
	}
	flush_dcache_page(page);
	flush_page_to_ram(page);
	set_pte(pte, pte_mkdirty(pte_mkwrite(mk_pte(page, PAGE_COPY))));
/* no need for flush_tlb */
}


//进程的用户空间中地址最高处为堆栈区,这里的常数STACK_TOP就是TASK_SIZE,也就是3GB.
//堆栈区的顶部为一个数组,数组中的每一个元素都是一个页面.数组的大小为MAX_ARG_PAGES,
//而实际映射的页面数量则取决于这些执行参数和环境变量的数量.
int setup_arg_pages(struct linux_binprm *bprm)
{
	unsigned long stack_base;
	struct vm_area_struct *mpnt;
	int i;

	stack_base = STACK_TOP - MAX_ARG_PAGES*PAGE_SIZE;

	bprm->p += stack_base;
	if (bprm->loader)
		bprm->loader += stack_base;
	bprm->exec += stack_base;

	mpnt = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!mpnt) 
		return -ENOMEM; 
	
	down(&current->mm->mmap_sem);
	{
		mpnt->vm_mm = current->mm;
		mpnt->vm_start = PAGE_MASK & (unsigned long) bprm->p;
		mpnt->vm_end = STACK_TOP;
		mpnt->vm_page_prot = PAGE_COPY;
		mpnt->vm_flags = VM_STACK_FLAGS;
		mpnt->vm_ops = NULL;
		mpnt->vm_pgoff = 0;
		mpnt->vm_file = NULL;
		mpnt->vm_private_data = (void *) 0;
		insert_vm_struct(current->mm, mpnt);
		current->mm->total_vm = (mpnt->vm_end - mpnt->vm_start) >> PAGE_SHIFT;
	} 

	for (i = 0 ; i < MAX_ARG_PAGES ; i++) {
		struct page *page = bprm->page[i];
		if (page) {
			bprm->page[i] = NULL;
			current->mm->rss++;
			put_dirty_page(current,page,stack_base);
		}
		stack_base += PAGE_SIZE;
	}
	up(&current->mm->mmap_sem);
	
	return 0;
}

struct file *open_exec(const char *name)
{
	struct nameidata nd;
	struct inode *inode;
	struct file *file;
	int err = 0;

	if (path_init(name, LOOKUP_FOLLOW|LOOKUP_POSITIVE, &nd))
		err = path_walk(name, &nd);
	file = ERR_PTR(err);
	if (!err) {
		inode = nd.dentry->d_inode;
		file = ERR_PTR(-EACCES);
		if (!IS_NOEXEC(inode) && S_ISREG(inode->i_mode)) {
			int err = permission(inode, MAY_EXEC);
			file = ERR_PTR(err);
			if (!err) {
				file = dentry_open(nd.dentry, nd.mnt, O_RDONLY);
				if (!IS_ERR(file)) {
					err = deny_write_access(file);
					if (err) {
						fput(file);
						file = ERR_PTR(err);
					}
				}
out:
				return file;
			}
		}
		path_release(&nd);
	}
	goto out;
}

int kernel_read(struct file *file, unsigned long offset,
	char * addr, unsigned long count)
{
	mm_segment_t old_fs;
	loff_t pos = offset;
	int result = -ENOSYS;

	if (!file->f_op->read)
		goto fail;
	old_fs = get_fs();
	set_fs(get_ds());
	result = file->f_op->read(file, addr, count, &pos);
	set_fs(old_fs);
fail:
	return result;
}

static int exec_mmap(void)
{
	struct mm_struct * mm, * old_mm;

//同样,子进程的用户空间可能是父进程用户空间的复制品.也可能只是通过一个指针来共享父进程的用户空间.这一点只要检查一下对用户空间,也就是current->mm的共享计数就知道了.
//当共享计数为１时，表明对此空间的使用是独占的,也就是说这是从父进程复制过来的.那就要先释放mm_struct数据结构以下的所有vm_area_struct数据结构(但是不包括mm_struct结构本身)
//并且将页面表中的表项都设置为０.
	old_mm = current->mm;
	if (old_mm && atomic_read(&old_mm->mm_users) == 1) {
		flush_cache_mm(old_mm);
        //这里只是以防万一.
		mm_release();
		exit_mmap(old_mm);
		flush_tlb_mm(old_mm);
		return 0;
	}
//当这里，就表示子进程的用户空间是通过指针共享而不是复制的,或者根本就没有用户空间,那就不需要调用exit_mmap()释放代表用户空间的那些数据结构了.
//但是,此时要为子进程分配一个mm_struct数据结构以及页面目录,使得稍后可以在此基础上建立起子进程的用户空间.

	mm = mm_alloc();
	if (mm) {
		struct mm_struct *active_mm = current->active_mm;

		if (init_new_context(current, mm)) {
			mmdrop(mm);
			return -ENOMEM;
		}

		/* Add it to the list of mm's */
		spin_lock(&mmlist_lock);
		list_add(&mm->mmlist, &init_mm.mmlist);
		spin_unlock(&mmlist_lock);

		task_lock(current);
		current->mm = mm;
		current->active_mm = mm;
		task_unlock(current);

//通过下面这个函数切换到这个新的用户空间
//在include/asm-i386/mmu_context.h

//在这里当前进程的用户空间切换到了新分配mm_struct数据结构所代表的空间了.
//但是现在新的“用户空间"实际上只是一个框架,一个"空壳",里面一个页面也没有.另一方面,现在是在内核中运行,所以用户空间的切换对目前的运行无影响.
		activate_mm(active_mm, mm);
//从此,原来的用户空间就与当前进程无关了.也就是说,当前进程最终放弃了对原来用户空间的共享.这时候执行mm_release将父进程唤醒.
//对于父进程的用户空间,当然要减少它的共享计数。
		mm_release();
		if (old_mm) {
			if (active_mm != old_mm) BUG();
			mmput(old_mm);
			return 0;
		}
//这是一个特殊的情况.就是当子进程进入exec_mmap时,其task_struct中的mm_struct指针mm为0,也就是没有用户空间(所以是内核线程).但是,另一个mm_struct结构指针active_mm却不是0,而这时候active_mm是暂借的.在调度其停止运行时,会将该指针设置为0. 
//也就是说,一个内核线程在受到调度运行时要"借用"在它之前运行的那个进程的active_mm,因而要递增这个mm_struct结构的使用计数,而现在,已经为内核线程分配了它自己的mm_struct结构,使其升格成为了进程,就不再使用借来的active_mm了.所以要调用mmdrop,递减其使用计数.
		mmdrop(active_mm);
		return 0;
	}
	return -ENOMEM;
}

/*
 * This function makes sure the current process has its own signal table,
 * so that flush_signal_handlers can later reset the handlers without
 * disturbing other processes.  (Other processes might share the signal
 * table via the CLONE_SIGNAL option to clone().)
 */
 
static inline int make_private_signals(void)
{
	struct signal_struct * newsig;

	if (atomic_read(&current->sig->count) <= 1)
		return 0;
	newsig = kmem_cache_alloc(sigact_cachep, GFP_KERNEL);
	if (newsig == NULL)
		return -ENOMEM;
	spin_lock_init(&newsig->siglock);
	atomic_set(&newsig->count, 1);
	memcpy(newsig->action, current->sig->action, sizeof(newsig->action));
	spin_lock_irq(&current->sigmask_lock);
	current->sig = newsig;
	spin_unlock_irq(&current->sigmask_lock);
	return 0;
}
	
/*
 * If make_private_signals() made a copy of the signal table, decrement the
 * refcount of the original table, and free it if necessary.
 * We don't do that in make_private_signals() so that we can back off
 * in flush_old_exec() if an error occurs after calling make_private_signals().
 */

static inline void release_old_signals(struct signal_struct * oldsig)
{
	if (current->sig == oldsig)
		return;
	if (atomic_dec_and_test(&oldsig->count))
		kmem_cache_free(sigact_cachep, oldsig);
}

/*
 * These functions flushes out all traces of the currently running executable
 * so that a new one can be started
 */

//在进程的tast_struct中的struct files_struct保存中已打开文件的信息.
//在这个结构中,有个位图close_on_exec,里面存储着表示那些文件在执行一个新目标程序时应予关闭的信息.
//flush_old_files就是要根据这个位图的指示将这些文件关闭,并且将此位图清成全0.


//一般来说,进程的开头三个文件,即fd为0,1,和2(或stdin, stdout以及stderr)的已打开文件是不关闭的;
//其它的已打开文件则都应该关闭,但是也可以通过ioctl系统调用来加以改变.
static inline void flush_old_files(struct files_struct * files)
{
	long j = -1;

	write_lock(&files->file_lock);
	for (;;) {
		unsigned long set, i;

		j++;
		i = j * __NFDBITS;
		if (i >= files->max_fds || i >= files->max_fdset)
			break;
		set = files->close_on_exec->fds_bits[j];
		if (!set)
			continue;
		files->close_on_exec->fds_bits[j] = 0;
		write_unlock(&files->file_lock);
		for ( ; set ; i++,set >>= 1) {
			if (set & 1) {
				sys_close(i);
			}
		}
		write_lock(&files->file_lock);

	}
	write_unlock(&files->file_lock);
}

/*
 * An execve() will automatically "de-thread" the process.
 * Note: we don't have to hold the tasklist_lock to test
 * whether we migth need to do this. If we're not part of
 * a thread group, there is no way we can become one
 * dynamically. And if we are, we only need to protect the
 * unlink - even if we race with the last other thread exit,
 * at worst the list_del_init() might end up being a no-op.
 */
static inline void de_thread(struct task_struct *tsk)
{
	if (!list_empty(&tsk->thread_group)) {
		write_lock_irq(&tasklist_lock);
		list_del_init(&tsk->thread_group);
		write_unlock_irq(&tasklist_lock);
	}

	/* Minor oddity: this might stay the same. */
	tsk->tgid = tsk->pid;
}

int flush_old_exec(struct linux_binprm * bprm)
{
	char * name;
	int i, ch, retval;
	struct signal_struct * oldsig;

	/*
	 * Make sure we have a private signal table
	 */
//首先是进程的信号(软中断)处理表. 一个进程的信号处理表就好像一个系统中的中断向量表.
//当子进程被创建出来时,父进程的信号处理表可能已经复制过来了,但也可能只是把父进程的信号处理表指针复制了过来.而通过这指针来共享父进程的信号处理表.

//现在,子进程最终要”自立门户”了,所以要看一下如果还在共享父进程的信号处理表的话,就要把它复制过来.正因为这样,make_private_signals的代码与do_fork中调用的copy_sighand基本相同.
	oldsig = current->sig;
	retval = make_private_signals();
	if (retval) goto flush_failed;

	/* 
	 * Release all of the old mmap stuff
	 */
//这里很关键了,从父进程继承下来的用户空间就是在这里放弃的.
	retval = exec_mmap();
	if (retval) goto mmap_failed;

	/* This is the point of no return */
//当前进程原来可能是通过指针共享父进程的信号处理表的,而现在有了自己的独立的信号处理表,所以也要递减父进程信号处理表的共享计数
	release_old_signals(oldsig);

	current->sas_ss_sp = current->sas_ss_size = 0;

	if (current->euid == current->uid && current->egid == current->gid)
		current->dumpable = 1;
	name = bprm->filename;
	for (i=0; (ch = *(name++)) != '\0';) {
		if (ch == '/')
			i = 0;
		else
			if (i < 15)
				current->comm[i++] = ch;
	}
	current->comm[i] = '\0';

	flush_thread();

//如果"当前进程”原来只是一个线程,那么它的task_struct结构中的thread_group挂入由其父进程为首的"线程组"队列.
//现在它已经通过execve升级为进程,放弃了对父进程用户空间的共享.所以就要通过de_thread从这个线程组中脱离出来.
	de_thread(current);

	if (bprm->e_uid != current->euid || bprm->e_gid != current->egid || 
	    permission(bprm->file->f_dentry->d_inode,MAY_READ))
		current->dumpable = 0;

	/* An exec changes our domain. We are no longer part of the thread
	   group */
	   
	current->self_exec_id++;
		
//进程的信号处理表就好像是个中断向量表,但是,这里还有个重要不同,就是信号处理表则还可以有对各种信号预设的(default)响应,并不一定非要指向一个服务程序.
//当把信号处理表从父进程复制过来时,其中每个表项的值有三种可能:一种可能是SIG_IGN,表示不理睬;第二种是SIG_DFL,表示采取预设的响应方式(例如收到SIGQUIT就exit);
//第三种就是指向一个用户空间的子程序.
//但是,现在整个用户空间都已经放弃了,怎么还能让信号处理表项指向用户空间的子程序呢? 所以还得检查一遍,将指向服务程序的表项改成SIG_DFL.这就是由下面的程序完成的.
//在kernel/signal.c中	
	flush_signal_handlers(current);

//对原有已打开文件的处理
	flush_old_files(current->files);

	return 0;

mmap_failed:
flush_failed:
	spin_lock_irq(&current->sigmask_lock);
	if (current->sig != oldsig)
		kfree(current->sig);
	current->sig = oldsig;
	spin_unlock_irq(&current->sigmask_lock);
	return retval;
}

/*
 * We mustn't allow tracing of suid binaries, unless
 * the tracer has the capability to trace anything..
 */
static inline int must_not_trace_exec(struct task_struct * p)
{
	return (p->ptrace & PT_PTRACED) && !cap_raised(p->p_pptr->cap_effective, CAP_SYS_PTRACE);
}

/* 
 * Fill the binprm structure from the inode. 
 * Check permissions, then read the first 128 (BINPRM_BUF_SIZE) bytes
 */
//读128B到bprm的缓冲区
int prepare_binprm(struct linux_binprm *bprm)
{
	int mode;
	struct inode * inode = bprm->file->f_dentry->d_inode;

//在读之前要先检查当前进程是否有这个权利,以及该文件是否有可执行属性.
//如果可执行文件具有"set uid"特性,则要做相应的设置.

	mode = inode->i_mode;
	/* Huh? We had already checked for MAY_EXEC, WTF do we check this? */
	if (!(mode & 0111))	/* with at least _one_ execute bit set */
		return -EACCES;
	if (bprm->file->f_op == NULL)
		return -EACCES;

	bprm->e_uid = current->euid;
	bprm->e_gid = current->egid;

	if(!IS_NOSUID(inode)) {
		/* Set-uid? */
		if (mode & S_ISUID)
			bprm->e_uid = inode->i_uid;

		/* Set-gid? */
		/*
		 * If setgid is set but no group execute bit then this
		 * is a candidate for mandatory locking, not a setgid
		 * executable.
		 */
		if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
			bprm->e_gid = inode->i_gid;
	}

	/* We don't have VFS support for capabilities yet */
	cap_clear(bprm->cap_inheritable);
	cap_clear(bprm->cap_permitted);
	cap_clear(bprm->cap_effective);

	/*  To support inheritance of root-permissions and suid-root
         *  executables under compatibility mode, we raise all three
         *  capability sets for the file.
         *
         *  If only the real uid is 0, we only raise the inheritable
         *  and permitted sets of the executable file.
         */

	if (!issecure(SECURE_NOROOT)) {
		if (bprm->e_uid == 0 || current->uid == 0) {
			cap_set_full(bprm->cap_inheritable);
			cap_set_full(bprm->cap_permitted);
		}
		if (bprm->e_uid == 0) 
			cap_set_full(bprm->cap_effective);
	}

	memset(bprm->buf,0,BINPRM_BUF_SIZE);
	return kernel_read(bprm->file,0,bprm->buf,BINPRM_BUF_SIZE);
}

/*
 * This function is used to produce the new IDs and capabilities
 * from the old ones and the file's capabilities.
 *
 * The formula used for evolving capabilities is:
 *
 *       pI' = pI
 * (***) pP' = (fP & X) | (fI & pI)
 *       pE' = pP' & fE          [NB. fE is 0 or ~0]
 *
 * I=Inheritable, P=Permitted, E=Effective // p=process, f=file
 * ' indicates post-exec(), and X is the global 'cap_bset'.
 *
 */

void compute_creds(struct linux_binprm *bprm) 
{
	kernel_cap_t new_permitted, working;
	int do_unlock = 0;

	new_permitted = cap_intersect(bprm->cap_permitted, cap_bset);
	working = cap_intersect(bprm->cap_inheritable,
				current->cap_inheritable);
	new_permitted = cap_combine(new_permitted, working);

	if (bprm->e_uid != current->uid || bprm->e_gid != current->gid ||
	    !cap_issubset(new_permitted, current->cap_permitted)) {
                current->dumpable = 0;
		
		lock_kernel();
		if (must_not_trace_exec(current)
		    || atomic_read(&current->fs->count) > 1
		    || atomic_read(&current->files->count) > 1
		    || atomic_read(&current->sig->count) > 1) {
			if(!capable(CAP_SETUID)) {
				bprm->e_uid = current->uid;
				bprm->e_gid = current->gid;
			}
			if(!capable(CAP_SETPCAP)) {
				new_permitted = cap_intersect(new_permitted,
							current->cap_permitted);
			}
		}
		do_unlock = 1;
	}


	/* For init, we want to retain the capabilities set
         * in the init_task struct. Thus we skip the usual
         * capability rules */
	if (current->pid != 1) {
		current->cap_permitted = new_permitted;
		current->cap_effective =
			cap_intersect(new_permitted, bprm->cap_effective);
	}
	
        /* AUD: Audit candidate if current->cap_effective is set */

        current->suid = current->euid = current->fsuid = bprm->e_uid;
        current->sgid = current->egid = current->fsgid = bprm->e_gid;

	if(do_unlock)
		unlock_kernel();
	current->keep_capabilities = 0;
}


void remove_arg_zero(struct linux_binprm *bprm)
{
	if (bprm->argc) {
		unsigned long offset;
		char * kaddr;
		struct page *page;

		offset = bprm->p % PAGE_SIZE;
		goto inside;

		while (bprm->p++, *(kaddr+offset++)) {
			if (offset != PAGE_SIZE)
				continue;
			offset = 0;
			kunmap(page);
inside:
			page = bprm->page[bprm->p/PAGE_SIZE];
			kaddr = kmap(page);
		}
		kunmap(page);
		bprm->argc--;
	}
}

/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
//先来介绍一个大概
//在内核中有一个队列，叫做formats,挂在此队列中的成员是代表着各种可执行文件格式的"代理人".
//每个成员只认识并且处理一种特定格式的可执行文件的运行.
//那么现在就有formats队列中的成员来逐个认领.
//要是都不认识呢？那就呀根据文件头部信息再找找看,是否有为此种格式设计,仍是作为可动态安装模块实现的“代理人"存在于文件系统中.
//如果有的话,就把这模块安装进来并且将其挂入到formats队列中.然后让formats队列中的各个”代理人“再来认一次.
int search_binary_handler(struct linux_binprm *bprm,struct pt_regs *regs)
{
	int try,retval=0;
	struct linux_binfmt *fmt;
#ifdef __alpha__
	/* handle /sbin/loader.. */
	{
	    struct exec * eh = (struct exec *) bprm->buf;

	    if (!bprm->loader && eh->fh.f_magic == 0x183 &&
		(eh->fh.f_flags & 0x3000) == 0x3000)
	    {
		char * dynloader[] = { "/sbin/loader" };
		struct file * file;
		unsigned long loader;

		allow_write_access(bprm->file);
		fput(bprm->file);
		bprm->file = NULL;

	        loader = PAGE_SIZE*MAX_ARG_PAGES-sizeof(void *);

		file = open_exec(dynloader[0]);
		retval = PTR_ERR(file);
		if (IS_ERR(file))
			return retval;
		bprm->file = file;
		bprm->loader = loader;
		retval = prepare_binprm(bprm);
		if (retval<0)
			return retval;
		/* should call search_binary_handler recursively here,
		   but it does not matter */
	    }
	}
#endif
	for (try=0; try<2; try++) {
		read_lock(&binfmt_lock);
//内层的for循环就是对formats队列中的每个成员循环,让队列中的成员逐个试试他们的load_binary函数,看看是否能对上号,如果对上号,那就把目标文件装入并将其投入运行,再返回一个正数或者０.
//当cpu从系统调用退回时,该目标文件的执行就真正开始了.
//否则,如果不能辨识,或者在处理的过程中出了错,就返回一个负数. 

//出错代码-ENOEXEC表示只是对不上号,而并没有发生其他错误,所以循环回去,让队列中的下一个成员再来试试.
//但是如果出了错而又不是-ENOEXEC,那就表示对上号了,但是出了其他的错,这就不用再让其他的成员来试了.
		for (fmt = formats ; fmt ; fmt = fmt->next) {
			int (*fn)(struct linux_binprm *, struct pt_regs *) = fmt->load_binary;
			if (!fn)
				continue;
			if (!try_inc_mod_count(fmt->module))
				continue;
			read_unlock(&binfmt_lock);
			retval = fn(bprm, regs);
			if (retval >= 0) {
				put_binfmt(fmt);
				allow_write_access(bprm->file);
				if (bprm->file)
					fput(bprm->file);
				bprm->file = NULL;
				current->did_exec = 1;
				return retval;
			}
			read_lock(&binfmt_lock);
			put_binfmt(fmt);
			if (retval != -ENOEXEC)
				break;
			if (!bprm->file) {
				read_unlock(&binfmt_lock);
				return retval;
			}
		}
//内层循环结束后，如果失败的原因是-ENOEXEC，就说明队列中的所有成员都不认识目标文件的格式.
//这时候,如果内核支持动态安装模块,就根据目标文件的第２和第３字节生成一个binfmt模块名,通过request_module试着将相应的模块装入.
//外层的for循环共进行两次,正是为了在安装模块以后再来试一次.
		read_unlock(&binfmt_lock);
		if (retval != -ENOEXEC) {
			break;
#ifdef CONFIG_KMOD
		}else{
#define printable(c) (((c)=='\t') || ((c)=='\n') || (0x20<=(c) && (c)<=0x7e))
			char modname[20];
			if (printable(bprm->buf[0]) &&
			    printable(bprm->buf[1]) &&
			    printable(bprm->buf[2]) &&
			    printable(bprm->buf[3]))
				break; /* -ENOEXEC */
			sprintf(modname, "binfmt-%04x", *(unsigned short *)(&bprm->buf[2]));
			request_module(modname);
#endif
		}
	}
	return retval;
}


/*
 * sys_execve() executes a new program.
 */
int do_execve(char * filename, char ** argv, char ** envp, struct pt_regs * regs)
{
	struct linux_binprm bprm;
	struct file *file;
	int retval;
	int i;

//这里的file代表着读入可执行文件的上下文.
	file = open_exec(filename);

	retval = PTR_ERR(file);
	if (IS_ERR(file))
		return retval;

//目标文件打开后,下一步就要从文件中装入可执行程序了.
//内核中为可执行程序的装入定义了一个数据结构linux_binprm,以便将运行一个可执行文件时所需的信息组织在一起.


//每个参数的最大长度也定义为一个物理页面,所以bprm中有一个页面指针数组,数组的大小为允许的最大参数个数MAX_ARG_PAGES,目前这个常数定义为32.
//现在将bprm.p设置成这些页面的总和减去一个指针大小.因为第0个参数也就是argv[0]是可执行程序本身的路径名.
	bprm.p = PAGE_SIZE*MAX_ARG_PAGES-sizeof(void *);

//通过memset将这个指针数组初始化成全0.
	memset(bprm.page, 0, MAX_ARG_PAGES*sizeof(bprm.page[0])); 

	bprm.file = file;
	bprm.filename = filename;

//sh.bang的值说明可执行文件的性质,当可执行文件是一个shell过程,即shell脚本时,置1.而现在还不知道，所以暂且将其置为0,也就是先假定为二进制文件.
	bprm.sh_bang = 0;
	bprm.loader = 0;
	bprm.exec = 0;

//开始处理可执行文件的参数和环境变量

//注意这里的数组argv[]和envp[]是在用户空间而不在内核空间,所以计数的操作并不那么简单.
//count对字符串指针数组argv[]中的参数个数进行计数.而bprm.p/sizeof(void*)表示允许的最大值.
	if ((bprm.argc = count(argv, bprm.p / sizeof(void *))) < 0) {

//这里如果count失败,对目标文件执行一次allow_write_access操作,这个函数是与deny_write_access配对使用的,目的在于防止其他进程在读入可执行文件期间通过内存映射改变它的内容. deny_write_access是在
//打开可执行文件时在open_exec中调用的.
		allow_write_access(file);
		fput(file);
		return bprm.argc;
	}

	if ((bprm.envc = count(envp, bprm.p / sizeof(void *))) < 0) {
		allow_write_access(file);
		fput(file);
		return bprm.envc;
	}
//完成统计之后,进一步对数据结构bprm做准备,从可执行文件中读入开头的128B到linux_binprm的bprm中的缓冲区中.
	retval = prepare_binprm(&bprm);
	if (retval < 0) 
		goto out; 


//最后的准备工作就是把执行的参数,也就是argv[]以及运行的环境,也就是envp[],从用户空间拷贝到数据结构bprm中.
//其中第一个参数argv[0]就是可执行文件的路径名.已经在bprm.filename中了.所以用copy_strings_kernel从内核空间中拷贝.
//其他的就要用copy_strings从用户空间拷贝.


	retval = copy_strings_kernel(1, &bprm.filename, &bprm);
	if (retval < 0) 
		goto out; 

	bprm.exec = bprm.p;
	retval = copy_strings(bprm.envc, envp, &bprm);
	if (retval < 0) 
		goto out; 

	retval = copy_strings(bprm.argc, argv, &bprm);
	if (retval < 0) 
		goto out; 


//所有的准备工作都已经做完了,所有必要的信息都已经收集到了linux_binprm中了,接着下来就要装入并运行目标程序了
	retval = search_binary_handler(&bprm,regs);
	if (retval >= 0)
		/* execve success */
		return retval;

out:
	/* Something went wrong, return the inode and free the argument pages*/
	allow_write_access(bprm.file);
	if (bprm.file)
		fput(bprm.file);

	for (i = 0 ; i < MAX_ARG_PAGES ; i++) {
		struct page * page = bprm.page[i];
		if (page)
			__free_page(page);
	}

	return retval;
}

void set_binfmt(struct linux_binfmt *new)
{
	struct linux_binfmt *old = current->binfmt;
//如果当前进程原来执行的代码格式与新的代码格式都不是由可安装模块支持,则实际上只剩下一行语句,那就是current->binfmt
	if (new && new->module)
		__MOD_INC_USE_COUNT(new->module);
	current->binfmt = new;
	if (old && old->module)
		__MOD_DEC_USE_COUNT(old->module);
}

int do_coredump(long signr, struct pt_regs * regs)
{
	struct linux_binfmt * binfmt;
	char corename[6+sizeof(current->comm)];
	struct file * file;
	struct inode * inode;

	lock_kernel();
	binfmt = current->binfmt;
	if (!binfmt || !binfmt->core_dump)
		goto fail;
	if (!current->dumpable || atomic_read(&current->mm->mm_users) != 1)
		goto fail;
	current->dumpable = 0;
	if (current->rlim[RLIMIT_CORE].rlim_cur < binfmt->min_coredump)
		goto fail;

	memcpy(corename,"core.", 5);
#if 0
	memcpy(corename+5,current->comm,sizeof(current->comm));
#else
	corename[4] = '\0';
#endif
	file = filp_open(corename, O_CREAT | 2 | O_TRUNC | O_NOFOLLOW, 0600);
	if (IS_ERR(file))
		goto fail;
	inode = file->f_dentry->d_inode;
	if (inode->i_nlink > 1)
		goto close_fail;	/* multiple links - don't dump */

	if (!S_ISREG(inode->i_mode))
		goto close_fail;
	if (!file->f_op)
		goto close_fail;
	if (!file->f_op->write)
		goto close_fail;
	if (!binfmt->core_dump(signr, regs, file))
		goto close_fail;
	unlock_kernel();
	filp_close(file, NULL);
	return 1;

close_fail:
	filp_close(file, NULL);
fail:
	unlock_kernel();
	return 0;
}
