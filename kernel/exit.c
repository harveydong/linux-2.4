/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/config.h>
#include <linux/malloc.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#ifdef CONFIG_BSD_PROCESS_ACCT
#include <linux/acct.h>
#endif

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>

extern void sem_exit (void);
extern struct task_struct *child_reaper;

int getrusage(struct task_struct *, int, struct rusage *);

static void release_task(struct task_struct * p)
{
	if (p != current) {
#ifdef CONFIG_SMP
		/*
		 * Wait to make sure the process isn't on the
		 * runqueue (active on some other CPU still)
		 */
		for (;;) {
			task_lock(p);
			if (!p->has_cpu)
				break;
			task_unlock(p);
			do {
				barrier();
			} while (p->has_cpu);
		}
		task_unlock(p);
#endif
		atomic_dec(&p->user->processes);
		free_uid(p->user);
		unhash_process(p);

		release_thread(p);
		current->cmin_flt += p->min_flt + p->cmin_flt;
		current->cmaj_flt += p->maj_flt + p->cmaj_flt;
		current->cnswap += p->nswap + p->cnswap;
		/*
		 * Potentially available timeslices are retrieved
		 * here - this way the parent does not get penalized
		 * for creating too many processes.
		 *
		 * (this cannot be used to artificially 'generate'
		 * timeslices, because any timeslice recovered here
		 * was given away by the parent in the first place.)
		 */
		current->counter += p->counter;
		if (current->counter >= MAX_COUNTER)
			current->counter = MAX_COUNTER;
		free_task_struct(p);
	} else {
		printk("task releasing itself\n");
	}
}

/*
 * This checks not only the pgrp, but falls back on the pid if no
 * satisfactory pgrp is found. I dunno - gdb doesn't work correctly
 * without this...
 */
int session_of_pgrp(int pgrp)
{
	struct task_struct *p;
	int fallback;

	fallback = -1;
	read_lock(&tasklist_lock);
	for_each_task(p) {
 		if (p->session <= 0)
 			continue;
		if (p->pgrp == pgrp) {
			fallback = p->session;
			break;
		}
		if (p->pid == pgrp)
			fallback = p->session;
	}
	read_unlock(&tasklist_lock);
	return fallback;
}

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are
 * to receive a SIGHUP and a SIGCONT.
 *
 * "I ask you, have you ever known what it is to be an orphan?"
 */
static int will_become_orphaned_pgrp(int pgrp, struct task_struct * ignored_task)
{
	struct task_struct *p;

	read_lock(&tasklist_lock);
	for_each_task(p) {
		if ((p == ignored_task) || (p->pgrp != pgrp) ||
		    (p->state == TASK_ZOMBIE) ||
		    (p->p_pptr->pid == 1))
			continue;
		if ((p->p_pptr->pgrp != pgrp) &&
		    (p->p_pptr->session == p->session)) {
			read_unlock(&tasklist_lock);
 			return 0;
		}
	}
	read_unlock(&tasklist_lock);
	return 1;	/* (sighing) "Often!" */
}

int is_orphaned_pgrp(int pgrp)
{
	return will_become_orphaned_pgrp(pgrp, 0);
}

static inline int has_stopped_jobs(int pgrp)
{
	int retval = 0;
	struct task_struct * p;

	read_lock(&tasklist_lock);
	for_each_task(p) {
		if (p->pgrp != pgrp)
			continue;
		if (p->state != TASK_STOPPED)
			continue;
		retval = 1;
		break;
	}
	read_unlock(&tasklist_lock);
	return retval;
}

/*
 * When we die, we re-parent all our children.
 * Try to give them to another thread in our process
 * group, and if no such member exists, give it to
 * the global child reaper process (ie "init")
 */
static inline void forget_original_parent(struct task_struct * father)
{
	struct task_struct * p, *reaper;

	read_lock(&tasklist_lock);

	/* Next in our thread group */
	reaper = next_thread(father);
	if (reaper == father)
		reaper = child_reaper;

	for_each_task(p) {
		if (p->p_opptr == father) {
			/* We dont want people slaying init */
			p->exit_signal = SIGCHLD;
			p->self_exec_id++;
			p->p_opptr = reaper;
			if (p->pdeath_signal) send_sig(p->pdeath_signal, p, 0);
		}
	}
	read_unlock(&tasklist_lock);
}

static inline void close_files(struct files_struct * files)
{
	int i, j;

	j = 0;
	for (;;) {
		unsigned long set;
		i = j * __NFDBITS;
		if (i >= files->max_fdset || i >= files->max_fds)
			break;
		set = files->open_fds->fds_bits[j++];
		while (set) {
			if (set & 1) {
				struct file * file = xchg(&files->fd[i], NULL);
				if (file)
					filp_close(file, files);
			}
			i++;
			set >>= 1;
		}
	}
}

void put_files_struct(struct files_struct *files)
{
	if (atomic_dec_and_test(&files->count)) {
		close_files(files);
		/*
		 * Free the fd and fdset arrays if we expanded them.
		 */
		if (files->fd != &files->fd_array[0])
			free_fd_array(files->fd, files->max_fds);
		if (files->max_fdset > __FD_SETSIZE) {
			free_fdset(files->open_fds, files->max_fdset);
			free_fdset(files->close_on_exec, files->max_fdset);
		}
		kmem_cache_free(files_cachep, files);
	}
}

static inline void __exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

void exit_files(struct task_struct *tsk)
{
	__exit_files(tsk);
}

static inline void __put_fs_struct(struct fs_struct *fs)
{
	/* No need to hold fs->lock if we are killing it */
	if (atomic_dec_and_test(&fs->count)) {
		dput(fs->root);
		mntput(fs->rootmnt);
		dput(fs->pwd);
		mntput(fs->pwdmnt);
		if (fs->altroot) {
			dput(fs->altroot);
			mntput(fs->altrootmnt);
		}
		kmem_cache_free(fs_cachep, fs);
	}
}

void put_fs_struct(struct fs_struct *fs)
{
	__put_fs_struct(fs);
}

static inline void __exit_fs(struct task_struct *tsk)
{
	struct fs_struct * fs = tsk->fs;

	if (fs) {
		task_lock(tsk);
		tsk->fs = NULL;
		task_unlock(tsk);
		__put_fs_struct(fs);
	}
}

void exit_fs(struct task_struct *tsk)
{
	__exit_fs(tsk);
}

/*
 * We can use these to temporarily drop into
 * "lazy TLB" mode and back.
 */
struct mm_struct * start_lazy_tlb(void)
{
	struct mm_struct *mm = current->mm;
	current->mm = NULL;
	/* active_mm is still 'mm' */
	atomic_inc(&mm->mm_count);
	enter_lazy_tlb(mm, current, smp_processor_id());
	return mm;
}

void end_lazy_tlb(struct mm_struct *mm)
{
	struct mm_struct *active_mm = current->active_mm;

	current->mm = mm;
	if (mm != active_mm) {
		current->active_mm = mm;
		activate_mm(active_mm, mm);
	}
	mmdrop(active_mm);
}

/*
 * Turn us into a lazy TLB process if we
 * aren't already..
 */
static inline void __exit_mm(struct task_struct * tsk)
{
	struct mm_struct * mm = tsk->mm;

//在fork和execve中看到,当do_fork时标志位CLONE_VFORK为1时,父进程在睡眠,等待子进程在一个信号量上执行一次up操作以后才能回到用户空间运行.
//而子进程必须在释放其用户存储空间时执行这个操作,所以这里调用mm_release.
	mm_release();
	if (mm) {
		atomic_inc(&mm->mm_count);
		if (mm != tsk->active_mm) BUG();
		/* more a memory barrier than a real lock */
		task_lock(tsk);
		tsk->mm = NULL;
		task_unlock(tsk);
		enter_lazy_tlb(mm, current, smp_processor_id());
//实际的存储空间释放是调用mmput完成的.
		mmput(mm);
	}
}

void exit_mm(struct task_struct *tsk)
{
	__exit_mm(tsk);
}

/*
 * Send signals to all our closest relatives so that they know
 * to properly mourn us..
 */
static void exit_notify(void)
{
	struct task_struct * p, *t;

//就像人一样,所谓父进程也有"生父"和"养父"之分.
//在task_struct结构中有个指针p_opptr指向其"original parent",就是生父.
//另外还有个指针p_pptr则指向其养父.
//一个进程在创建之初其生父和养父是一致的,所以两个指针指向同一个父进程.
//但是,在运行中p_pptr可以暂时地改变.这种改变发生在一个进程通过系统调用ptrace来跟踪另一个进程的时候,这时候被跟踪进程的p_pptr指针被设置成指向正在跟踪它的进程.
//那个进程就暂时成了被跟踪进程的"养父".

//如果一个进程在其子进程之前"去世"的话,就要把它的子进程托付给某个进程.那托付给谁呢?
//如果当前进程是一个线程,那就托付给同一线程组中的下一个线程,使子进程的p_opptr指向这个线程.否则,就只好托付给系统中的init进程,所以这init进程就好像是孤儿院.
//由此可见,所谓"original parent"也不是永远不变的,原因在于系统中的进程号pid以及用作task_struct结构的页面都是在周转使用的.

	forget_original_parent(current);
	/*
	 * Check to see if any process groups have become orphaned
	 * as a result of our exiting, and if they have any stopped
	 * jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 *
	 * Case i: Our father is in a different pgrp than we are
	 * and we were the only connection outside, so our pgrp
	 * is about to become orphaned.
	 */
	 
	t = current->p_pptr;
	
	if ((t->pgrp != current->pgrp) &&
	    (t->session == current->session) &&
	    will_become_orphaned_pgrp(current->pgrp, current) &&
	    has_stopped_jobs(current->pgrp)) {
		kill_pg(current->pgrp,SIGHUP,1);
		kill_pg(current->pgrp,SIGCONT,1);
	}

	/* Let father know we died 
	 *
	 * Thread signals are configurable, but you aren't going to use
	 * that to send signals to arbitary processes. 
	 * That stops right now.
	 *
	 * If the parent exec id doesn't match the exec id we saved
	 * when we started then we know the parent has changed security
	 * domain.
	 *
	 * If our self_exec id doesn't match our parent_exec_id then
	 * we have changed execution domain as these two values started
	 * the same after a fork.
	 *	
	 */
	
	if(current->exit_signal != SIGCHLD &&
	    ( current->parent_exec_id != t->self_exec_id  ||
	      current->self_exec_id != current->parent_exec_id) 
	    && !capable(CAP_KILL))
		current->exit_signal = SIGCHLD;


	/*
	 * This loop does two things:
	 *
  	 * A.  Make init inherit all the child processes
	 * B.  Check to see if any process groups have become orphaned
	 *	as a result of our exiting, and if they have any stopped
	 *	jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 */

	write_lock_irq(&tasklist_lock);
//当前进程的状态设置成TASK_ZOMBLE,表示进程的生命已经结束,从此不再接受调度.
//但是当前进程的残骸仍旧占着最低限度的资源.包括其task_struct数据结构和系统空间堆栈所在的连个页面.

	current->state = TASK_ZOMBIE;
	do_notify_parent(current, current->exit_signal);
	while (current->p_cptr != NULL) {
		p = current->p_cptr;
		current->p_cptr = p->p_osptr;
		p->p_ysptr = NULL;
		p->ptrace = 0;

		p->p_pptr = p->p_opptr;
		p->p_osptr = p->p_pptr->p_cptr;
		if (p->p_osptr)
			p->p_osptr->p_ysptr = p;
		p->p_pptr->p_cptr = p;
		if (p->state == TASK_ZOMBIE)
			do_notify_parent(p, p->exit_signal);
		/*
		 * process group orphan check
		 * Case ii: Our child is in a different pgrp
		 * than we are, and it was the only connection
		 * outside, so the child pgrp is now orphaned.
		 */
		if ((p->pgrp != current->pgrp) &&
		    (p->session == current->session)) {
			int pgrp = p->pgrp;

			write_unlock_irq(&tasklist_lock);
			if (is_orphaned_pgrp(pgrp) && has_stopped_jobs(pgrp)) {
				kill_pg(pgrp,SIGHUP,1);
				kill_pg(pgrp,SIGCONT,1);
			}
			write_lock_irq(&tasklist_lock);
		}
	}
	write_unlock_irq(&tasklist_lock);
}


//这里NORET_TYPE是在include/linux/kernle.h中定义为/**/,就是一个提醒作用.
//cpu在进入do_exit以后,当前进程就在中途寿终正寝,不会从这个函数返回.
NORET_TYPE void do_exit(long code)
{
	struct task_struct *tsk = current;

//所谓exit，只有进程(或线程)才谈得上,中断服务程序根本就不应该调用do_exit.
//在include/asm-i386/hardirq.h中
	if (in_interrupt())
		panic("Aiee, killing interrupt handler!");

//只要不是在中断上下文,就一定是在某个进程(或线程)的上下文中.
//但是,0号进程和1号进程,也就是"空转(idle)进程和“初始化(init)进程",是不允许退出的.所以接着要对当前进程的pid加以检查
	if (!tsk->pid)
		panic("Attempted to kill the idle task!");
	if (tsk->pid == 1)
		panic("Attempted to kill init!");
	tsk->flags |= PF_EXITING;

//进程在决定退出之前可能已经设置了实时定时器,也就是将其tast_struct中的成员real_timer挂入了内核中的定时器队列.
//现在进程即将退出系统,一来是这个定时器已经没有了存在的必要;二来进程的task_struct结构行将撤销,所以要将当前进程从定时器队列中脱离出来.
	del_timer_sync(&tsk->real_timer);

fake_volatile:
#ifdef CONFIG_BSD_PROCESS_ACCT
	acct_process(code);
#endif

//可想而知,进程在结束生命退出系统之前要释放其所有的资源.包括有存储空间、已打开的文件、工作目录、信号处理表等等.
//但是,还有一种资源是不”继承“的,所以在do_fork中不会看到,那就是进程在用户空间建立和使用的”信号量“. 如果在调用exit之前还有信号量尚未撤销,那就也要
//把它撤销.
	__exit_mm(tsk);

	lock_kernel();
//在ipc/sem.c中
	sem_exit();
	__exit_files(tsk);
	__exit_fs(tsk);
	exit_sighand(tsk);
	exit_thread();

	if (current->leader)
		disassociate_ctty(1);

	put_exec_domain(tsk->exec_domain);
	if (tsk->binfmt && tsk->binfmt->module)
		__MOD_DEC_USE_COUNT(tsk->binfmt->module);

	tsk->exit_code = code;

//调用该函数通知父进程,让父进程料理后事
//这样安排的原因有两个:
//1.首先在子进程的task_struct数据结构中还有不少有用的统计信息,让父进程来料理后事可以将这些统计信息并入父进程的统计信息中而不会使这些信息丢失.
//2.也许更重要的是,系统一旦进入多进程状态以后,任何一刻都需要有个"当前进程”存在.
//在中断和异常处理程序中都要用到当前进程的内核空间堆栈.如果进程在系统调度另一个进程投入运行之前就把它的task_struct结构和内核空间堆栈释放,那就会造成一个空隙.
//如果恰好有一次中断或者异常在此空隙中发生就会造成问题.所以子进程的task_struct和内核空间堆栈必须要保存到另一个进程开始运行之后才能释放.这样让父进程来料理后事
//就是一个合理的安排了.
	exit_notify();
	schedule();
	BUG();
/*
 * In order to get rid of the "volatile function does return" message
 * I did this little loop that confuses gcc to think do_exit really
 * is volatile. In fact it's schedule() that is volatile in some
 * circumstances: when current->state = ZOMBIE, schedule() never
 * returns.
 *
 * In fact the natural way to do all this is to have the label and the
 * goto right after each other, but I put the fake_volatile label at
 * the start of the function just in case something /really/ bad
 * happens, and the schedule returns. This way we can try again. I'm
 * not paranoid: it's just that everybody is out to get me.
 */
	goto fake_volatile;
}

NORET_TYPE void up_and_exit(struct semaphore *sem, long code)
{
	if (sem)
		up(sem);
	
	do_exit(code);
}

asmlinkage long sys_exit(int error_code)
{
	do_exit((error_code&0xff)<<8);
}

asmlinkage long sys_wait4(pid_t pid,unsigned int * stat_addr, int options, struct rusage * ru)
{
	int flag, retval;
	DECLARE_WAITQUEUE(wait, current);
	struct task_struct *tsk;

	if (options & ~(WNOHANG|WUNTRACED|__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;

	add_wait_queue(&current->wait_chldexit,&wait);
repeat:
	flag = 0;
	current->state = TASK_INTERRUPTIBLE;
	read_lock(&tasklist_lock);
	tsk = current;
	do {
		struct task_struct *p;
	 	for (p = tsk->p_cptr ; p ; p = p->p_osptr) {
			if (pid>0) {
				if (p->pid != pid)
					continue;
			} else if (!pid) {
				if (p->pgrp != current->pgrp)
					continue;
			} else if (pid != -1) {
				if (p->pgrp != -pid)
					continue;
			}
			/* Wait for all children (clone and not) if __WALL is set;
			 * otherwise, wait for clone children *only* if __WCLONE is
			 * set; otherwise, wait for non-clone children *only*.  (Note:
			 * A "clone" child here is one that reports to its parent
			 * using a signal other than SIGCHLD.) */
			if (((p->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
			    && !(options & __WALL))
				continue;
			flag = 1;
			switch (p->state) {
			case TASK_STOPPED:
				if (!p->exit_code)
					continue;
				if (!(options & WUNTRACED) && !(p->ptrace & PT_PTRACED))
					continue;
				read_unlock(&tasklist_lock);
				retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0; 
				if (!retval && stat_addr) 
					retval = put_user((p->exit_code << 8) | 0x7f, stat_addr);
				if (!retval) {
					p->exit_code = 0;
					retval = p->pid;
				}
				goto end_wait4;
			case TASK_ZOMBIE:
				current->times.tms_cutime += p->times.tms_utime + p->times.tms_cutime;
				current->times.tms_cstime += p->times.tms_stime + p->times.tms_cstime;
				read_unlock(&tasklist_lock);
				retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
				if (!retval && stat_addr)
					retval = put_user(p->exit_code, stat_addr);
				if (retval)
					goto end_wait4; 
				retval = p->pid;
				if (p->p_opptr != p->p_pptr) {
					write_lock_irq(&tasklist_lock);
					REMOVE_LINKS(p);
					p->p_pptr = p->p_opptr;
					SET_LINKS(p);
					do_notify_parent(p, SIGCHLD);
					write_unlock_irq(&tasklist_lock);
				} else
					release_task(p);
				goto end_wait4;
			default:
				continue;
			}
		}
		if (options & __WNOTHREAD)
			break;
		tsk = next_thread(tsk);
	} while (tsk != current);
	read_unlock(&tasklist_lock);
	if (flag) {
		retval = 0;
		if (options & WNOHANG)
			goto end_wait4;
		retval = -ERESTARTSYS;
		if (signal_pending(current))
			goto end_wait4;
		schedule();
		goto repeat;
	}
	retval = -ECHILD;
end_wait4:
	current->state = TASK_RUNNING;
	remove_wait_queue(&current->wait_chldexit,&wait);
	return retval;
}

#if !defined(__alpha__) && !defined(__ia64__)

/*
 * sys_waitpid() remains for compatibility. waitpid() should be
 * implemented by calling sys_wait4() from libc.a.
 */
asmlinkage long sys_waitpid(pid_t pid,unsigned int * stat_addr, int options)
{
	return sys_wait4(pid, stat_addr, options, NULL);
}

#endif
