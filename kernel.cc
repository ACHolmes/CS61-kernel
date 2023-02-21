#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"
#include "atomic.hh"

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state - see `kernel.hh`
physpageinfo physpages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();

// Constant for later
int ALL_PERMS = PTE_P | PTE_W | PTE_U;

// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel_start(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // (re-)initialize kernel page table
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int perm = PTE_P | PTE_W | PTE_U;
        if (addr == 0) {
            // nullptr is inaccessible even to the kernel
            perm = 0;
        }
        if (addr < PROC_START_ADDR && addr != CONSOLE_ADDR)
        {
            perm = PTE_P | PTE_W;
            
        }
        // install identity mapping
        int rk = vmiter(kernel_pagetable, addr).try_map(addr, perm);
        assert(rk == 0); 
        // mappings dfuring kernel_start MUST NOT fail
        // (Note that later mappings might fail!!)
    }

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) {
        command = WEENSYOS_FIRST_PROCESS;
    }
    if (!program_image(command).empty()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // switch to first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel physical memory allocator. Allocates at least `sz` contiguous bytes
//    and returns a pointer to the allocated memory, or `nullptr` on failure.
//    The returned pointer’s address is a valid physical address, but since the
//    WeensyOS kernel uses an identity mapping for virtual memory, it is also a
//    valid virtual address that the kernel can access or modify.
//
//    The allocator selects from physical pages that can be allocated for
//    process use (so not reserved pages or kernel data), and from physical
//    pages that are currently unused (`physpages[N].refcount == 0`).
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The handout code returns the next allocatable free page it can find.
//    It checks all pages. (You could maybe make this faster!)
//
//    The returned memory is initially filled with 0xCC, which corresponds to
//    the `int3` instruction. Executing that instruction will cause a `PANIC:
//    Unhandled exception 3!` This may help you debug.

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    for (uintptr_t pa = 0; pa != MEMSIZE_PHYSICAL; pa += PAGESIZE) {
        if (allocatable_physical_address(pa)
            && physpages[pa / PAGESIZE].refcount == 0) {
            ++physpages[pa / PAGESIZE].refcount;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
    }
    return nullptr;
}

// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    uintptr_t addr = (uintptr_t) kptr;
    // Checking for correct usage
    assert(addr % PAGESIZE == 0);
    assert(addr <= MEMSIZE_PHYSICAL);
    // Can try to free nullptr or something that is already free, just return
    if (addr == (uintptr_t) nullptr || physpages[addr / PAGESIZE].refcount == 0)
    {
        return;
    }
    // reduce its refcount by 1 - since we now have shared memory we just decrement, kind of 
    // 'fake freeing' since we pretend we have freed for that process but in reality it may be being used elsewhere
    // and we maintained it for that other process
    physpages[addr / PAGESIZE].refcount -= 1;
    return;
}


int copy_kernel_mappings(x86_64_pagetable* dst, x86_64_pagetable* src) {
    vmiter srcit(src, 0);
    vmiter dstit(dst, 0);
    for (; srcit.va() < PROC_START_ADDR; srcit += PAGESIZE, dstit += PAGESIZE) {
        int r = dstit.try_map(srcit.pa(), srcit.perm());
        if (r != 0)
        {
            return -1;
        }
    }
    return 0;
}


// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // initialize process page table
    ptable[pid].pagetable = kalloc_pagetable();
    // If we're out of pagetables, free everything
    // Don't syscall_exit as we set the process up from another process
    // so we just free it and return to the kernel process and carry on
    if (ptable[pid].pagetable == nullptr)
    {
        free_everything(pid);
        return;
    }
    // Copy kernel mappings to new process. Guaranteed to succeed
    int r = copy_kernel_mappings(ptable[pid].pagetable, kernel_pagetable);
    assert(r == 0);

    // obtain reference to program image
    // (The program image models the process executable.)
    program_image pgm(program_name);

    // allocate and map process memory as specified in program image
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {
        for (uintptr_t a = round_down(seg.va(), PAGESIZE);
             a < seg.va() + seg.size();
             a += PAGESIZE) 
        {
            // If we run out of memory, free everything from the process and return to caller process
            uintptr_t phys_addr = (uintptr_t) kalloc(PAGESIZE);
            if (phys_addr == (uintptr_t) nullptr)
            {
                free_everything(pid);
                return;
            }
            // Default perms, add write if writeable
            int perms = PTE_P | PTE_U;
            if (seg.writable())
            {
                perms = perms | PTE_W;
            }
            // Check that vmiter maps correctly, else free everything and return
            int rm = vmiter(ptable[pid].pagetable, a).try_map(phys_addr, perms);
            if (rm != 0)
            {
                free_everything(pid);
                return;
            }
        }
    }


    // copy instructions and data from program image into process memory
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) 
    {
        vmiter it(ptable[pid].pagetable, seg.va());
        memset((void*) it.pa(), 0, seg.size());
        memcpy((void*) it.pa(), seg.data(), seg.data_size());
    }

    // mark entry point
    ptable[pid].regs.reg_rip = pgm.entry();

    // allocate and map stack segment
    // Compute process virtual address for stack page
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    uintptr_t phys_addr = (uintptr_t) kalloc(PAGESIZE);
    // Again, if out of space, free everything (phys_addr is nullptr so no need to free)
    if (phys_addr == (uintptr_t) nullptr)
    {
        free_everything(pid);
        return;
    }
    // Check vmiter didn't fail
    int rf = vmiter(ptable[pid].pagetable, stack_addr).try_map(phys_addr, ALL_PERMS);
    if (rf != 0)
    {
        kfree((void *) phys_addr);
        free_everything(pid);
        return;
    }
    // Set %rsp
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;

    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PTE_W
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PTE_P
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PTE_U)) {
            proc_panic(current, "Kernel page fault on %p (%s %s, rip=%p)!\n",
                       addr, operation, problem, regs->reg_rip);
        }
        error_printf(CPOS(24, 0), 0x0C00,
                     "Process %d page fault on %p (%s %s, rip=%p)!\n",
                     current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_FAULTED;
        break;
    }

    default:
        proc_panic(current, "Unhandled exception %d (rip=%p)!\n",
                   regs->reg_intno, regs->reg_rip);

    }


    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


int copy_proc_mappings(x86_64_pagetable* dst, x86_64_pagetable* src) {
    vmiter srcit(src, PROC_START_ADDR);
    vmiter dstit(dst, PROC_START_ADDR);
    for (; srcit.va() < MEMSIZE_VIRTUAL; srcit += PAGESIZE, dstit += PAGESIZE) {
        if(srcit.present())
        {            
            // Non COW version:
            // Map read only memory and the console to be shared
            if (!srcit.writable() || srcit.va() == CONSOLE_ADDR)
            {
                int r = vmiter(dst, srcit.va()).try_map(srcit.pa(), srcit.perm());
                if (r != 0)
                {
                    return -1;
                }
                physpages[srcit.pa() / PAGESIZE].refcount += 1;
            }
            // Otherwise all writeable memory we kalloc a new physical page
            else
            {
                uintptr_t new_pa = (uintptr_t) kalloc(PAGESIZE);
                if (new_pa == (uintptr_t) nullptr)
                {
                    // return -1 so we can run free_everything
                    return -1;
                }
                int r = vmiter(dst, srcit.va()).try_map(new_pa, srcit.perm());
                if (r != 0)
                {
                    // Free the allocated page!
                    kfree((void *) new_pa);
                    return -1;
                }
                // Set the whole page to 0 and then copy in the data
                memset((void *) new_pa, 0, PAGESIZE);
                memcpy((void *) new_pa, (void *) srcit.pa(), PAGESIZE);
            }
        }
    }
    return 0;
}

// Take in a pid instead
void free_everything(pid_t pid) 
{
    // Check for correct usage, don't mess with kernel
    assert(pid != 0);
    assert(pid < NPROC);
    x86_64_pagetable* pt = ptable[pid].pagetable;
    
    for (vmiter it(pt, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        // Free everything in the pagetable except console (shared between processes)
        if (it.user() && it.va() != CONSOLE_ADDR) {
            kfree(it.kptr());
        }
    }
    // Free the actual pagetable
    for (ptiter it(pt); !it.done(); it.next()) {
        kfree(it.kptr());
    }
    kfree(pt);
    // This process is now free
    ptable[pid].state = P_FREE;
}


int syscall_fork()
{
    // Finding a free process slot
    int npid = 0;
    for(int i = 1; i < NPROC; ++i)
    {
        if(ptable[i].state == P_FREE)
        {
            npid = i;
            break;
        }
    }
    if (!npid)
    {
        return -1;
    }
    // Create new pagetable for child process
    x86_64_pagetable* npagetable = kalloc_pagetable();
    if (npagetable == nullptr)
    {
        return -1;
    }
    ptable[npid].pagetable = npagetable;
    // Copying all mappings
    int rf = copy_kernel_mappings(ptable[npid].pagetable, ptable[current->pid].pagetable);
    if (rf == -1)
    {
        free_everything(npid);
        return -1;
    }
    int r = copy_proc_mappings(ptable[npid].pagetable, ptable[current->pid].pagetable);
    if (r == -1)
    {
        free_everything(npid);
        return -1;
    }
    // Set registers
    ptable[npid].regs = ptable[current->pid].regs;
    ptable[npid].regs.reg_rax = 0;
    // Set process as runnable
    ptable[npid].state = P_RUNNABLE;
    return npid;
}

void syscall_exit()
{
    // Free everything except console. Then in syscall we will schedule the next process
    free_everything(current->pid);
}


// syscall(regs)
//    Handle a system call initiated by a `syscall` instruction.
//    The process’s register values at system call time are accessible in
//    `regs`.
//
//    If this function returns with value `V`, then the user process will
//    resume with `V` stored in `%rax` (so the system call effectively
//    returns `V`). Alternately, the kernel can exit this function by
//    calling `schedule()`, perhaps after storing the eventual system call
//    return value in `current->regs.reg_rax`.
//
//    It is only valid to return from this function if
//    `current->state == P_RUNNABLE`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state.
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        user_panic(current);
        break; // will not be reached

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        syscall_exit();
        schedule();

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_PAGE_FREE:
        return syscall_page_free(current->regs.reg_rdi);
    
    case SYSCALL_MUNMAP:
        return syscall_munmap(current->regs.reg_rdi, current->regs.reg_rsi);

    case SYSCALL_SLEEP:
        syscall_sleep(current->regs.reg_rdi, current->regs.reg_rsi);
        schedule();

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Handles the SYSCALL_PAGE_ALLOC system call. This function
//    should implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the handout code, it does not).


// sys_page_alloc(addr)
//    Allocate a page of memory at address `addr` for this process. The
//    newly-allocated memory is initialized to 0. Any memory previously
//    located at `addr` should be freed. Returns 0 on success; if there is a
//    failure (out memory or invalid argument), returns -1 without modifying
//    memory.
//
//    `Addr` should be page-aligned (i.e., a multiple of PAGESIZE == 4096),
//    >= PROC_START_ADDR, and < MEMSIZE_VIRTUAL. If any of these requirements
//    is not met, the system call should return -1 without modifying memory.

int syscall_page_alloc(uintptr_t addr) {
    // Check for valid argument
    if(addr == (uintptr_t) nullptr || addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0)
    {
        return -1;
    }
    // Free any memory previously located at addr
    vmiter it(ptable[current->pid].pagetable, addr);
    if (it.present())
    {
        kfree((void *) it.pa());
    }
    // Create new allocation
    uintptr_t new_addr = (uintptr_t) kalloc(PAGESIZE);
    // Check allocation and map worked, else free and return -1
    if (new_addr == (uintptr_t) nullptr)
    {
        return -1;
    }
    int r = vmiter(ptable[current->pid].pagetable, addr).try_map(new_addr, PTE_P | PTE_W | PTE_U);
    if (r != 0)
    {
        kfree((void*) new_addr);
        return -1;
    }
    // Initialize to 0
    memset((void*) new_addr, 0, PAGESIZE);
    return 0;
}


// Bonus point work (work in progress)
int syscall_page_free(uintptr_t addr)
{
    if(addr == (uintptr_t) nullptr || addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0)
    {
        return -1;
    }
    vmiter it(ptable[current->pid].pagetable, addr);
    return it.try_map(nullptr, 0);
}

int syscall_munmap(uintptr_t addr, size_t length)
{
    if(addr == (uintptr_t) nullptr || addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0)
    {
        return -1;
    }
    size_t pos = 0;
    // Note in manual for munmap it says 'all pages containing a part of the indicated range are unmapped,
    // hence even if you run this with length = 1 it should unmap a full page
    for(; addr < MEMSIZE_VIRTUAL - PAGESIZE && pos < length; addr += PAGESIZE, pos += PAGESIZE)
    {
        int r = syscall_page_free(addr);
        if (r != 0)
        {
            return -1;
        }
    }
    return 0;
}

// Checker function (for debugging / checking)
int check_munmap(uintptr_t addr, size_t length)
{
    log_printf("Entered checker\n");
    if(addr == (uintptr_t) nullptr || addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0)
    {
        return -1;
    }
    vmiter it(ptable[current->pid].pagetable, addr);
    for(size_t pos = 0; pos < length && it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE, pos += PAGESIZE)
    {
        assert(it.pa() == (uintptr_t) nullptr);
    }
    log_printf("Munmap checked succesfully\n");
    return 0;

}

void syscall_sleep(pid_t pid, size_t duration)
{
    // Don't allow sleeping the kernel
    if (pid == 0)
    {
        return;
    }
    // Set a time when to wake up
    size_t end = duration + ticks;
    // Don't let it be run in the meantime
    ptable[pid].state = P_BLOCKED;
    // Set the time when we should wake it up
    ptable[pid].awake = end;
}

void syscall_awake(pid_t pid)
{
    // Check for correct usage
    assert(ptable[pid].state == P_BLOCKED);
    // Awake if ready!
    if (ptable[pid].awake < ticks)
    {
        ptable[pid].state = P_RUNNABLE;
    }
}

// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_BLOCKED)
        {
            syscall_awake(pid);
        }
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
//    Run process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    console_memviewer(p);
    if (!p) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}
