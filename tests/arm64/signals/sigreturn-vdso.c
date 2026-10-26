// Returning from a signal handler must work. musl on arm64 registers
// handlers without SA_RESTORER, so the return goes through
// __kernel_rt_sigreturn in the vDSO, which therefore has to be mapped
// readable and executable. Freestanding: no libc, so it cross-compiles with
// clang alone and does not depend on the guest's C library.
typedef unsigned long u64; typedef long i64;
static i64 sc(i64 n, i64 a, i64 b, i64 c, i64 d) {
    register i64 x8 asm("x8") = n, x0 asm("x0") = a, x1 asm("x1") = b, x2 asm("x2") = c, x3 asm("x3") = d;
    asm volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
static volatile int handled;
static void on_usr1(int sig) { (void) sig; handled = 1; }
struct kernel_sigaction { void (*handler)(int); u64 flags; void *restorer; u64 mask; };
int main(void) {
    struct kernel_sigaction sa = {on_usr1, 0, 0, 0};
    if (sc(134 /* rt_sigaction */, 10 /* SIGUSR1 */, (i64) &sa, 0, 8)) return 2;
    sc(129 /* kill */, sc(172 /* getpid */, 0, 0, 0, 0), 10, 0, 0);
    if (!handled) return 3;
    static const char ok[] = "sigreturn-vdso-ok\n";
    sc(64 /* write */, 1, (i64) ok, sizeof ok - 1, 0);
    return 0;
}
asm(".text\n.globl _start\n_start:\n mov x29, #0\n bl main\n mov x8, #94\n svc 0\n");
