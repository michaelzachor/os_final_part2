# 1. kernel/itoa.c
## We'll need to implement an itoa program
In kernel add a file called itoa.c and add this code
```
void reverse(char str[], int length)
{
    int start = 0;
    int end = length -1;
    char temp;
    while (start < end)
    {
        temp = *(str+start);
        *(str+start) = *(str+end);
        *(str+end) = temp;
        // swap(*(str+start), *(str+end));
        start++;
        end--;
    }
}
 
// Implementation of itoa()
char* itoa(int num, char* str)
{
    int i = 0;
    // int isNegative = 0;
 
    /* Handle 0 explicitly, otherwise empty string is printed for 0 */
    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
 
    // Process individual digits
    while (num != 0)
    {
        int rem = num % 10;
        str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
        num = num/10;
    }
 
    str[i] = '\0'; // Append string terminator
 
    // Reverse the string
    reverse(str, i);
 
    return str;
}
```

# 2. kernel/trace.h
## Define some states that we'll use throughout the kernel
In kernel add a file called trace.h and add this code
```
#define T_TRACE 1
#define T_ONFORK 2

#define T_UNTRACE 0
```

# 3. kernel/syscall.h
## Add trace and sdump as syscalls
At the end of the file add this:
```
#define SYS_trace  22
#define SYS_sdump  23
```

# 4. kernel/syscall.c
## A. Create circular buffer for dumping
In kernel/syscall.c add this code at line 9, after #include syscall.h
```
#include "kernel/trace.h"
#include "kernel/itoa.c"

enum {STR_SIZE = 100};
enum {DUMP_SIZE = 20};

static char buf[DUMP_SIZE][STR_SIZE]; // array of 20 arrays of 100 chars

static int end = 0;    // write index
static int start = 0;  // read index

void circPut(char item[]) {
  int i = 0;
  while (item[i] && i < 100) {
      buf[end][i] = item[i];
      i++;
  }
  end++;
  end %= DUMP_SIZE;
  if (buf[end+1][0]) {
      start ++;
  }
}

char* circGet() {
  char* item = buf[start++];
  start %= DUMP_SIZE;
  return item;
}

void circDump() {
    do {
        cprintf(circGet());
    } while(start != 0);
}

void createStrAddToBuf(char* procPidBuf, char procNameBuf[], char* syscallBuf, char * retValBuf) {
    char newDump[STR_SIZE];
    int j = 0;
    while (j < "\e[35mTrace: pid = "[j]) {
        newDump[j] = "\e[35mTrace: pid = "[j];
        j++;
    }
    while (*procPidBuf) {
        newDump[j] = *procPidBuf;
        j++;
        procPidBuf++;
    }
    int k = j;
    while (" | command name = "[j-k]) {
        newDump[j] = " | command name = "[j-k];
        j++;
    }
    k = j;
    while (procNameBuf[j-k]) {
        newDump[j] = procNameBuf[j-k];
        j++;
    }
    k = j;
    while (" | syscall = "[j-k]) {
        newDump[j] = " | syscall = "[j-k];
        j++;
    }
    k=j;
    while (syscallBuf[j-k]) {
        newDump[j] = syscallBuf[j-k];
        j++;
    }
    k = j;
    if (*retValBuf != ' ' && *retValBuf != '0') {
        while (" | return val = "[j-k]) {
            newDump[j] = " | return val = "[j-k];
            j++;
        }
        k = j;
        while (*retValBuf) {
            newDump[j] = *retValBuf;
            j++;
            retValBuf++;
        }
        k = j;
    }
    while ("\e[0m\n\0"[j-k]) {
        newDump[j] = "\e[0m\n\0"[j-k];
        j++;
    }
    while (newDump[j]) {
        newDump[j] = '\0';
        j++;
    }
    circPut(newDump);   
}
```

## B. Add trace and sdump to list of syscalls and define sys_trace
Scroll down to around line 183 (list of syscalls) and add:
```
extern int sys_trace(void);
extern int sys_sdump(void);

int sys_trace() {
    int n;
    argint(0, &n);
    proc->traced = (n & T_TRACE) ? n : 0;
    return 0;
}
```
At the end of the list after that, add this, should be line 200:
```
, [SYS_trace] sys_trace, [SYS_sdump] sys_sdump
```

## C. Add list of syscall names so that we can print them later
Right after that list of syscalls, add this:
```
static char *syscall_names[] = {
    [SYS_fork] "fork",   [SYS_exit] "exit",     [SYS_wait] "wait",
    [SYS_pipe] "pipe",   [SYS_read] "read",     [SYS_kill] "kill",
    [SYS_exec] "exec",   [SYS_fstat] "fstat",   [SYS_chdir] "chdir",
    [SYS_dup] "dup",     [SYS_getpid] "getpid", [SYS_sbrk] "sbrk",
    [SYS_sleep] "sleep", [SYS_uptime] "uptime", [SYS_open] "open",
    [SYS_write] "write", [SYS_mknod] "mknod",   [SYS_unlink] "unlink",
    [SYS_link] "link",   [SYS_mkdir] "mkdir",   [SYS_close] "close",
    [SYS_trace] "trace", [SYS_sdump] "sdump"
};
```

## D. Handle trace information and dump
At the bottom there's a function called syscall(). We're going to check if we're being traced, if we are, we print out the trace information and add it to the buffer. We also check if the sdump syscall was called, and if so we call circDump(), which is defined above. Just replace the whole syscall() function with this:
```
void syscall(void) {
  int num, i;

  int is_traced = (proc->traced & T_TRACE);
  char procname[16];

  for (i=0; proc->name[i] != 0; i++) {
      procname[i] = proc->name[i];
  }
  procname[i] = '\0';

  num = proc->tf->eax;

  if (num == SYS_sdump) {
      circDump();
  }

  if (num == SYS_exit && is_traced) {
      cprintf("\e[35mTrace: pid = %d | command name = %s | syscall = %s\e[0m\n", 
      proc->pid, 
      procname, 
      syscall_names[num]);
      char tempStr[STR_SIZE];
      createStrAddToBuf(itoa(proc->pid, tempStr), procname, syscall_names[num], " ");
  }

  if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    proc->tf->eax = syscalls[num]();
    if (is_traced) {
        cprintf((num == SYS_exec && proc->tf->eax == 0) ?
        "\e[35mTRACE: pid = %d | command name = %s | syscall = %s\e[0m\n" :
        "\e[35mTRACE: pid = %d | command name = %s | syscall = %s | return val = %d\e[0m\n",
        proc->pid,
        procname,
        syscall_names[num],
        proc->tf->eax);
        char tempStr1[STR_SIZE];
        char tempStr2[STR_SIZE];
        createStrAddToBuf(itoa(proc->pid, tempStr1), procname, syscall_names[num], itoa(proc->tf->eax, tempStr2));
    }
  } 

  else {
    cprintf("%d %s: unknown sys call %d\n", proc->pid, proc->name, num);
    proc->tf->eax = -1;
  }
}
```

# 5. kernel/sysproc.c
## Continue adding trace and sdump as system calls
Add this at the bottom of sysproc.c:
```
void sys_sdump(void) {
    sdump();
}
```

# 6. kernel/proc.h
## Initialize sdump, add tracing feature to processes
Add this at the bottom of proc.h:
```
void sdump();
```
and on line 69, inside struct proc, add this after ```char name[16]```:
```
int traced;
```

# 7. kernel/proc.c
## A. Define sdump
Add this at the bottom of proc.c. We're not doing anything because in syscall.c is where we handle what happens if sdump is called, since it involves the circular buffer, which is defined and declared in syscall.c. 
```
void sdump() {
    return;
}
```

## B. Initialize untraced state
Near the top of proc.c, add this to the list of #includes:
```
#include "kernel/trace.h"
```
and a little bit lower (should be line 44), after they set the state to EMBRYO, add this:
```
p->traced = T_UNTRACE;
```

## C. On fork, set the traced state
Scroll down to around line 135 (the line right above this ```np->sz = proc->sz;```) and add this:
```
np->traced = (proc->traced & T_ONFORK) ? proc->traced : T_UNTRACE;
```

# 8. user/user.h
## Add trace and sdump as syscalls
At the end of the list of all the syscalls add this:
```
int trace(int);
void sdump(void);
```

# 9. user/usys.S
## Add trace and sdump as syscalls
At the end of the file add this:
```
SYSCALL(trace)
SYSCALL(sdump)
```

# 10. user/sh.c
## A. Add some strings we'll look for in user input (and create string compare function)
First add this to list of #includes:
```
#include "kernel/trace.h"
```
then add this after ```#define MAXARGS 10```:
```
int tracing = 0;

char trace_cmd[] = "strace on\n";
char untrace_cmd[] = "strace off\n";
char tracerun_cmd[] = "strace run";
char tracedump_cmd[] = "strace dump\n";

char trace_e_cmd[] = "strace -e ";
int stringEqual(char* a, char* b) {
    while (1) {
        if (*a != *b) {
            return 0;
        }
        if (*a == '\n' || (*a == '\0' && *b == '\0')) return 1;
        a++;
        b++;
    }
}
```

## B. Set tracing state
Scroll down and inside case EXEC, right before ```exec(ecmd->argv[0], ecmd->argv);```, add this:
```
if (tracing) {
    trace(T_TRACE | T_ONFORK);
}
```

## C. Handle "strace on", "strace off", etc commands
Scroll down to around line 163. Replace all of main() with this. Basically we set startOfBuf to the first 11 characters of the buffer and endOfBuf to the rest of the buffer. We check if the user has typed "strace on\n", "strace off\n", or "strace run" and we turn tracing on, off, or temporarily turn it on (set it to 3, at the start of main turn it off). 
```
int main(void) {
  static char buf[100];
  int fd;

  // Assumes three file descriptors open.
  while ((fd = open("console", O_RDWR)) >= 0) {
    if (fd >= 3) {
      close(fd);
      break;
    }
  }

  // Read and run input commands.
  while (getcmd(buf, sizeof(buf)) >= 0) {
    if (tracing == 3) tracing = 0;
    if (buf[0] == 'c' && buf[1] == 'd' && buf[2] == ' ') {
      // Clumsy but will have to do for now.
      // Chdir has no effect on the parent if run in the child.
      buf[strlen(buf) - 1] = 0; // chop \n
      if (chdir(buf + 3) < 0)
        printf(2, "cannot cd %s\n", buf + 3);
      continue;
    }
    char startOfBuf[11];
    for (int i = 0; i < 10; i++) {
        if (buf[i]) startOfBuf[i] = buf[i];
        else startOfBuf[i] = ' ';
    }
    startOfBuf[10] = '\0';
    int counter = 0;
    while (buf[counter + 11] != '\n' && buf[counter + 11] != '\0') {
        counter++;
    } counter++;
    char endOfBuf[counter];
    for (int i = 0; i <= counter; i++) {
        endOfBuf[i] = buf[i+11];
    }
    if (stringEqual(startOfBuf, tracerun_cmd)) {
        tracing = 3;
    }
    if (stringEqual(buf, trace_cmd)) {
        tracing = 1;
        continue;
    }
    if (stringEqual(buf, untrace_cmd)) {
        tracing = 0;
        continue;
    }
    if (fork1() == 0) {
      if (tracing == 3) {
          runcmd(parsecmd(endOfBuf));
      }
      else {
          runcmd(parsecmd(buf));
      }
    }
    wait();
  }
  exit();
}
```

# 11. user/strace.c
## Create a program that lets user run strace dump
In user space create a file called strace.c and add this:
```
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user.h"

// strace dump
int main(int argc, char *argv[]) {

  if (argc <= 1) {
    exit();
  }
  
  if (argv[1][0] == 'd' && argv[1][1] == 'u' && argv[1][2] == 'm' && argv[1][3] == 'p') {
    sdump();
  }
  else {
      printf(2, "invalid command\n");
      exit();
  }
  exit();
}
```

# 12. user/traceTest.c
## Create a program that forks itself for the "Trace child process" part of the project
In user space create a file called traceTest.c and add this:
```
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user.h"
#include "kernel/trace.h"

int main(int argc, char *argv[]) {
    int fr = fork();
	if (fr == -1) {
		printf(1, "Fork error!\n");
        exit();
	} else if (fr == 0) {
        printf(1, "Test\n");
        int fr2 = fork();
        if (fr2 == -1) {
            printf(1, "Fork error!\n");
            exit();
        } else if (fr2 == 0) {
            printf(1, "Test2\n");
            exit();
        } else {
            wait();
        }
		exit();
	} else {
		wait();
	}

	exit();
}
```

# 13. Makefile
## Add strace and traceTest to the Makefile
Add this to the list of UPROGS in the Makefile (around line 137):
```
$U/_traceTest\
$U/_strace\
```
