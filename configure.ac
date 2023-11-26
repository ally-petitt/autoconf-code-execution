AC_INIT([hello], [1.0])
AC_CONFIG_SRCDIR([hello.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_PROG_CC

# Trigger the vulnerabilities by writing to a file called `vulns`
syscmd(echo vuln1 > vulns) # vuln1
m4_file_append(test, `echo vuln2 >> vulns`) # vuln2 and vuln3


AC_CONFIG_FILES([Makefile])
AC_OUTPUT