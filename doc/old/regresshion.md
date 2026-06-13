# Was regreSSHion on purpose? Investigating intentionality of CVE-2024-6387

CVE-2024-6387, codenamed "regreSSHion", is a remote code execution
vulnerability introduced in OpenSSH 8.5 in 2020. The details of the
vulnerability's impact, methods of exploitation, and mitigations are
documented by Qualys in their [security advisory
report](https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt). The
details are rather complicated, but in summary the exploit works by causing
sshd to trigger a signal handler (via SIGALRM) while sshd is actively running
a `malloc()` call. If the signal handler also runs `malloc()`, it is possible
to overwrite a function pointer in such a way that it points to an
attacker-controlled location in memory, which can contain arbitrary code. This
code runs as root, unsandboxed, allowing an attacker to take full control over
an affected machine. There are potentially other ways of exploiting a signal
handler that runs async-signal-unsafe code, but this is the method described
by Qualys.

The codename for the CVE, "regreSSHion", is so named because the vulnerability
is a "resurrection" of an older vulnerability, CVE-2006-5051. The way in which
the vulnerability was reintroduced is interesting because, had the code
change that introduced the vuln been designed slightly differently, the
vulnerability's reintroduction would have been glaringly obvious, and the
issue would likely have been caught during regular code review. Unfortunately,
due to design decisions made in the code change, the vulnerability went
undetected for approximately three years and four months (from March 3, 2021,
when OpenSSH 8.5 was released, to July 1, 2024, when the regreSSHion CVE was
published).

The vulnerability report from Qualys states that "OpenSSH is one of the most
secure software in the world; this vulnerability is one slip-up in an
otherwise near-flawless implementation" and that the vulnerability was caused
by "accidentally removed" code. However, it is known that agencies with
interest in compromising other entities will sometimes approach open-source
developers and ask them to introduce bugs into their projects that act as a
backdoor (the most famous example of this is the NSA allegedly [requesting
Linus Torvalds to backdoor the Linux
kernel](https://www.youtube.com/watch?v=EkpIddQ8m2s&t=11346s)).

Given some of the circumstances surrounding this vulnerability, the Kicksecure
development team has chosen to analyze regreSSHion to determine the truth of
Qualys's claims of OpenSSH's security and the unintentional nature of the
vulnerability's introduction. In other words, does OpenSSH show a history of
well-designed, safe code? Was the vulnerability potentially introduced on
purpose?

## The role of the regreSSHion committer

The regreSSHion vulnerability was introduced in the
[openssh-portable](https://github.com/openssh/openssh-portable) Git repository
by [Damien Miller](https://github.com/djmdjm) in commit
[752250caabda3dd24635503c4cd689b32](https://github.com/openssh/openssh-portable/commit/752250caabda3dd24635503c4cd689b32).

According to the [OpenSSH History page](https://www.openssh.com/history.html),
Miller started work on OpenSSH after the OpenSSH 1.2.2 release, which was
initially for OpenBSD only. He is listed as one of several individuals who
were interested in porting OpenSSH to other UNIX and UNIX-like platforms. The
history page notes that the core OpenSSH product is still OpenBSD-only, while
the version made to be portable in other operating systems has been split off
into a separate repository. This separate repository is the previously
mentioned openssh-portable repo.

Since that time, Miller's role in OpenSSH development has become highly
privileged. He is the first committer to the openssh-portable Git repository,
his commits make up over 33% of all code changes to the repository (though
many of these are CVS imports), and he frequently posts OpenSSH-related
content (such as new release announcements and security-related discussions)
on Mastodon. At least from an outside perspective, he appears to be the
primary maintainer of openssh-portable.

Given Miller's long history of involvement and highly trusted position, it is
unlikely that Miller's presence in the project is solely for the purpose of
introducing malicious code, such as Xia Tan's involvement in XZ appears to have
been.

## Fatal logging in OpenSSH

OpenSSH's logging facilities have changed several times over the years. The
regreSSHion vulnerability specifically has to do with logging when a fatal
error occurs. With this in mind, let's look at how logging in OpenSSH has
historically worked in a fatal condition.

Starting at the very first commit in the repository,
`d4a8b7e34dd619a4debf9a206c81db26d1402ea6`, made on October 27, 1999 by Damien
Miller:

```c
// In file ssh.h
/*------------ Definitions for logging. -----------------------*/

/* Supported syslog facilities. */
typedef enum
{
  SYSLOG_FACILITY_DAEMON,
  SYSLOG_FACILITY_USER,
  SYSLOG_FACILITY_AUTH,
  SYSLOG_FACILITY_LOCAL0,
  SYSLOG_FACILITY_LOCAL1,
  SYSLOG_FACILITY_LOCAL2,
  SYSLOG_FACILITY_LOCAL3,
  SYSLOG_FACILITY_LOCAL4,
  SYSLOG_FACILITY_LOCAL5,
  SYSLOG_FACILITY_LOCAL6,
  SYSLOG_FACILITY_LOCAL7
} SyslogFacility;

/* Initializes logging.  If debug is non-zero, debug() will output something.
   If quiet is non-zero, none of these will log send anything to syslog
   (but maybe to stderr). */
void log_init(char *av0, int on_stderr, int debug, int quiet,
        SyslogFacility facility);

/* Outputs a message to syslog or stderr, depending on the implementation.
   The format must guarantee that the final message does not exceed 1024
   characters.  The message should not contain newline. */
void log(const char *fmt, ...);

/* Outputs a message to syslog or stderr, depending on the implementation.
   The format must guarantee that the final message does not exceed 1024
   characters.  The message should not contain newline. */
void debug(const char *fmt, ...);

/* Outputs a message to syslog or stderr, depending on the implementation.
   The format must guarantee that the final message does not exceed 1024
   characters.  The message should not contain newline. */
void error(const char *fmt, ...);

/* Outputs a message to syslog or stderr, depending on the implementation.
   The format must guarantee that the final message does not exceed 1024
   characters.  The message should not contain newline.
   This call never returns. */
void fatal(const char *fmt, ...);

/* Registers a cleanup function to be called by fatal() before exiting.
   It is permissible to call fatal_remove_cleanup for the function itself
   from the function. */
void fatal_add_cleanup(void (*proc)(void *context), void *context);

/* Removes a cleanup frunction to be called at fatal(). */
void fatal_remove_cleanup(void (*proc)(void *context), void *context);
```

```c
// In file log-server.c:
/* Fatal messages.  This function never returns. */

void fatal(const char *fmt, ...)
{
  va_list args;
  struct fatal_cleanup *cu, *next_cu;
  static int fatal_called = 0;
#if defined(KRB4)
  extern char *ticket;
#endif /* KRB4 */
  DECL_MSGBUF;

  if (log_quiet)
    exit(1);
  va_start(args, fmt);
  vsnprintf(msgbuf, MSGBUFSIZE, fmt, args);
  va_end(args);
  if (log_on_stderr)
    fprintf(stderr, "fatal: %s\n", msgbuf);
  syslog(LOG_ERR, "fatal: %.500s", msgbuf);

  if (fatal_called)
    exit(1);
  fatal_called = 1;

  /* Call cleanup functions. */
  for (cu = fatal_cleanups; cu; cu = next_cu)
    {
      next_cu = cu->next;
      debug("Calling cleanup 0x%lx(0x%lx)",
      (unsigned long)cu->proc, (unsigned long)cu->context);
      (*cu->proc)(cu->context);
    }
#if defined(KRB4)
  /* If you forwarded a ticket you get one shot for proper
     authentication. */
  /* If tgt was passed unlink file */
  if (ticket)
    {
      if (strcmp(ticket,"none"))
  unlink(ticket);
      else
  ticket = NULL;
    }
#endif /* KRB4 */

  /* If local XAUTHORITY was created, remove it. */
  if (xauthfile) unlink(xauthfile);

  exit(1);
}
```

This function does... a lot, but the main interesting part is that some of the
functions it calls are async-signal-unsafe (such as the `printf()`-family
calls and `syslog()`). A quick look through the code reveals that this is a
vulnerable implementation - `fatal()` is called by `grace_alarm_handler()`,
which is triggered by `SIGALRM`:

```c
// In file sshd.c:
  /* We don\'t want to listen forever unless the other side successfully
     authenticates itself.  So we set up an alarm which is cleared after
     successful authentication.  A limit of zero indicates no limit.
     Note that we don\'t set the alarm in debugging mode; it is just annoying
     to have the server exit just when you are about to discover the bug. */
  signal(SIGALRM, grace_alarm_handler);
```

```c
// In file sshd.c:
/* Signal handler for the alarm after the login grace period has expired. */

void grace_alarm_handler(int sig)
{
  /* Close the connection. */
  packet_close();

  /* Log error and exit. */
  fatal("Timeout before authentication.");
}
```

(As a side note, the `packet_close()` call also calls async-signal-unsafe
functions, and as such this is the function Qualys used in their regreSSHion
exploit development to prepare their initial exploit prototype. Only later did
they have to resort to exploiting logging functionality. Another side note,
this calls an entire chain of cleanup functions in a signal handler, which is
terrifying in its own right and quite possibly would provide further methods
of exploitation.)

The next commit that affects the `fatal()` function definition is
`5ce662a9202240a2f5fa6a9334d58186bdaba50c`, made on November 11, 1999 by
Miller, importing changes from OpenBSD's CVS repository:

```c
// In file ssh.h:
/*------------ Definitions for logging. -----------------------*/

/* Supported syslog facilities and levels. */
typedef enum
{
  SYSLOG_FACILITY_DAEMON,
  SYSLOG_FACILITY_USER,
  SYSLOG_FACILITY_AUTH,
  SYSLOG_FACILITY_LOCAL0,
  SYSLOG_FACILITY_LOCAL1,
  SYSLOG_FACILITY_LOCAL2,
  SYSLOG_FACILITY_LOCAL3,
  SYSLOG_FACILITY_LOCAL4,
  SYSLOG_FACILITY_LOCAL5,
  SYSLOG_FACILITY_LOCAL6,
  SYSLOG_FACILITY_LOCAL7
} SyslogFacility;

typedef enum
{
  SYSLOG_LEVEL_QUIET,
  SYSLOG_LEVEL_FATAL,
  SYSLOG_LEVEL_ERROR,
  SYSLOG_LEVEL_INFO,
  SYSLOG_LEVEL_CHAT,
  SYSLOG_LEVEL_DEBUG
} LogLevel;

/* Initializes logging. */
void log_init(char *av0, LogLevel level, SyslogFacility facility, int on_stderr);

/* Logging implementation, depending on server or client */
void do_log(LogLevel level, const char *fmt, va_list args);

/* Output a message to syslog or stderr */
void fatal(const char *fmt, ...);
void error(const char *fmt, ...);
void log(const char *fmt, ...);
void chat(const char *fmt, ...);
void debug(const char *fmt, ...);

/* same as fatal() but w/o logging */
void fatal_cleanup(void);

/* Registers a cleanup function to be called by fatal()/fatal_cleanup() before exiting.
   It is permissible to call fatal_remove_cleanup for the function itself
   from the function. */
void fatal_add_cleanup(void (*proc)(void *context), void *context);

/* Removes a cleanup function to be called at fatal(). */
void fatal_remove_cleanup(void (*proc)(void *context), void *context);
```

```c
// In file log.c:
/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  fatal_cleanup();
}
...
/* Cleanup and exit */
void
fatal_cleanup(void)
{
  struct fatal_cleanup *cu, *next_cu;
  static int called = 0;
  if (called)
    exit(255);
  called = 1;

  /* Call cleanup functions. */
  for (cu = fatal_cleanups; cu; cu = next_cu)
    {
      next_cu = cu->next;
      debug("Calling cleanup 0x%lx(0x%lx)",
      (unsigned long)cu->proc, (unsigned long)cu->context);
      (*cu->proc)(cu->context);
    }

  exit(255);
}
```

```c
// In file log-server.c:
#define MSGBUFSIZE 1024

void
do_log(LogLevel level, const char *fmt, va_list args)
{
  char msgbuf[MSGBUFSIZE];
  char fmtbuf[MSGBUFSIZE];
  char *txt = NULL;
  int pri = LOG_INFO;

  if (level > log_level)
    return;
  switch (level)
    {
    case SYSLOG_LEVEL_ERROR:
      txt = "error";
      pri = LOG_ERR;
      break;
    case SYSLOG_LEVEL_FATAL:
      txt = "fatal";
      pri = LOG_ERR;
      break;
    case SYSLOG_LEVEL_INFO:
      pri = LOG_INFO;
      break;
    case SYSLOG_LEVEL_CHAT:
      pri = LOG_INFO;
      break;
    case SYSLOG_LEVEL_DEBUG:
      txt = "debug";
      pri = LOG_DEBUG;
      break;
    default:
      txt = "internal error";
      pri = LOG_ERR;
      break;
    }

  if (txt != NULL) {
    snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", txt, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
  }else{
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
  }
  if (log_on_stderr)
    fprintf(stderr, "%s\n", msgbuf);
  syslog(pri, "%.500s", msgbuf);
}
```

Significant refactoring has occurred; Kerberos and Xauthority-related routines
are no longer directly part of the `fatal()` call, `fatal()` itself no longer
has separate client and server implementations, and some functionality has
been delegated to `do_log()`. `grace_alarm_handler()` continues to call
`fatal()`, which continues to call `printf()`-family functions and `syslog()`,
thus this is likely still vulnerable.

Next we have `95def09838fc61b37b6ea7cd5c234a465b4b129b`, made on November 25,
1999, again by Damien Miller, importing more OpenBSD CVS code changes:

```c
// In file ssh.h:
/*------------ Definitions for logging. -----------------------*/

/* Supported syslog facilities and levels. */
typedef enum {
  SYSLOG_FACILITY_DAEMON,
  SYSLOG_FACILITY_USER,
  SYSLOG_FACILITY_AUTH,
  SYSLOG_FACILITY_LOCAL0,
  SYSLOG_FACILITY_LOCAL1,
  SYSLOG_FACILITY_LOCAL2,
  SYSLOG_FACILITY_LOCAL3,
  SYSLOG_FACILITY_LOCAL4,
  SYSLOG_FACILITY_LOCAL5,
  SYSLOG_FACILITY_LOCAL6,
  SYSLOG_FACILITY_LOCAL7
}       SyslogFacility;

typedef enum {
  SYSLOG_LEVEL_QUIET,
  SYSLOG_LEVEL_FATAL,
  SYSLOG_LEVEL_ERROR,
  SYSLOG_LEVEL_INFO,
  SYSLOG_LEVEL_VERBOSE,
  SYSLOG_LEVEL_DEBUG
}       LogLevel;
/* Initializes logging. */
void    log_init(char *av0, LogLevel level, SyslogFacility facility, int on_stderr);

/* Logging implementation, depending on server or client */
void    do_log(LogLevel level, const char *fmt, va_list args);

/* name to facility/level */
SyslogFacility log_facility_number(char *name);
LogLevel log_level_number(char *name);

/* Output a message to syslog or stderr */
void    fatal(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    error(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    log(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    verbose(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    debug(const char *fmt,...) __attribute__((format(printf, 1, 2)));

/* same as fatal() but w/o logging */
void    fatal_cleanup(void);

/* Registers a cleanup function to be called by fatal()/fatal_cleanup() before exiting.
   It is permissible to call fatal_remove_cleanup for the function itself
   from the function. */
void    fatal_add_cleanup(void (*proc) (void *context), void *context);

/* Removes a cleanup function to be called at fatal(). */
void    fatal_remove_cleanup(void (*proc) (void *context), void *context);
```

Most of the logging functionality remains the same. `grace_alarm_handler()`
continues to call `fatal()` which continues to call cleanup functions and
`printf()`-family functions and `syslog()` and thus is likely vulnerable.

Next we have commit `226cfa03781466907dd252916aeade6879e376b8`, made by Ben
Lindstrom this time, on January 22, 2001. For the first time, `log.h` is
introduced:

```c
// In file log.h:
/* Supported syslog facilities and levels. */
typedef enum {
  SYSLOG_FACILITY_DAEMON,
  SYSLOG_FACILITY_USER,
  SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
        SYSLOG_FACILITY_AUTHPRIV,
#endif
  SYSLOG_FACILITY_LOCAL0,
  SYSLOG_FACILITY_LOCAL1,
  SYSLOG_FACILITY_LOCAL2,
  SYSLOG_FACILITY_LOCAL3,
  SYSLOG_FACILITY_LOCAL4,
  SYSLOG_FACILITY_LOCAL5,
  SYSLOG_FACILITY_LOCAL6,
  SYSLOG_FACILITY_LOCAL7
}       SyslogFacility;

typedef enum {
  SYSLOG_LEVEL_QUIET,
  SYSLOG_LEVEL_FATAL,
  SYSLOG_LEVEL_ERROR,
  SYSLOG_LEVEL_INFO,
  SYSLOG_LEVEL_VERBOSE,
  SYSLOG_LEVEL_DEBUG1,
  SYSLOG_LEVEL_DEBUG2,
  SYSLOG_LEVEL_DEBUG3
}       LogLevel;
/* Initializes logging. */
void    log_init(char *av0, LogLevel level, SyslogFacility facility, int on_stderr);

/* Logging implementation, depending on server or client */
void    do_log(LogLevel level, const char *fmt, va_list args);

/* name to facility/level */
SyslogFacility log_facility_number(char *name);
LogLevel log_level_number(char *name);

/* Output a message to syslog or stderr */
void    fatal(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    error(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    log(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    verbose(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    debug(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    debug2(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void    debug3(const char *fmt,...) __attribute__((format(printf, 1, 2)));

/* same as fatal() but w/o logging */
void    fatal_cleanup(void);

/*
 * Registers a cleanup function to be called by fatal()/fatal_cleanup()
 * before exiting. It is permissible to call fatal_remove_cleanup for the
 * function itself from the function.
 */
void    fatal_add_cleanup(void (*proc) (void *context), void *context);

/* Removes a cleanup function to be called at fatal(). */
void    fatal_remove_cleanup(void (*proc) (void *context), void *context);
```

`fatal()` is looking as deadly as ever with its `printf()` and `syslog()` calls
and cleanup routines. `grace_alarm_handler()` continues to call `fatal()`, so
not much has changed.

Next we come to `4cc240dabbd81a308f06f2717b1942041fe0e205`, made on July 4,
2021, which has a commit message indicating that a lot of comments were
removed from `.h` files, including `log.h`, "since they are cut&paste from
the .c files and out of sync". This again is by Ben Lindstrom.

```
// In file log.h:
/* Supported syslog facilities and levels. */
typedef enum {
  SYSLOG_FACILITY_DAEMON,
  SYSLOG_FACILITY_USER,
  SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
  SYSLOG_FACILITY_AUTHPRIV,
#endif
  SYSLOG_FACILITY_LOCAL0,
  SYSLOG_FACILITY_LOCAL1,
  SYSLOG_FACILITY_LOCAL2,
  SYSLOG_FACILITY_LOCAL3,
  SYSLOG_FACILITY_LOCAL4,
  SYSLOG_FACILITY_LOCAL5,
  SYSLOG_FACILITY_LOCAL6,
  SYSLOG_FACILITY_LOCAL7
}       SyslogFacility;

typedef enum {
  SYSLOG_LEVEL_QUIET,
  SYSLOG_LEVEL_FATAL,
  SYSLOG_LEVEL_ERROR,
  SYSLOG_LEVEL_INFO,
  SYSLOG_LEVEL_VERBOSE,
  SYSLOG_LEVEL_DEBUG1,
  SYSLOG_LEVEL_DEBUG2,
  SYSLOG_LEVEL_DEBUG3
}       LogLevel;

void     log_init(char *, LogLevel, SyslogFacility, int);

SyslogFacility  log_facility_number(char *);
LogLevel log_level_number(char *);

void     fatal(const char *, ...) __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     log(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));

void     fatal_cleanup(void);
void     fatal_add_cleanup(void (*) (void *), void *);
void     fatal_remove_cleanup(void (*) (void *), void *);
```

Interestingly, `log-server.c` is no more, and `do_log()` has moved into
`log.c`. The contents are still problematic with `printf()`-family calls and
`syslog()`. `grace_alarm_handler()` keeps calling `fatal()`.

We draw yet closer to the discovery of CVE-2006-5051, with commit
`3e33cecf71860f73656a73b754cc7b7b9ec0b0ce`, made by Darren Tucker on October 2,
2003. Quite a bit has changed, primarily because the linked list of cleanup
callbacks has been removed.

```c
// In file log.h:
void     fatal(const char *, ...) __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     logit(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));

void   do_log(LogLevel, const char *, va_list);
void   cleanup_exit(int);
```

`fatal()` has moved into its own file, `fatal.c`. `do_log()` is looking a bit
different:

```c
// In file log.c:
void
do_log(LogLevel level, const char *fmt, va_list args)
{
#ifdef OPENLOG_R
  struct syslog_data sdata = SYSLOG_DATA_INIT;
#endif
  char msgbuf[MSGBUFSIZ];
  char fmtbuf[MSGBUFSIZ];
  char *txt = NULL;
  int pri = LOG_INFO;

  if (level > log_level)
    return;

  switch (level) {
  case SYSLOG_LEVEL_FATAL:
    if (!log_on_stderr)
      txt = "fatal";
    pri = LOG_CRIT;
    break;
  case SYSLOG_LEVEL_ERROR:
    if (!log_on_stderr)
      txt = "error";
    pri = LOG_ERR;
    break;
  case SYSLOG_LEVEL_INFO:
    pri = LOG_INFO;
    break;
  case SYSLOG_LEVEL_VERBOSE:
    pri = LOG_INFO;
    break;
  case SYSLOG_LEVEL_DEBUG1:
    txt = "debug1";
    pri = LOG_DEBUG;
    break;
  case SYSLOG_LEVEL_DEBUG2:
    txt = "debug2";
    pri = LOG_DEBUG;
    break;
  case SYSLOG_LEVEL_DEBUG3:
    txt = "debug3";
    pri = LOG_DEBUG;
    break;
  default:
    txt = "internal error";
    pri = LOG_ERR;
    break;
  }
  if (txt != NULL) {
    snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", txt, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
  } else {
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
  }
  strnvis(fmtbuf, msgbuf, sizeof(fmtbuf), VIS_SAFE|VIS_OCTAL);
  if (log_on_stderr) {
    snprintf(msgbuf, sizeof msgbuf, "%s\r\n", fmtbuf);
    write(STDERR_FILENO, msgbuf, strlen(msgbuf));
  } else {
#ifdef OPENLOG_R
    openlog_r(argv0 ? argv0 : __progname, LOG_PID, log_facility, &sdata);
    syslog_r(pri, &sdata, "%.500s", fmtbuf);
    closelog_r(&sdata);
#else
    openlog(argv0 ? argv0 : __progname, LOG_PID, log_facility);
    syslog(pri, "%.500s", fmtbuf);
    closelog();
#endif
  }
}
```

`cleanup_exit()` has also changed significantly.

```c
// In file sshd.c:
/* server specific fatal cleanup */
void
cleanup_exit(int i)
{
  if (the_authctxt)
    do_cleanup(the_authctxt);
  _exit(i);
}
```

```c
// In file session.c:
void
do_cleanup(Authctxt *authctxt)
{
  static int called = 0;

  debug("do_cleanup");

  /* no cleanup if we're in the child for login shell */
  if (is_child)
    return;

  /* avoid double cleanup */
  if (called)
    return;
  called = 1;

  if (authctxt == NULL)
    return;
#ifdef KRB5
  if (options.kerberos_ticket_cleanup &&
      authctxt->krb5_ctx)
    krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
  if (compat20 && options.gss_cleanup_creds)
    ssh_gssapi_cleanup_creds();
#endif

  /* remove agent socket */
  auth_sock_cleanup_proc(authctxt->pw);

  /*
   * Cleanup ptys/utmp only if privsep is disabled,
   * or if running in monitor.
   */
  if (!use_privsep || mm_is_monitor())
    session_destroy_all(session_pty_cleanup2);
}
```

But most interestingly, `grace_alarm_handler()` has finally gotten some
much-needed recognition as a troublemaker:

```c
// In file sshd.c:
/*
 * Signal handler for the alarm after the login grace period has expired.
 */
static void
grace_alarm_handler(int sig)
{
  /* XXX no idea how fix this signal handler */

  /* Log error and exit. */
  fatal("Timeout before authentication for %s", get_remote_ipaddr());
}
```

Apparently this function remained in this "no idea how to fix" state for
another three years... whether it was clear to developers that there was a
vuln or not is not immediately apparent, but it looks like some problems were
now known.

Next we have commit `efa62f98a140e238256c2f75f4cd8a282fe802a3`, made by Darren
Tucker on June 22, 2004. Not much interesting has changed, except for
`grace_alarm_handler()` has gotten a bit more tweaking:

```c
// In file sshd.c:
/*
 * Signal handler for the alarm after the login grace period has expired.
 */
static void
grace_alarm_handler(int sig)
{
  /* XXX no idea how fix this signal handler */

  if (use_privsep && pmonitor != NULL && pmonitor->m_pid > 0)
    kill(pmonitor->m_pid, SIGALRM);

  /* Log error and exit. */
  fatal("Timeout before authentication for %s", get_remote_ipaddr());
}
```

And now, at long last, we arrive at a glimmer of hope, in commit
`99a648e59291d3adb39eeee4fa1f8a5b2ee2d769`, committed by Damien Miller but
actually authored by OpenBSD's head developer Theo de Raadt:

```
commit 99a648e59291d3adb39eeee4fa1f8a5b2ee2d769
Author: Damien Miller <djm@mindrot.org>
Date:   Sat Aug 19 00:32:20 2006 +1000

       - deraadt@cvs.openbsd.org 2006/08/18 09:13:26
         [log.c log.h sshd.c]
         make signal handler termination path shorter; risky code pointed out by
         mark dowd; ok djm markus
```

We see the introduction of a new function, `sigdie()`:

```c
// In file log.h:
void     fatal(const char *, ...) __dead __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     sigdie(const char *, ...) __attribute__((format(printf, 1, 2)));
void     logit(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));

void   do_log(LogLevel, const char *, va_list);
void   cleanup_exit(int) __dead;
```

```c
// In file log.c:
void
sigdie(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  _exit(1);
}
```

Comparing this with `fatal()`, this is essentially the same thing as `fatal()`
but without the cleanup calls. `grace_alarm_handler()` has been tweaked to use
this new "give up and die" call:

```c
// In file sshd.c:
/*
 * Signal handler for the alarm after the login grace period has expired.
 */
/*ARGSUSED*/
static void
grace_alarm_handler(int sig)
{
  if (use_privsep && pmonitor != NULL && pmonitor->m_pid > 0)
    kill(pmonitor->m_pid, SIGALRM);

  /* Log error and exit. */
  sigdie("Timeout before authentication for %s", get_remote_ipaddr());
}
```

Of course, `syslog()` is still being called via `do_log()`, so this isn't
quite fixed yet, but we're getting closer at least.

And finally, we arrive at our final destination, the fix for CVE-2006-5051, in
commit `bb59814cd644f78e82df07d820ed00fa7a25e68a`, by Damien Miller on August
19, 2006:

```
commit bb59814cd644f78e82df07d820ed00fa7a25e68a (HEAD)
Author: Damien Miller <djm@mindrot.org>
Date:   Sat Aug 19 08:38:23 2006 +1000

     - (djm) Disable sigdie() for platforms that cannot safely syslog inside
       a signal handler (basically all of them, excepting OpenBSD);
       ok dtucker@
```

This commit, unlike the previous one, is authored by Miller, not by de Raadt.

```
// In file log.c:
void
sigdie(const char *fmt,...)
{
  va_list args;

#ifdef DO_LOG_SAFE_IN_SIGHAND
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
#endif
  _exit(1);
}
```

`DO_LOG_SAFE_IN_SIGHAND` is only defined if `SYSLOG_R_SAFE_IN_SIGHAND` is
defined, and that only gets defined on OpenBSD, where `syslog_r()` can be
safely called in a signal handler. With this, the vulnerability is finally
fixed. (At least, we hope. `grace_alarm_handler()` is calling
`get_remote_ipaddr()` which is a relatively long-winded codepath. Every single
thing in this codepath needs to be async-signal-safe to avoid another
potential vulnerability, but investigating this is left as an exercise to the
reader, mainly because openssh-portable upstream no longer does this.)

The next commit we come to is `f8b7eb7c3c77625845f4e2a844cc57c0496d414e`, by
Darren Tucker on Jun 13, 2008. This is mostly just some attribute tweaks:

```c
// In file log.h:
void     fatal(const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     sigdie(const char *, ...)  __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     logit(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));

void   do_log(LogLevel, const char *, va_list);
void   cleanup_exit(int) __attribute__((noreturn));
```

The OpenSSH logging mechanisms surrounding `fatal()` and `sigdie()` then
basically stayed static for the next 12 years.

## The introduction of regreSSHion

Jumping forward to the next change, we get to commit
`752250caabda3dd24635503c4cd689b32a650794`, the commit which introduced
regreSSHion:

```
commit 752250caabda3dd24635503c4cd689b32a650794 (HEAD)
Author: djm@openbsd.org <djm@openbsd.org>
Date:   Fri Oct 16 13:24:45 2020 +0000

    upstream: revised log infrastructure for OpenSSH

    log functions receive function, filename and line number of caller.
    We can use this to selectively enable logging via pattern-lists.

    ok markus@

    OpenBSD-Commit-ID: 51a472610cbe37834ce6ce4a3f0e0b1ccc95a349
```

Looking in OpenBSD's upstream code, we find that this corresponds to commit
`321d5b75a2584757f5e5ced8f753f14b156d338a` in
[openbsd/src](https://github.com/openbsd/src):

```
commit 321d5b75a2584757f5e5ced8f753f14b156d338a
Author: djm <djm@openbsd.org>
Date:   Fri Oct 16 13:24:45 2020 +0000

    revised log infrastructure for OpenSSH

    log functions receive function, filename and line number of caller.
    We can use this to selectively enable logging via pattern-lists.

    ok markus@
```

This confirms that the author of the code change is indeed Miller.

`log.h` has been massively overhauled:

```c
// In file log.h:
void     log_init(char *, LogLevel, SyslogFacility, int);
LogLevel log_level_get(void);
int      log_change_level(LogLevel);
int      log_is_on_stderr(void);
void     log_redirect_stderr_to(const char *);
void   log_verbose_add(const char *);
void   log_verbose_reset(void);

SyslogFacility  log_facility_number(char *);
const char *  log_facility_name(SyslogFacility);
LogLevel  log_level_number(char *);
const char *  log_level_name(LogLevel);

void   set_log_handler(log_handler_fn *, void *);
void   cleanup_exit(int) __attribute__((noreturn));

void   sshlog(const char *, const char *, int, int,
    LogLevel, const char *, ...) __attribute__((format(printf, 6, 7)));
void   sshlogv(const char *, const char *, int, int,
    LogLevel, const char *, va_list);
void   sshsigdie(const char *, const char *, int, const char *, ...)
    __attribute__((noreturn)) __attribute__((format(printf, 4, 5)));
void   sshlogdie(const char *, const char *, int, const char *, ...)
    __attribute__((noreturn)) __attribute__((format(printf, 4, 5)));
void   sshfatal(const char *, const char *, int, const char *, ...)
    __attribute__((noreturn)) __attribute__((format(printf, 4, 5)));

#define ssh_nlog(level, ...)  sshlog(__FILE__, __func__, __LINE__, 0, level, __VA_ARGS__)
#define ssh_debug3(...)   sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
#define ssh_debug2(...)   sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
#define ssh_debug(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
#define ssh_verbose(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
#define ssh_log(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
#define ssh_error(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_fatal(...)    sshfatal(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define ssh_logdie(...)   sshlogdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define ssh_sigdie(...)   sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)

#define debug ssh_debug
#define debug1  ssh_debug1
#define debug2  ssh_debug2
#define debug3  ssh_debug3
#define error ssh_error
#define logit ssh_log
#define verbose ssh_verbose
#define fatal ssh_fatal
#define logdie  ssh_logdie
#define sigdie  ssh_sigdie
#define do_log2 ssh_nlog
```

Most of this is clever preprocessor magic that makes it possible to record in
logs the exact file, function, and line number where a particular error or
condition was hit. When something like `sigdie()` is written in the code, the
preprocessor will rewrite it to something along the lines of
`ssh_sigdie("/path/to/file", "function", "1234", ...)`, which will then be
rewritten again to `sshsigdie("/path/to/file", "function", "1234", ...)`. This
allows detailed debugging info to be logged without requiring any extra work
from the programmer. Without going through macros, this would require
extremely repetitive and error-prone code, so this is very useful.

It is curious why the logging functions go through two layers of macro
indirection though; it seems like the macros here could have been written as
`#define sigdie(...)   sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)`
to achieve the same result. One plausible explanation for the more complicated
indirection is that not all of the original function names map to new function
names in an obvious one-to-one fashion, so this provides a map of how the old
names match with the new names. This could also have been done to allow the
underlying macro names to change without mandating mass-refactoring of the
codebase. Keeping things decoupled is good. Those things being said, this
indirection layer seems to have been added in a somewhat sloppy manner, as
`debug1` points to `ssh_debug1`, which looks like it should be a macro but
isn't defined anywhere:

```
$ grep -ri 'ssh_debug1'
log.h:#define debug1    ssh_debug1
```

To verify that the simpler macro definitions would have worked, I tried
writing a patch on top of the regreSSHion-introducing commit to simplify
things. There were a couple of `sshfatal()` functions that needed changed, but
those were rather trivial to fix:

```
diff --git a/fatal.c b/fatal.c
index 3ecd510f1..9cc8c74b4 100644
--- a/fatal.c
+++ b/fatal.c
@@ -39,7 +39,7 @@ sshfatal(const char *file, const char *func, int line, const char *fmt, ...)
        va_list args;

        va_start(args, fmt);
-       ssh_log(file, func, line, SYSLOG_LEVEL_FATAL, fmt, args);
+       sshlogv(file, func, line, 0, SYSLOG_LEVEL_FATAL, fmt, args);
        va_end(args);
        cleanup_exit(255);
 }
diff --git a/log.h b/log.h
index b1ab7c7e0..822c5571c 100644
--- a/log.h
+++ b/log.h
@@ -78,27 +78,15 @@ void         sshlogdie(const char *, const char *, int, const char *, ...)
 void    sshfatal(const char *, const char *, int, const char *, ...)
     __attribute__((noreturn)) __attribute__((format(printf, 4, 5)));

-#define ssh_nlog(level, ...)   sshlog(__FILE__, __func__, __LINE__, 0, level, __VA_ARGS__)
-#define ssh_debug3(...)                sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
-#define ssh_debug2(...)                sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
-#define ssh_debug(...)         sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
-#define ssh_verbose(...)       sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
-#define ssh_log(...)           sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
-#define ssh_error(...)         sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
-#define ssh_fatal(...)         sshfatal(__FILE__, __func__, __LINE__, __VA_ARGS__)
-#define ssh_logdie(...)                sshlogdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
-#define ssh_sigdie(...)                sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
-
-#define debug  ssh_debug
-#define debug1 ssh_debug1
-#define debug2 ssh_debug2
-#define debug3 ssh_debug3
-#define error  ssh_error
-#define logit  ssh_log
-#define verbose        ssh_verbose
-#define fatal  ssh_fatal
-#define logdie ssh_logdie
-#define sigdie ssh_sigdie
-#define do_log2        ssh_nlog
+#define debug(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
+#define debug2(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
+#define debug3(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
+#define error(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
+#define logit(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
+#define verbose(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
+#define fatal(...)  sshfatal(__FILE__, __func__, __LINE__, __VA_ARGS__)
+#define logdie(...)  sshlogdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
+#define sigdie(...)  sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
+#define do_log2(level, ...)  sshlog(__FILE__, __func__, __LINE__, 0, level, __VA_ARGS__)

 #endif
diff --git a/ssh-keyscan.c b/ssh-keyscan.c
index ac7bfcd18..cbc8080fe 100644
--- a/ssh-keyscan.c
+++ b/ssh-keyscan.c
@@ -8,7 +8,7 @@
  */

 #include "includes.h"
-
+
 #include <sys/types.h>
 #include "openbsd-compat/sys-queue.h"
 #include <sys/resource.h>
@@ -641,7 +641,7 @@ sshfatal(const char *file, const char *func, int line,
        va_list args;

        va_start(args, fmt);
-       ssh_log(file, func, line, SYSLOG_LEVEL_FATAL, fmt, args);
+       sshlogv(file, func, line, 0, SYSLOG_LEVEL_FATAL, fmt, args);
        va_end(args);
        cleanup_exit(255);
 }
```

This code built successfully and produced `ssh` and `sshd` binaries. I did not
test the resulting binaries.

Anyway, `log.h` seems like it changed in an overall good fashion, except for
the sloppy and unnecessary second layer of indirection. Things aren't quite as
great when looking at log.c. To fully appreciate the issue here, one has to
look at a section of the commit diff, not the code files themselves:

```diff
diff --git a/log.c b/log.c
index 6b1a7a314..159c306de 100644
--- a/log.c
+++ b/log.c
@@ -1,4 +1,4 @@
-/* $OpenBSD: log.c,v 1.52 2020/07/03 06:46:41 djm Exp $ */
+/* $OpenBSD: log.c,v 1.53 2020/10/16 13:24:45 djm Exp $ */
 /*
  * Author: Tatu Ylonen <ylo@cs.hut.fi>
  * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
@@ -51,6 +51,7 @@
 #endif

 #include "log.h"
+#include "match.h"

 static LogLevel log_level = SYSLOG_LEVEL_INFO;
 static int log_on_stderr = 1;
@@ -59,6 +60,8 @@ static int log_facility = LOG_AUTH;
 static char *argv0;
 static log_handler_fn *log_handler;
 static void *log_handler_ctx;
+static char **log_verbose;
+static size_t nlog_verbose;

 extern char *__progname;

@@ -157,96 +160,30 @@ log_level_name(LogLevel level)
 	return NULL;
 }

-/* Error messages that should be logged. */
-
-void
-error(const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_ERROR, fmt, args);
-	va_end(args);
-}
-
-void
-sigdie(const char *fmt,...)
-{
-#ifdef DO_LOG_SAFE_IN_SIGHAND
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_FATAL, fmt, args);
-	va_end(args);
-#endif
-	_exit(1);
-}
-
-void
-logdie(const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_INFO, fmt, args);
-	va_end(args);
-	cleanup_exit(255);
-}
-
-/* Log this message (information that usually should go to the log). */
-
-void
-logit(const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_INFO, fmt, args);
-	va_end(args);
-}
-
-/* More detailed messages (information that does not need to go to the log). */
-
-void
-verbose(const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_VERBOSE, fmt, args);
-	va_end(args);
-}
-
-/* Debugging messages that should not be logged during normal operation. */
-
-void
-debug(const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_DEBUG1, fmt, args);
-	va_end(args);
-}
-
 void
-debug2(const char *fmt,...)
+log_verbose_add(const char *s)
 {
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_DEBUG2, fmt, args);
-	va_end(args);
+	char **tmp;
+
+	/* Ignore failures here */
+	if ((tmp = recallocarray(log_verbose, nlog_verbose, nlog_verbose + 1,
+	    sizeof(*log_verbose))) != NULL) {
+		log_verbose = tmp;
+		if ((log_verbose[nlog_verbose] = strdup(s)) != NULL)
+			nlog_verbose++;
+	}
 }

 void
-debug3(const char *fmt,...)
+log_verbose_reset(void)
 {
-	va_list args;
+	size_t i;

-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_DEBUG3, fmt, args);
-	va_end(args);
+	for (i = 0; i < nlog_verbose; i++)
+		free(log_verbose[i]);
+	free(log_verbose);
+	log_verbose = NULL;
+	nlog_verbose = 0;
 }

 /*
@@ -395,18 +332,9 @@ set_log_handler(log_handler_fn *handler, void *ctx)
 	log_handler_ctx = ctx;
 }

-void
-do_log2(LogLevel level, const char *fmt,...)
-{
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(level, fmt, args);
-	va_end(args);
-}
-
-void
-do_log(LogLevel level, const char *fmt, va_list args)
+static void
+do_log(const char *file, const char *func, int line, LogLevel level,
+    int force, const char *fmt, va_list args)
 {
 #if defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
 	struct syslog_data sdata = SYSLOG_DATA_INIT;
@@ -418,7 +346,7 @@ do_log(LogLevel level, const char *fmt, va_list args)
 	int saved_errno = errno;
 	log_handler_fn *tmp_handler;

-	if (level > log_level)
+	if (!force && level > log_level)
 		return;

 	switch (level) {
@@ -467,7 +395,7 @@ do_log(LogLevel level, const char *fmt, va_list args)
 		/* Avoid recursion */
 		tmp_handler = log_handler;
 		log_handler = NULL;
-		tmp_handler(level, fmtbuf, log_handler_ctx);
+		tmp_handler(file, func, line, level, fmtbuf, log_handler_ctx);
 		log_handler = tmp_handler;
 	} else if (log_on_stderr) {
 		snprintf(msgbuf, sizeof msgbuf, "%.*s\r\n",
@@ -486,3 +414,64 @@ do_log(LogLevel level, const char *fmt, va_list args)
 	}
 	errno = saved_errno;
 }
+
+void
+sshlog(const char *file, const char *func, int line, int showfunc,
+    LogLevel level, const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	sshlogv(file, func, line, showfunc, level, fmt, args);
+	va_end(args);
+}
+
+void
+sshlogdie(const char *file, const char *func, int line, const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	sshlogv(file, func, line, 0, SYSLOG_LEVEL_INFO, fmt, args);
+	va_end(args);
+	cleanup_exit(255);
+}
+
+void
+sshsigdie(const char *file, const char *func, int line, const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	sshlogv(file, func, line, 0, SYSLOG_LEVEL_FATAL, fmt, args);
+	va_end(args);
+	_exit(1);
+}
+
+void
+sshlogv(const char *file, const char *func, int line, int showfunc,
+    LogLevel level, const char *fmt, va_list args)
+{
+	char tag[128], fmt2[MSGBUFSIZ + 128];
+	int forced = 0;
+	const char *cp;
+	size_t i;
+
+	snprintf(tag, sizeof(tag), "%.48s:%.48s():%d",
+	    (cp = strrchr(file, '/')) == NULL ? file : cp + 1, func, line);
+	for (i = 0; i < nlog_verbose; i++) {
+		if (match_pattern_list(tag, log_verbose[i], 0) == 1) {
+			forced = 1;
+			break;
+		}
+	}
+
+	if (log_handler == NULL && forced)
+		snprintf(fmt2, sizeof(fmt2), "%s: %s", tag, fmt);
+	else if (showfunc)
+		snprintf(fmt2, sizeof(fmt2), "%s: %s", func, fmt);
+	else
+		strlcpy(fmt2, fmt, sizeof(fmt2));
+
+	do_log(file, func, line, level, forced, fmt2, args);
+}
```

This is *a lot* of changes, which unfortunately is part of how this managed to
slip through code review. Of special significance, we see that `sigdie()` has
been deleted:

```diff
-void
-sigdie(const char *fmt,...)
-{
-#ifdef DO_LOG_SAFE_IN_SIGHAND
-	va_list args;
-
-	va_start(args, fmt);
-	do_log(SYSLOG_LEVEL_FATAL, fmt, args);
-	va_end(args);
-#endif
-	_exit(1);
-}
```

And then way further down in the diff, we see its successor, `sshsigdie()`:

```diff
+void
+sshsigdie(const char *file, const char *func, int line, const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	sshlogv(file, func, line, 0, SYSLOG_LEVEL_FATAL, fmt, args);
+	va_end(args);
+	_exit(1);
+}
```

Notice that the `#ifdef DO_LOG_SAFE_IN_SIGHAND` line and its matching `#endif`
have vanished. This basically puts us back to where we were in Theo de Raadt's
commit `99a648e59291d3adb39eeee4fa1f8a5b2ee2d769`, which introduced `sigdie`
as a variant of `fatal()` but without calling cleanup functionality. Indeed,
if we look at the new `sshfatal()`, we see that it's now the exact same thing
as `sigdie()` but with a cleanup call:

```c
// In file fatal.c:
void
sshfatal(const char *file, const char *func, int line, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ssh_log(file, func, line, SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```

We can also see that `ssh_log()` is called rather than `sshlogv()`, but as it
turns out this ends up being little more than an alias for `sshlogv()`:

```c
// In file log.h:
#define ssh_log(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
```

```c
// In file log.c:
void
sshlog(const char *file, const char *func, int line, int showfunc,
    LogLevel level, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  sshlogv(file, func, line, showfunc, level, fmt, args);
  va_end(args);
}
```

Why `fatal.c` doesn't just use `sshlogv()` directly is not apparent, it would
definitely be an easier code path to trace. Indeed, `sshlogdie()` takes
exactly that approach:

```c
// In file log.c:
void
sshlogdie(const char *file, const char *func, int line, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  sshlogv(file, func, line, 0, SYSLOG_LEVEL_INFO, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```

The only difference between this and `sshfatal()` is that it uses a different
syslog level, and it calls `sshlogv()` more directly. At any rate, this is a
bit of a tangent. We can say confidently that `sshsigdie()` now does nothing
different than `sshfatal()` except for skipping the cleanup function. We've
gone back to calling `printf()`-family functions and `syslog()`, and of course
our good friend `grace_alarm_handler()` is calling this now-dangerous code
path:

```c
// In file sshd.c:
/*
 * Signal handler for the alarm after the login grace period has expired.
 */
/*ARGSUSED*/
static void
grace_alarm_handler(int sig)
{
  if (use_privsep && pmonitor != NULL && pmonitor->m_pid > 0)
    kill(pmonitor->m_pid, SIGALRM);

  /*
   * Try to kill any processes that we have spawned, E.g. authorized
   * keys command helpers.
   */
  if (getpgid(0) == getpid()) {
    ssh_signal(SIGTERM, SIG_IGN);
    kill(0, SIGTERM);
  }

  /* XXX pre-format ipaddr/port so we don't need to access active_state */
  /* Log error and exit. */
  sigdie("Timeout before authentication for %s port %d",
      ssh_remote_ipaddr(the_active_state),
      ssh_remote_port(the_active_state));
}
```

And that is how regreSSHion was introduced.

## Guessing the rationale behind the vulnerable commit's design

At this point we end up with a couple of rather obvious questions; how did the
`#ifdef` get dropped, and why were the `sshlogdie()` and `sshsigdie()`
functions moved? There are several plausible answers that could be given here:

* Miller maliciously removed the `#ifdef` lines on purpose, then moved the
  functions so that the bug would be harder to notice.
* Miller deleted the functions, then rewrote them from scratch using the newly
  introduced `sshlog()` as a template. They were rewritten under `sshlog()`
  because that was the most intuitive place to put them, and because the
  `#ifdef` solution from 2006 was a bit of a hack, it was forgotten during the
  rewrite.
* Miller forgot that the lines were important or necessary, since he was
  develping for OpenBSD which doesn't have issues writing to the system log in
  a signal handler.
* Miller intended to keep the `#ifdef` lines, but had to remove them for
  debugging purposes (perhaps he was developing on a Linux machine and wanted
  to see logs to make sure things were working right), and then forgot to add
  them back before committing and pushing.

The fourth answer would be the easiest explanation, since virtually every
programmer has accidentally pushed testing code to production (like the time I
unintentionally pushed a change embedding my own GPG key into a list of
trusted keys in the Kicksecure build system). This explanation unfortunately
seems rather unlikely, as Miller committed this change into OpenBSD and
openssh-portable simultaneously, as can be seen looking at the git logs above.
(the commits were made on the exact same second). OpenBSD can safely call
logging functionality in a signal handler, so assuming the code was tested
on OpenBSD (which would be likely for a code change committed into OpenBSD's
codebase), those lines would not have needed to be removed in order to test.

The first answer is obviously the worst. If Miller maliciously removed the
code, OpenSSH as a whole (and potentially OpenBSD as a whole) could
potentially contain similar intentional "bug backdoors". The project would
have to be considered untrusted until such a time as it underwent whatever
reforms were necessary to ensure this sort of thing didn't happen again. But
given OpenBSD's reputation, assuming the worst is likely not a great idea.

For the third answer, Miller would have been looking right at the `#ifdef`
lines, probably multiple times in the course of such an in-depth rewrite of
logging functionality. The only reason those lines existed was for non-OpenBSD
platforms. It's quite easy to discover this by just tracing the define back to
its source:

```c
// In file defines.h:
#if defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT) && \
    defined(SYSLOG_R_SAFE_IN_SIGHAND)
# define DO_LOG_SAFE_IN_SIGHAND
#endif
```

```
# In file configure.ac (notably, this file has Damien Miller specified as the
# copyright owner)
*-*-openbsd*)
  use_pie=auto
  AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
  AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
  AC_DEFINE([SSH_TUN_OPENBSD], [1], [Open tunnel devices the OpenBSD way])
  AC_DEFINE([SYSLOG_R_SAFE_IN_SIGHAND], [1],
      [syslog_r function is safe to use in in a signal handler])
  TEST_MALLOC_OPTIONS="AFGJPRX"
  ;;
```

Just "forgetting" non-OpenBSD platforms for such a critical piece of code
would be rather alarming. If the third answer is correct, it's very
disappointing.

The second answer is the most plausible, but still disappointing. Miller would
have been able to see that `sshfatal()` and `sshsigdie()` were virtually
identical (or at least, he hopefully would have seen that - perhaps the
indirection with `ssh_log()` would have obscured that from himself). This
should have been a warning that the functions' differences were probably
important, or that one or the other of them could be removed during
refactoring. Had he looked to see why the cleanup functions were skipped in
`sshsigdie()`, he would have probably noticed `grace_alarm_handler()`, which
would have given a good hint as to why the `#ifdef` lines were present in the
original `sigdie()`. Missing all of this would have required Miller to
basically blindly delete the original functions, rewrite them without context,
and fail to check where they were used. The reviewer also would have to have
been somewhat careless in their review - it wouldn't have taken much to have
seen that `sigdie()` had become `sshsigdie()`, and then compare them
side-by-side using a tool like Meld. Given Miller's highly privileged position
though, a semi-careless review is excusable. The coding practices in these
circumstances are not nearly as excusable.

There are also arguments to be made in favor of this being a malicious change.
The confusing indirection with `ssh_log()`, `sshlog()`, `sshlogv()`,
`fatal()`, and `sshlogdie()` all make it a headache to analyze this code
carefully (this probably took me fiftten or twenty minutes to unravel), which
one could argue would encourage a more careless review. The fact that this was
done in a commit intended to improve OpenSSH's log infrastructure is also
weird, since one would expect a commit like this to make the logging systems
more clear, not less. `sshsigdie()` looks an awful lot like a tweaked copy of
`sigdie()` at first glance, and if it *is* a copy, then the only plausible
explanation for how the `#ifdef` got removed was that it was deleted on
purpose. And while one can use time as an excuse here, the fact that Miller is
not only the one who broke this, but also the one who originally fixed this
approximately 14 years earlier, is strange. If anyone had a decent chance of
remembering why the `#ifdef` was there, it would have been Miller.

To top off an already ugly situation, OpenSSH "fixed" this vulnerability, not
by adding back the missing `#ifdef`, but by doing *another* massive overhaul
to the logging functionality, in commit
`81c1099d22b81ebfd20a334ce986c4f753b0db29`. This commit is huge and
complicated enough I will not waste space by pasting the diff or waste time by
investigating how it works under the hood. The commit on Github is
[here](https://github.com/openssh/openssh-portable/commit/81c1099d22b81ebfd20a334ce986c4f753b0db29)
if you're interested in that. I will paste the commit message though:

```
commit 81c1099d22b81ebfd20a334ce986c4f753b0db29 (HEAD)
Author: djm@openbsd.org <djm@openbsd.org>
Date:   Thu Jun 6 17:15:25 2024 +0000

    upstream: Add a facility to sshd(8) to penalise particular

    problematic client behaviours, controlled by two new sshd_config(5) options:
    PerSourcePenalties and PerSourcePenaltyExemptList.

    When PerSourcePenalties are enabled, sshd(8) will monitor the exit
    status of its child pre-auth session processes. Through the exit
    status, it can observe situations where the session did not
    authenticate as expected. These conditions include when the client
    repeatedly attempted authentication unsucessfully (possibly indicating
    an attack against one or more accounts, e.g. password guessing), or
    when client behaviour caused sshd to crash (possibly indicating
    attempts to exploit sshd).

    When such a condition is observed, sshd will record a penalty of some
    duration (e.g. 30 seconds) against the client's address. If this time
    is above a minimum threshold specified by the PerSourcePenalties, then
    connections from the client address will be refused (along with any
    others in the same PerSourceNetBlockSize CIDR range).

    Repeated offenses by the same client address will accrue greater
    penalties, up to a configurable maximum. A PerSourcePenaltyExemptList
    option allows certain address ranges to be exempt from all penalties.

    We hope these options will make it significantly more difficult for
    attackers to find accounts with weak/guessable passwords or exploit
    bugs in sshd(8) itself.

    PerSourcePenalties is off by default, but we expect to enable it
    automatically in the near future.

    much feedback markus@ and others, ok markus@

    OpenBSD-Commit-ID: 89ded70eccb2b4926ef0366a4d58a693de366cca
```

According to Github, this change added 982 lines of code, and removed 93. That
doesn't sound even remotely like something I'd want to backport. This
extraordinary "fix" for a relatively simple problem was noted by Qualys, who
stated in their vulnerability report:

```
Because this fix is part of a large commit (81c1099), on top of an even
larger defense-in-depth commit (03e3de4, "Start the process of splitting
sshd into separate binaries"), it might prove difficult to backport. In
that case, the signal handler race condition itself can be fixed by
removing or commenting out the async-signal-unsafe code from the
sshsigdie() function...
```

They then go on to recommend using `#if 0` to make the compiler ignore the
parts of `sshsigdie` that cause it to log, making it nothing more than a
wrapper around `_exit()`.

The fact that the vulnerability fix was done in this way is not in itself a
problem. It's not even necessarily a problem in combination with the rest of
this information. But even this is done in a sloppy way -
`SYSLOG_R_SAFE_IN_SIGHAND` is still being defined even in today's
openssh-portable git master (commit
`5e4bfe6c16924b1c21a733f3e218cfcba98e301e`, authored by Damien Miller, dated
July 26, 2025), as is `DO_LOG_SAFE_IN_SIGHAND`. Neither of these are used for
anything any longer. It's as if the original fix has simply been forgotten and
left to rot.

## Maintainer behavior in the wake of regreSSHion

Looking at Miller's public Mastodon profile at https://cybervillains.com/@djm,
we can find some posts that appear to relate to regreSSHion. The most recent
one, from August 12, 2024, reads:

```
Link: https://cybervillains.com/@djm/112948935022292399

Whom amongst us _hasn't_ added an unsafe function to a sshd signal handler?

https://www.freebsd.org/security/advisories/FreeBSD-SA-24:08.openssh.asc
```

Another one, from July 1, 2024, the day of the disclosure:

```
Link: https://cybervillains.com/@djm/112710943371316387

I'm extremely grateful that there are excellent security researchers like the
Qualys person/team and Google Project Zero who are putting their work into the
public domain.

An unfortunately large chunk of vulnerability research has "gone dark" and
sells their findings to buyers that include intelligence agencies in
repressive regimes and organised crime groups.

OSS attracting top-tier adversarial research is IMO necessary for its
survival. IDK what would happen if it dried up...
```

And a short thread, for the OpenSSH 9.8 release announcement:

```
Link: https://cybervillains.com/@djm/112710220020323435

OpenSSH 9.8 has just been released. This release includes a fix for a critical
race condition in sshd that could be exploited for remote code execution so
you should definitely patch or upgrade. It also contains a fix for a minor
issue in ssh that saw the recently-added ObscureKeystrokeTiming feature work
the opposite way as intended.

There are some new features too. Please see the release notes at
https://openssh.com/releasenotes.html for more details

---

Lots more details on exploitation of the critical vulnerability in Qualys'
report: https://www.qualys.com/2024/07/01/cve-2024

```

## Conclusions

Based on the analysis of the code introduced in the regreSSHion vulnerability,
there seem to be two plausible explanations for how the vulnerability was
introduced. Either, the vulnerability was introduced intentionally, or it was
introduced because of a rather surprising lack of care on the part of both
developers and reviewers.

It isn't easy to overlook the sloppiness some of the changes here were made
with. The confusing nature of the original rewrite is also hard to ignore. And
this is not the only somewhat alarming code present in ssh either. `umac.c`,
for instance, contains the following somewhat scary comment:

```c
// In file umac.c:
  * 5) With FORCE_C_ONLY flags set to 0, incorrect results are sometimes
  * produced under gcc with optimizations set -O3 or higher. Dunno why.
```

In my opinion, the fact that malicious behavior cannot be conclusively proven
or disproven is not really of much consequence at this point. Even if
regreSSHion's introduction wasn't malicious (and there's several reasons to
think it may have been), the way in which this code is being managed is
unreasonably careless, and, if the impact of regreSSHion is any indicator,
arguably reckless. Coming from the developers of an OS that advertises loudly
"Only two remote holes in the default install, in a heck of a long time!",
this is far from what a security-conscious user would expect. (Not to mention
the fact that this claim is no longer even true - OpenSSH is part of the
OpenBSD default install, regreSSHion is a remote hole, and the second remote
hole in OpenBSD was discovered in 2007, so this claim needs to be updated to
specify at least three remote holes now.)

In conclusion, I do not consider OpenSSH to be safe against nation-state level
adversaries or powerful, motivated attackers any longer. From 1999 to 2006, it
carried a remotely exploitable race condition allowing arbitrary code
execution, and then the vuln was reintroduced and open between 2020 and 2024.
That's a total of between 8 and 10 years of being vulnerable, all because of
one signal handler that was being used in an incorrect and unsafe manner, with
development practices that were clearly not in a security-conscious user's
best interest.

What should be done going forward? I am reluctant to simply say "switch to a
different SSH implementation", since if experience is any indicator, secure,
well-written code is relatively rare. For now the best that can be done is
probably to ensure that your servers and clients that use SSH are regularly
kept up-to-date, keep highly critical information airgapped, and consider
using isolation-based security measures like Qubes OS where possible. In the
long run though, either OpenSSH needs to shape up, or it needs replaced. For
something that is so core to the security of our systems and the Internet at
large, this is not acceptable.

---

# DO NOT PUBLISH ANYTHING BELOW THIS LINE

---

# Appendix A: "Security analysis of CVE-2024-6387 - regreSSHion"

This is a transcription of the report received by the Kicksecure and Whonix
developers. Some typos in the original have been corrected, and the format
changed from a PDF document to Markdown, but the meaningful content of the
original has been preserved in its entirety.

## Security analysis of CVE-2024-6387 - regreSSHion

### Executive summary

This analysis concludes that with a high probability the regression of the
vulnerability CVE-2006-5051 that is reintroduced as CVE-2024-6387 into the
OpenSSH codebase was done **on purpose** by one of the lead developers.
Putting the credibility of the project into question, not only as to solving
CVE-2024-6387 but also further development. Hence, we have changed our
recommendation from "update to latest version" to "**decommission and
replace**".

### Background

OpenSSH is perhaps the most important tool worldwide, it's the cornerstone in
the modern digital world. On the 1st of July a CVE, tagged as
[CVE-2024-6387](https://ubuntu.com/security/CVE-2024-6387) was disclosed, it
exposes a vulnerability, link
[here](https://github.com/openssh/openssh-portable/commit/752250caabda3dd24635503c4cd689b32a650794),
that has been checked-in by [Damien Miller](https://github.com/djmdjm), one of
the lead developers of OpenSSH, more info about OpenSSH
[here](https://www.openssh.com/history.html). This vulnerability is a
reintroduction of an old CVE-2006-5051 link
[here](https://nvd.nist.gov/vuln/detail/CVE-2006-5051).

### Understanding CVE-2006-5051, and OpenSSH logging

To make a proper analysis of the latest CVE we first need to understand the
history behind CVE-2006-5051. Now this vulnerability is a specific set of
vulnerabilities called race conditions. In this case we are talking about race
conditions that are connected to logging. Checking "log.h" before
CVE-2006-5051 was mitigated we find that OpenSSH has a straightforward logging
mechanism. It consists of six log functions, defined in "log.c" and one
function, "fatal", defined in "fatal.c" that logs and then exits.

```c
void     fatal(const char *, ...) __dead __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     logit(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));
```

The vulnerability is triggered when "fatal" is called in a non-thread safe
way, this behavior is OS dependent, and Linux is vulnerable. To fix this
problem a new function, sigdie is introduced, and implemented in log.c. This
is done
[here](https://github.com/openssh/openssh-portable/commit/99a648e59291d3adb39eeee4fa1f8a5b2ee2d769),
and
[here](https://github.com/openssh/openssh-portable/commit/bb59814cd644f78e82df07d820ed00fa7a25e68a).

```c
void
sigdie(const char *fmt,...)
{
  va_list args;

#ifdef DO_LOG_SAFE_IN_SIGHAND
  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
#endif
  _exit(1);
}
```
log.c (bb59814c)

```c
void
fatal(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```
fatal.c

```c
/* default implementation */
void
cleanup_exit(int i)
{
  _exit(i);
}
```

As shown above, "sigdie" and "fatal" are almost the same, the big difference
is that the "#ifdef" disables logging on systems that are seen as unsafe.
There is a difference in exit state, but this only reflects the fact that the
error is not written to the log. As we can see in both cases the author is
Damien Miller. As a side note, the "#ifdef" is moved one line up to avoid a
warning, check-in
[here](https://github.com/openssh/openssh-portable/commit/aa1517ca1e7e71070b77357626c87dcf9ee30697).

In conclusion the method "sigdie" was introduced by Damien Miller specifically
to mitigate CVE-2006-5051, and it's a copy of fatal with the "#ifdef" used to
remove the unsafe logging on vulnerable systems.

### Before the check-in of CVE-2024-6387

We visit "log.h" just before the fateful check-in to see if anything has
changed.

```c
void     fatal(const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     error(const char *, ...) __attribute__((format(printf, 1, 2)));
void     sigdie(const char *, ...)  __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     logdie(const char *, ...) __attribute__((noreturn))
    __attribute__((format(printf, 1, 2)));
void     logit(const char *, ...) __attribute__((format(printf, 1, 2)));
void     verbose(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug2(const char *, ...) __attribute__((format(printf, 1, 2)));
void     debug3(const char *, ...) __attribute__((format(printf, 1, 2)));
```

We see that things are mostly the same. We have a few functions for general
logging depending on log-level, and then we have a few special functions,
namely "logdie", "sigdie" and "fatal". There is a new function logdie, defined
in "log.c" but this is only a variant of "fatal", it will play a minor role in
the future.

```c
void
logdie(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_INFO, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```

The usage of "sigdie" has gone up from one to three places in the code. In
sshd.c line 378, and auth-pam.c line 178, 180.

```c
  /* XXX pre-format ipaddr/port so we don't need to access active_state */
  /* Log error and exit. */
  sigdie("Timeout before authentication for %s port %d",
      ssh_remote_ipaddr(the_active_state),
      ssh_remote_port(the_active_state));
}
```

```c
  if (!WIFEXITED(sshpam_thread_status))
    sigdie("PAM: authentication thread exited unexpectedly");
  if (WEXITSTATUS(sshpam_thread_status) != 0)
    sigdie("PAM: authentication thread exited uncleanly");
```

This is the outer logging framework, and we also know that it **will not
change** with the check-in in question, **remember this, it will be important
later.**

Now let's do an analysis of the
[check-in](https://github.com/openssh/openssh-portable/commit/752250caabda3dd24635503c4cd689b32a650794)
that introduces the current vulnerability,
[CVE-2024-6387](https://ubuntu.com/security/CVE-2024-6387). If we start by
comparing log.h to see the changes:

```c
#define ssh_nlog(level, ...)  sshlog(__FILE__, __func__, __LINE__, 0, level, __VA_ARGS__)
#define ssh_debug3(...)   sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)
#define ssh_debug2(...)   sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
#define ssh_debug(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
#define ssh_verbose(...)  sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
#define ssh_log(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_INFO, __VA_ARGS__)
#define ssh_error(...)    sshlog(__FILE__, __func__, __LINE__, 0, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
#define ssh_fatal(...)    sshfatal(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define ssh_logdie(...)   sshlogdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define ssh_sigdie(...)   sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)

#define debug ssh_debug
#define debug1  ssh_debug1
#define debug2  ssh_debug2
#define debug3  ssh_debug3
#define error ssh_error
#define logit ssh_log
#define verbose ssh_verbose
#define fatal ssh_fatal
#define logdie  ssh_logdie
#define sigdie  ssh_sigdie
#define do_log2 ssh_nlog
```

As we can see this check-in used "#define" to redefine the old functions into
a new set of functions, that first get a ssh_ and then are mapped in a way so
that the normal log functions are all mapped to the new function sshlog and
the special functions are all mapped as follows.

| Old function | Mapped to new function |
| ------------ | ---------------------- |
| fatal        | sshfatal               |
| logdie       | sshlogdie              |
| sigdie       | sshsigdie              |

As we saw earlier fatal has its own file, and this is modified correctly. But
for "logdie", and "sigdie" things are different. Instead of just modifying
them in place, the functions are deleted, and new functions are instead
implemented at the bottom of the file (log.c). In this process the "#ifdef" is
deleted in sshsigdie.

#### Change in "logdie"

```c
void
logdie(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_INFO, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```

```c
void
sshlogdie(const char *file, const char *func, int line, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  sshlogv(file, func, line, 0, SYSLOG_LEVEL_INFO, fmt, args);
  va_end(args);
  cleanup_exit(255);
}
```

As we can see the only change made in logdie is that the function name
changes, the parameters change, and the log-command is updated.

#### Change in "sigdie"

The same is true for "sigdie", the function is the same, it just has a
different name, and updated parameters and the log-command is updated, and
yes, the "#ifdef", the **very reason for this function's existence** has been
removed.

```c
void
sigdie(const char *fmt,...)
{
#ifdef DO_LOG_SAFE_IN_SIGHAND
  va_list args;

  va_start(args, fmt);
  do_log(SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
#endif
  _exit(1);
}
```

```c
void
sshsigdie(const char *file, const char *func, int line, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  sshlogv(file, func, line, 0, SYSLOG_LEVEL_FATAL, fmt, args);
  va_end(args);
  _exit(1);
}
```

Note that spaces, commas and every other indentation are the same in both the
old and new methods, it's therefore deemed probable that the new methods
started as a copy of the old methods, and further it is impossible that this
copy happened without the "#ifdef" in place. Hence the "#ifdef" must have been
**deliberately removed** after the method was copied to its new place, by an
author that we have established had, or should have had, full knowledge of why
it was there.

### Conclusions

It's very difficult at this stage, to draw any other conclusion other than
that the function has simply been copied from its original place in the file
to a place further down, that the header has been updated, along with the
log-command to match the feature, and then the "#ifdef" has been
**purposefully deleted.** Further, we have found no reason for moving the
method other than to **obfuscate** what is actually happening by making diffs
harder to read. Further, since the outer logging framework never changes, it's
difficult to find any other reason for the change in the function name other
than to deliberately **further obfuscate** the true intention of this feature.
It's very difficult to draw any other conclusion than, that this entire
rewrite of the log functions was **purposefully designed** to mask the
(re)introduction of the CVE-2006-5051.

As to why the author did this is difficult to know, one option is that he did
so for personal financial gain, most probably by selling the information to
some national state actor, like the NSA, CIA, SVR and GRU or similar. While
the market value of such a vulnerability is always difficult to estimate, a
rough estimation is somewhere between 2-20M USD.

### Recommendations

Since it cannot be ruled out that this regression was not done on purpose by a
person with considerable influence on the project, and since this is a
component that is usually used as a secure barrier between security zones, and
hence critical to the organization's security it's impossible at this stage to
recommend anything else than **decommission and replace.** One possible
alternative to OpenSSH is Dropbear SSH link
[here](https://matt.ucc.asn.au/dropbear/dropbear.html).

# Appendix B: Notes taken during article review

rough notes, not for final version:

* Damien Miller was one of the primary individuals responsible for porting
  OpenSSH to Linux
* Why does the author of the analysis show the "default implementation" of
  `cleanup_exit()`, rather than the sshd implementation? The cleanup does a
  lot more in some situations.
* No, the author is not Damien Miller for both the "fix" commits, this was
  originally a CVS repository and the first of the two commits was authored by
  Theo de Raadt, the lead OpenBSD developer.
* OpenSSH and OpenBSD don't have a warrant canary. This would have been useful
  for potentially judging whether malicious activity was involved.
* The vulnerable commit is part of a larger refactor of logging functionality.
* The formatting isn't exactly the same as claimed by the report, the function
  header is different.
* Difficulty of exploitation might have been suspected to be a NOBUS vuln due
  to KASLR?
* Upstream's fix was insanely complicated, to the point where no stable distro
  could reasonably backport the fix. The actual needed fix was extremely
  simple.
* `fatal_cleanup` removed in 3e33cecf71860f73656a73b754cc7b7b9ec0b0ce
