/* tclgpgme.c --
 *      Tcl interface to GNU Privacy Guard -- wrapper around gpg call.
 *
 * Copyright (c) 2008 Sergei Golovan <sgolovan@nes.ru>,
 *                    Antoni Grzymala <antoni@chopin.edu.pl>
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAMER OF ALL WARRANTIES.
 *
 * $Id$
 */

#include <tcl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAXCNAME 32

/* CloseDup --
 *
 *      Close one file handler and duplicate the other one.
 *
 * Arguments:
 *      cpipe       file descriptor to close;
 *      dpipe       file descriptor to duplicate;
 *      fd          if -1 then don't duplicate the second descriptor,
 *                  otherwise duplicate it to fd number.
 *
 * Result:
 *      None.
 *
 * Side effects:
 *      In case of error the process is terminated.
 */

void CloseDup(int cpipe,
              int dpipe,
              int fd) {
    close(cpipe);
    if (fd >= 0) {
        close(fd);
        if (dup2(dpipe, fd) < 0) _exit(1);
    }
}

/* CloseAndCreateChan --
 *
 *      Close one file handler and create a Tcl channel for the other one.
 *
 * Arguments:
 *      interp      a pointer to Tcl interpreter;
 *      cpipe       file descriptor to close;
 *      dpipe       file descriptor to wrap a Tcl channel around it;
 *      readOrWrite either TCL_READABLE or TCL_WRITABLE.
 *
 * Result:
 *      A pointer to a string object with new created Tcl channel name.
 *
 * Side effects:
 *      A new Tcl channel is created.
 */

Tcl_Obj *CloseAndCreateChan(Tcl_Interp *interp,
                            int         cpipe,
                            int         dpipe,
                            int         readOrWrite) {
    Tcl_Channel chan;

    close(cpipe);
    chan = Tcl_MakeFileChannel((ClientData) dpipe, readOrWrite);
    Tcl_RegisterChannel(interp, chan);
    return Tcl_NewStringObj(Tcl_GetChannelName(chan),-1);
}

/* Gpg_Exec --
 *
 *        Spawn GPG process and prepare several Tcl channels for communication.
 *
 * Arguments:
 *      unused      unused client data;
 *      interp      a pointer to Tcl interpreter;
 *      objc        a number of arguments;
 *      objv        a pointer to a table of arguments.
 *
 * Result:
 *      Either TCL_OK or TCL_ERROR. Tcl result is set to a list of opened
 *      channels in case of success.
 *
 * Side effects:
 *      A GPG process is spawned and 4 or 5 pipes are opened to it.
 */

static int Gpg_Exec(ClientData  unused,
                    Tcl_Interp *interp,
                    int         objc,
                    Tcl_Obj    *CONST objv[]) {
    char    *executable, *tmp;
    int      status;
    pid_t    pid;
    int      inpipe[2], outpipe[2], errpipe[2], stspipe[2], cmdpipe[2],
             msgpipe[2];
    Tcl_Obj *resultPtr;
    int      argc, i, decrypt, verify, batch;
    char   **argv;
    char     stsChannelName[MAXCNAME], cmdChannelName[MAXCNAME],
             msgChannelName[MAXCNAME];

    Tcl_ResetResult(interp);

    if (objc == 1) {
        Tcl_AppendResult(interp, "usage: ", Tcl_GetString(objv[0]),
                                 " executable ?args?", NULL);
        return TCL_ERROR;
    }

    Tcl_AppendResult(interp, Tcl_GetString(objv[0]), ": ", NULL);

    pipe(inpipe);
    pipe(outpipe);
    pipe(errpipe);
    pipe(stspipe);

    decrypt = 0;
    verify = 0;
    batch = 0;

    for (i = 2; i < objc; i++) {
        tmp = Tcl_GetString(objv[i]);

        if (strcmp(tmp, "--decrypt") == 0) {
            decrypt = 1;
        } else if (strcmp(tmp, "--verify") == 0) {
            verify = 1;
        } else if (strcmp(tmp, "--batch") == 0) {
            batch = 1;
        }
    }

    if (!batch) {
        pipe(cmdpipe);
    }

    if (decrypt || verify) {
        pipe(msgpipe);
    }

    if ((pid = fork()) < 0) {
        Tcl_AppendResult(interp, "can't fork", NULL);
        return TCL_ERROR;
    }
    
    if (pid == 0) {
        /* child: another fork and exit */

        if ((pid = fork()) < 0)
            _exit(1);
        else if (pid > 0)
            _exit(0);

        /* grandchild */

        CloseDup(inpipe[1], inpipe[0], 0);
        CloseDup(outpipe[0], outpipe[1], 1);
        CloseDup(errpipe[0], errpipe[1], 2);

        close(stspipe[0]);

        executable = Tcl_GetString(objv[1]);

        argv = (char **) attemptckalloc((objc + 16) * sizeof(char *));

        if (argv == NULL) _exit(1);

        argc = 0;

        argv[argc++] = executable;
        argv[argc++] = "--status-fd";
        sprintf(stsChannelName, "%d", stspipe[1]);
        argv[argc++] = stsChannelName;

        if (!batch) {
            close(cmdpipe[1]);
            argv[argc++] = "--command-fd";
            sprintf(cmdChannelName, "%d", cmdpipe[0]);
            argv[argc++] = cmdChannelName;
        }

        if (decrypt || verify) {
            argv[argc++] = "--enable-special-filenames";
        }

        for (i = 2; i < objc; i++) {
            argv[argc++] = Tcl_GetString(objv[i]);
        }

        if (decrypt || verify) {
            close(msgpipe[1]);
            sprintf(msgChannelName, "-&%d", msgpipe[0]);
            argv[argc++] = msgChannelName;
        }

        if (verify) {
            argv[argc++] = "-";
        }

        argv[argc++] = NULL;

        execv(executable, argv);

        _exit(1);
    }

    /* pid > 0 */

    if (waitpid(pid, &status, 0) < 0) {
        Tcl_AppendResult(interp, "can't waitpid", NULL);
        return TCL_ERROR;
    }

    if (WIFSIGNALED(status)) {
        Tcl_AppendResult(interp, "child is terminated by a signal", NULL);
        return TCL_ERROR;
    } else if (WIFEXITED(status)) {
        if (WEXITSTATUS(status)) {
            Tcl_AppendResult(interp, "child is exited with nonzero code", NULL);
            return TCL_ERROR;
        }
    } else {
        Tcl_AppendResult(interp, "child is exited abnormally", NULL);
        return TCL_ERROR;
    }

    resultPtr = Tcl_NewObj();

    Tcl_ListObjAppendElement(NULL, resultPtr,
                             CloseAndCreateChan(interp, inpipe[0],
                                                inpipe[1], TCL_WRITABLE));
    Tcl_ListObjAppendElement(NULL, resultPtr,
                             CloseAndCreateChan(interp, outpipe[1],
                                                outpipe[0], TCL_READABLE));
    Tcl_ListObjAppendElement(NULL, resultPtr,
                             CloseAndCreateChan(interp, errpipe[1],
                                                errpipe[0], TCL_READABLE));
    Tcl_ListObjAppendElement(NULL, resultPtr,
                             CloseAndCreateChan(interp, stspipe[1],
                                                stspipe[0], TCL_READABLE));
    if (!batch) {
        Tcl_ListObjAppendElement(NULL, resultPtr,
                                 CloseAndCreateChan(interp, cmdpipe[0],
                                                    cmdpipe[1], TCL_WRITABLE));
    }
    if (decrypt || verify) {
        Tcl_ListObjAppendElement(NULL, resultPtr,
                                 CloseAndCreateChan(interp, msgpipe[0],
                                                    msgpipe[1], TCL_WRITABLE));
    }
    Tcl_SetObjResult(interp, resultPtr);
    return TCL_OK;
}

/* Tclgpg_Init --
 *
 *      Initialize the library and register ::gpg::CExecGPG command.
 *
 * Arguments:
 *      interp      a pointer to Tcl interpreter.
 *
 * Result:
 *      TCL_OK in case of success or TCL_ERROR in case of failure.
 *
 * Side effects:
 *      A new Tcl command is created.
 */

int Tclgpg_Init (Tcl_Interp *interp) {
    if (Tcl_InitStubs (interp, "8.0", 0) == NULL)
        return TCL_ERROR;

    Tcl_CreateObjCommand (interp, "::gpg::CExecGPG", &Gpg_Exec,
                          (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);

    return TCL_OK;
}

/*
 * vim:ts=8:sw=4:sts=4:et
 */
