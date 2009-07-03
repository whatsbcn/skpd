#ifndef _SYS_MSG_H
#define _SYS_MSG_H

#include <sys/ipc.h>

__BEGIN_DECLS

/* ipcs ctl commands */
#define MSG_STAT 11
#define MSG_INFO 12

/* msgrcv options */
#define MSG_NOERROR     010000  /* no error if message is too big */
#define MSG_EXCEPT      020000  /* recv any msg except of specified type.*/

struct msqid_ds {
  struct ipc_perm msg_perm;
  struct msg *msg_first;	/* first message on queue,unused  */
  struct msg *msg_last;		/* last message in queue,unused */
  time_t msg_stime;		/* last msgsnd time */
  time_t msg_rtime;		/* last msgrcv time */
  time_t msg_ctime;		/* last change time */
  unsigned long  msg_lcbytes;	/* Reuse junk fields for 32 bit */
  unsigned long  msg_lqbytes;	/* ditto */
  unsigned short msg_cbytes;	/* current number of bytes on queue */
  unsigned short msg_qnum;	/* number of messages in queue */
  unsigned short msg_qbytes;	/* max number of bytes on queue */
  pid_t msg_lspid;		/* pid of last msgsnd */
  pid_t msg_lrpid;		/* last receive pid */
};

/* message buffer for msgsnd and msgrcv calls */
struct msgbuf {
	long mtype;         /* type of message */
	char mtext[1];      /* message text */
};

/* buffer for msgctl calls IPC_INFO, MSG_INFO */
struct msginfo {
	int msgpool;
	int msgmap;
	int msgmax;
	int msgmnb;
	int msgmni;
	int msgssz;
	int msgtql;
	unsigned short msgseg;
};

#define MSGMNI    16   /* <= IPCMNI */     /* max # of msg queue identifiers */
#define MSGMAX  8192   /* <= INT_MAX */   /* max size of message (bytes) */
#define MSGMNB 16384   /* <= INT_MAX */   /* default max size of a message queue */

extern int msgctl (int msqid, int cmd, struct msqid_ds *buf) __THROW;
extern int msgget (key_t key, int msgflg) __THROW;
extern int msgrcv (int msqid, void *msgp, size_t msgsz, long int msgtyp, int msgflg) __THROW;
extern int msgsnd (int msqid, const void *msgp, size_t msgsz, int msgflg) __THROW;

__END_DECLS

#endif
