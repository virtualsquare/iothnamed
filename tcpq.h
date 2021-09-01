#ifndef _TCPQ_H
#define _TCPQ_H
void tcpq_setmaxqlen(int value);
int tcpq_qlen(void);
void tcpq_enqueue(void *buf, int len);
void *tcpq_dequeue(int *len);
#endif
