#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

void init_signal_handlers();
void reset_suspend_time();
void suspend_handler( int signo );
void continue_handler( int signo );

#endif
