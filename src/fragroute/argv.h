/*
 * argv.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: argv.h,v 1.1 2002/01/18 18:11:18 dugsong Exp $
 */

#ifndef ARGV_H
#define ARGV_H

int	 argv_create(char *p, int argc, char *argv[]);
char	*argv_copy(char *argv[]);

#endif /* ARGV_H */
