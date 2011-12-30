/*
 * Metin KAYA <metin@EnderUNIX.org>
 *
 * April 2008, Istanbul/TURKIYE
 * http://www.enderunix.org/metfs/
 *
 * $Id: mstring.c,v 1.4 2008/04/13 05:10:16 mk Exp $
 */

/*-
 * These string functions are ported from OpenBSD source code and copyrights
 * are stated below:
 *
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

/* str_len() function of D.J.B. */
size_t
mstrlen(const char *s)
{
	register char *t;

	t = (char *) s;
	for (;;) {
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
	}
}

char *
mstrdup(const char *str)
{
	size_t siz;
	char   *copy;

	siz = mstrlen(str) + 1;
	if ((copy = malloc(siz)) == NULL)
		return (NULL);
	(void) memcpy(copy, str, siz);

	return (copy);
}

size_t
mstrcat(char *dst, const char *src, size_t size)
{
	register char       *d = dst;
	register const char *s = src;
	register size_t      n = size;
	size_t               dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n    = size - dlen;

	if (n == 0)
		return(dlen + mstrlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return (dlen + (s - src));	/* count does not include NUL */
}

size_t
mstrcpy(char *dst, const char *src, size_t size)
{
	register char       *d = dst;
	register const char *s = src;
	register size_t      n = size;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (size != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1);	/* count does not include NUL */
}

char *
mstrstr(char *string, char *find)
{
	size_t stringlen, findlen;
	char *cp;

	findlen   = mstrlen(find);
	stringlen = mstrlen(string);
	if (findlen > stringlen)
		return (NULL);

	for (cp = string + stringlen - findlen; cp >= string; cp--)
		if (strncmp(cp, find, findlen) == 0)
			return (cp);

	return (NULL);
}
