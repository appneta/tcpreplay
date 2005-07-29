/* Copyright (c) 1995 DJ Delorie, 334 North Road, Deerfield NH USA
   Distributed under the terms of the GNU GPL, version 2 or later.
   Note: The HTML output of this program is NOT considered a derived
   work of this program.  */

/*
   Original work by dj@delorie.com

   Usage: man2html < program.man > program.html
*/


#include <stdio.h>
#include <ctype.h>
#include <string.h>

int in_tt = 0;
int next_line_dd = 0;
int need_undl = 0;
int got_regular_line = 0;
int need_re = 0;
int fill_mode = 1;
int current_BI = 0;
int skip_nl = 0;

int process_line(void);

char *
get_token(char *inp, char *buf)
{
  int quoted = 0;
  /* skip whitespace */
  while (*inp && isspace(*inp))
    inp++;
  if (*inp == 0)
    return 0;

  while (*inp)
  {
    switch (*inp)
    {
    case '"':
      quoted = 1-quoted;
      break;
    case '\\':
      *buf++ = *inp;
      *buf++ = *++inp;
      break;
    default:
      if (isspace(*inp) && !quoted)
      {
	*buf = 0;
	return inp;
      }
      *buf++ = *inp;
      break;
    }
    inp++;
  }
  *buf = 0;
  return inp;
}

void
clean(char *cp)
{
  char foo[1000];
  char *rp = foo;
  char *ocp = cp;
  if (strncmp(cp, ".if t ", 6) == 0)
    cp += 6;
  while (*cp)
  {
    switch (*cp)
    {
    case '\\':
      cp++;
      switch (*cp)
      {
      case 'E':
      case 'F':
      case 'g':
      case 'b':
      case 'r':
      case 'B':
	*rp++ = '\\';
	*rp++ = *cp++;
	break;
      case '/':
      case '-':
      case '\\':
      case '+':
      case '.':
      case 10:
      case 0:
      case ' ':
      case '=':
      case '\'':
      case '`':
      case '[':
      case ']':
      case ':':
      case '}':
      case '{':
	*rp++ = *cp++;
	break;
      case '|':
      case '^':
      case '"':
      case 'd':
      case 'u':
      case 'n':
      case '&':
      case 'w':
      case '%':
      case 'v':
      case 'k':
	cp++;
	break;
      case 't':
	*rp++ = ' ';
	cp++;
	break;
      case '0':
	*rp++ = ' ';
	cp++;
	break;
      case 'c':
	if (cp[1] == '\n')
	{
	  skip_nl = 1;
	  cp++;
	}
	cp++;
	break;
      case 'e':
	*rp++ = '\\';
	cp++;
	break;
      case 's':
	cp++;
	cp++;
	while (isdigit(*cp))
	  cp++;
	break;
      case 'f':
	if (current_BI)
	{
	  *rp++ = '<';
	  *rp++ = '/';
	  *rp++ = current_BI;
	  *rp++ = '>';
	  current_BI = 0;
	}
	if (in_tt)
	{
	  strcpy(rp, "</tt>");
	  rp += 5;
	  in_tt = 0;
	}
	switch (*++cp)
	{
	case '(':
	  if (cp[1] == 'C' && cp[2] == 'W')
	  {
	    strcpy(rp, "<tt>");
	    rp += 4;
	    in_tt = 1;
	    cp += 2;
	  }
	  else
	    fprintf(stderr, "unknown font %.3s\n", cp);
	  break;
	case 'B':
	  current_BI = 'b';
	  *rp++ = '<';
	  *rp++ = 'b';
	  *rp++ = '>';
	  break;
	case 'R':
	case 'P':
	  break;
	case 'I':
	  current_BI = 'i';
	  *rp++ = '<';
	  *rp++ = 'i';
	  *rp++ = '>';
	  break;
	}
	cp++;
	break;
      case '*':
	cp++;
	if (cp[0] == '(')
	{
	  cp++;
	  if (cp[0] == 'l' && cp[1] == 'q')
	    *rp++ = '`';
	  else if (cp[0] == 'r' && cp[1] == 'q')
	    *rp++ = '\'';
	  else
	  {
	    sprintf(rp, "[%.2s]", cp);
	    rp += 4;
	  }
	  cp += 2;
	}
	else if (cp[0] == 'r')
	{
	  cp++;
	  strcpy(rp, "RCS");
	  rp += 3;
	}
	else
	{
	  sprintf(rp, "[%c]", *cp);
	  rp += 3;
	}
	break;
      case '(':
	if (cp[1] == 'c' && cp[2] == 'o')
	  *rp++ = 0xa9;
	else if (cp[1] == 'b' && cp[2] == 'v')
	  *rp++ = '|';
	else if (cp[1] == 'e' && cp[2] == 'm')
	  *rp++ = ' ';
	else if (cp[1] == '+' && cp[2] == '-')
	  *rp++ = 0xb1;
	else if (cp[1] == 't' && cp[2] == 'i')
	  *rp++ = '~';
	else if (cp[1] == 't' && cp[2] == 's')
	  *rp++ = '"';
	else if (cp[1] == 'p' && cp[2] == 'l')
	  *rp++ = '+';
	else if (cp[1] == 'm' && cp[2] == 'i')
	  *rp++ = '-';
	else if (cp[1] == 'f' && cp[2] == 'm')
	  *rp++ = '\'';
	else if (cp[1] == 'm' && cp[2] == 'u')
	  *rp++ = 'x';
	else if (cp[1] == 'b' && cp[2] == 'u')
	{
	  strcpy(rp, "<li>");
	  rp += 4;
	}
	else if (cp[1] == '>' && cp[2] == '=')
	{
	  *rp++ = '>';
	  *rp++ = '=';
	}
	else if (cp[1] == '*' && cp[2] == '*')
	{
	  *rp++ = '*';
	  *rp++ = '*';
	}
	else
	  fprintf(stderr, "unknown meta-character (%c%c\n", cp[1], cp[2]);
	cp += 3;
	break;
      default:
	fprintf(stderr, "unknown escape \\%c (%d)\n", *cp, *cp);
	break;
      }
      break;
    case '&':
      *rp++ = '&';
      *rp++ = 'a';
      *rp++ = 'm';
      *rp++ = 'p';
      *rp++ = ';';
      cp++;
      break;
    case '<':
      *rp++ = '&';
      *rp++ = 'l';
      *rp++ = 't';
      *rp++ = ';';
      cp++;
      break;
    case '>':
      *rp++ = '&';
      *rp++ = 'g';
      *rp++ = 't';
      *rp++ = ';';
      cp++;
      break;
    default:
      *rp++ = *cp++;
      break;
    }
  }
  *rp = 0;
  strcpy(ocp, foo);
}

void
un_bi(void)
{
  if (current_BI)
  {
    printf("</%c>", current_BI);
    current_BI = 0;
  }
}

void
process_line_til_regular(void)
{
  got_regular_line = 0;
  while (!got_regular_line)
    process_line();
}

void
bol(void)
{
  got_regular_line = 1;
  if (next_line_dd)
    printf("<dd>");
  next_line_dd = 0;
}

void
eol(void)
{
  if (!fill_mode)
    printf("<br>");
}

void
twoggle(char *a, char *b, char *l)
{
  int first = 1;
  char *c;
  char buf[1000];
  bol();
  while ((l = get_token(l, buf)))
  {
    clean(buf);
    c = first ? a : b;
    if (c)
      printf("<%s>%s</%s>", c, buf, c);
    else
      printf("%s", buf);
    if (a && b && strcmp(a, b) == 0)
      putchar(' ');
    first = 1-first;
  }
  un_bi();
  if (!skip_nl)
    printf("\n");
  eol();
  got_regular_line = 1;
}

int
process_line(void)
{
  char buf[1000], cmd[10];
  char token[1000];
  if (fgets(buf, 1000, stdin) == 0)
    return 0;

  skip_nl = 0;
  if (buf[0] != '.')
  {
    if (strncmp(buf, "'\\\"", 3) == 0)
      return 1;
    clean(buf);
    bol();
    fputs(buf, stdout);
    if (buf[0] == 0 || buf[0] == '\n')
      printf("<p>");
    eol();
    return 1;
  }

  if (sscanf(buf, "%s %[^\n]", cmd, buf) == 1)
    buf[0] = 0;
  if (strcmp(cmd, "..") == 0)
  {
  }
  else if (strcmp(cmd, ".B") == 0)
  {
    if (buf[0])
    {
      twoggle("b", "b", buf);
    }
    else
    {
      printf("<b>");
      process_line_til_regular();
      printf("</b>");
    }
  }
  else if (strcmp(cmd, ".I") == 0)
  {
    if (buf[0])
    {
      twoggle("i", "i", buf);
    }
    else
    {
      printf("<i>");
      process_line_til_regular();
      printf("</i>");
    }
  }
  else if (strcmp(cmd, ".BI") == 0)
  {
    twoggle("b", "i", buf);
  }
  else if (strcmp(cmd, ".IB") == 0)
  {
    twoggle("i", "b", buf);
  }
  else if (strcmp(cmd, ".BR") == 0)
  {
    twoggle("b", 0, buf);
  }
  else if (strcmp(cmd, ".RB") == 0)
  {
    twoggle(0, "b", buf);
  }
  else if (strcmp(cmd, ".IR") == 0)
  {
    twoggle("i", 0, buf);
  }
  else if (strcmp(cmd, ".RI") == 0)
  {
    twoggle(0, "i", buf);
  }
  else if (strcmp(cmd, ".nf") == 0)
  {
    if (fill_mode)
      printf("<pre>\n");
    fill_mode = 0;
  }
  else if (strcmp(cmd, ".fi") == 0)
  {
    if (!fill_mode)
      printf("</pre>\n");
    fill_mode = 1;
  }
  else if (strcmp(cmd, ".br") == 0
	   || strcmp(cmd, ".Sp") == 0
	   || strcmp(cmd, ".ti") == 0)
  {
    if (need_undl)
    {
      need_undl = 0;
      printf("</dl>");
    }
    printf("<br>\n");
  }
  else if (strcmp(cmd, ".LP") == 0
	   || strcmp(cmd, ".PP") == 0
	   || strcmp(cmd, ".sp") == 0
	   || strcmp(cmd, ".P") == 0)
  {
    if (need_undl)
    {
      need_undl = 0;
      printf("</dl>");
    }
    printf("\n<p>\n");
  }
  else if (strcmp(cmd, ".RS") == 0)
  {
    printf("<ul>");
    need_re ++;
  }
  else if (strcmp(cmd, ".RE") == 0)
  {
    if (need_re)
    {
      printf("</ul>");
      need_re --;
    }
  }
  else if (strcmp(cmd, ".SH") == 0
	   || strcmp(cmd, ".SS") == 0)
  {
    char *cp = buf;
    int got_token = 0;
    while (need_re)
    {
      printf("</ul>");
      need_re--;
    }
    if (need_undl)
    {
      printf("</dl>");
      need_undl = 0;
    }
    printf("\n</ul><H2>");
    while ((cp = get_token(cp, token)))
    {
      got_token = 1;
      clean(token);
      printf("%s ", token);
    }
    if (!got_token)
    {
      if (fgets(buf, 1000, stdin) == 0)
	return 0;
      printf("%s", buf);
    }
    printf("</H2><ul>\n\n");
    un_bi();
    got_regular_line = 1;
    if (!fill_mode)
      printf("</pre>");
    fill_mode = 1;
  }
  else if (strcmp(cmd, ".SM") == 0)
  {
    if (buf[0])
    {
      bol();
      clean(buf);
      printf("<code>%s</code>\n", buf);
      eol();
    }
    else
    {
      printf("<code>");
      process_line_til_regular();
      printf("</code>");
    }
  }
  else if (strcmp(cmd, ".TH") == 0)
  {
    int all_upper = 1, i;
    get_token(buf, buf);
    for (i=0; buf[i]; i++)
      if (islower(buf[i]))
	all_upper = 0;
    if (all_upper)
      for (i=0; buf[i]; i++)
	if (isupper(buf[i]))
	  buf[i] = tolower(buf[i]);
    printf("<!--#exec cmd=\"header %s\" -->\n", buf);
    printf("<ul>");
  }
  else if (strcmp(cmd, ".TP") == 0
	   || strcmp(cmd, ".Tp") == 0)
  {
    if (!need_undl)
    {
      printf("<p><dl compact>");
      need_undl = 1;
    }
    printf("<dt>");
    next_line_dd = 0;
    process_line_til_regular();
    next_line_dd = 1;
  }
  else if (strcmp(cmd, ".IP") == 0)
  {
    if (!need_undl)
    {
      printf("<p><dl compact>");
      need_undl = 1;
    }
    get_token(buf, buf);
    clean(buf);
    printf("<dt>%s", buf);
    next_line_dd = 1;
  }
  else if (strcmp(cmd, ".TQ") == 0)
  {
    printf("<dt>");
    next_line_dd = 0;
    process_line_til_regular();
    next_line_dd = 1;
  }
  else if (strcmp(cmd, ".FN") == 0)
  {
    bol();
    get_token(buf, buf);
    printf("<code>%s</code>\n", buf);
    got_regular_line = 1;
    eol();
  }
  /* Tcl macros */
  else if (strcmp(cmd, ".AP") == 0)
  {
    char *cp = buf;
    cp = get_token(cp, token);
    printf("<p>%s", token);
    cp = get_token(cp, token);
    printf(" <b>%s</b>", token);
    cp = get_token(cp, token);
    printf(" (<i>%s</i>) -\n", token);
  }
  else if (strcmp(cmd, ".DS") == 0)
  {
    printf("<pre>\n");
  }
  else if (strcmp(cmd, ".DE") == 0)
  {
    printf("</pre>\n");
  }
  /* end of Tcl macros */
  else if (strcmp(cmd, ".\"") == 0)
  {
  }
  else if (strcmp(cmd, ".de") == 0)
  {
    do {
      if (fgets(buf, 1000, stdin) == 0)
	return 0;
    } while (buf[0] != '.' || buf[1] != '.');
  }

  return 1;
}


int
main()
{

  while (process_line());
  printf("</ul>\n<!--#exec cmd=\"trailer\" -->\n");
  return 0;
}
