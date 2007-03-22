


#ifndef _INTERFACE_H_
#define _INTERFACE_H_

struct interface_list_s {
    char name[255];
    char alias[255];
    char description[255];
    u_int32_t flags;
    struct interface_list_s *next;
};

typedef struct interface_list_s interface_list_t;

#define INTERFACE_LIST_SIZE (80 * 80) /* 80 cols * 80 rows */

char *get_interface(interface_list_t *, const char *);
interface_list_t *get_interface_list(void);
void list_interfaces(interface_list_t *);

#endif
