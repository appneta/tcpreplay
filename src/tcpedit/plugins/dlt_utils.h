#ifndef _DLT_UTILS_H_
#define _DLT_UTILS_H_


u_char *tcpedit_dlt_l3data_copy(tcpeditdlt_t *ctx, u_char *packet, int ptklen, int l2len);
u_char *tcpedit_dlt_l3data_merge(tcpeditdlt_t *ctx, u_char *packet, int pktlen, const u_char *l3data, const int l2len);

int tcpedit_dlt_parse_opts(tcpeditdlt_t *ctx);
int tcpedit_dlt_validate(tcpeditdlt_t *ctx);

tcpeditdlt_plugin_t *tcpedit_dlt_newplugin(void);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin(tcpeditdlt_t *ctx, int dlt);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin_byname(tcpeditdlt_t *ctx, const char *name);

int tcpedit_dlt_addplugin(tcpeditdlt_t *ctx, tcpeditdlt_plugin_t *new);


#endif