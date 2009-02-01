ADD_LIBRARY(fragroute STATIC argv.c bget.c fragroute.c mod.c mod_delay.c mod_drop.c
	mod_dup.c mod_echo.c mod_ip_chaff.c mod_ip_frag.c mod_ip_opt.c
	mod_ip_tos.c mod_ip_ttl.c mod_order.c mod_print.c mod_tcp_chaff.c
	mod_tcp_opt.c mod_tcp_seg.c pkt.c randutil.c)