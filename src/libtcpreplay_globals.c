/*
 *   Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it
 *   and/or modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Globals normally defined by each tool's main() translation unit
 * (tcpreplay.c), provided here so applications linking libtcpreplay don't
 * have to define them themselves (#133):
 * - debug: level used by the dbg()/dbgx() macros in --enable-debug builds
 * - ctx: context the SIGUSR1/SIGCONT suspend/resume signal handlers act on;
 *   it stays NULL unless the application installs those handlers itself
 */

#include "defines.h"
#include "config.h"
#include "tcpreplay_api.h"

#ifdef DEBUG
int debug = 0;
#endif

tcpreplay_t *ctx;
