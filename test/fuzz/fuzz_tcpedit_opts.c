/*
 *   Copyright (c) 2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
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
 * libtcpedit's DLT plugins reference tcpedit_tcpedit_optDesc_p, which is
 * generated into tcprewrite_opts.c. Compile that file into fuzz_tcpedit rather
 * than linking tcprewrite's object, whose name is an automake implementation
 * detail.
 */
#include "tcprewrite_opts.c" /* NOLINT(bugprone-suspicious-include) */
