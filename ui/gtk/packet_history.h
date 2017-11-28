/* packet_history.h
 * packet history related functions   2004 Ulf Lamping
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_HISTORY_H__
#define __PACKET_HISTORY_H__

extern void packet_history_add(gint row);

extern void packet_history_clear(void);

extern void history_forward_cb(GtkWidget *widget, gpointer data);

extern void history_back_cb(GtkWidget *widget, gpointer data);

#endif /* __PACKET_HISTORY_H__ */
