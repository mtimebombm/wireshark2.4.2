/* epan.h
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#ifndef __EPAN_H__
#define __EPAN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>
#include "register.h"
#include "ws_symbol_export.h"

typedef struct epan_dissect epan_dissect_t;

struct epan_dfilter;
struct epan_column_info;

/**
	@mainpage Wireshark EPAN the packet analyzing engine. Source code can be found in the epan directory

	@section Introduction

	XXX

	@b Sections:
*/
/*
Ref 1
Epan
Ethereal Packet ANalyzer (XXX - is this correct?) the packet analyzing engine. Source code can be found in the epan directory.

Protocol-Tree - Keep data of the capture file protocol information.

Dissectors - The various protocol dissectors in epan/dissectors.

Plugins - Some of the protocol dissectors are implemented as plugins. Source code can be found at plugins.

Display-Filters - the display filter engine at epan/dfilter



Ref2 for further edits - delete when done
	\section Introduction

	This document describes the data structures and the functions exported by the CACE Technologies AirPcap library.
	The AirPcap library provides low-level access to the AirPcap driver including advanced capabilities such as channel setting,
	link type control and WEP configuration.<br>
	This manual includes the following sections:

	\note throughout this documentation, \e device refers to a physical USB AirPcap device, while \e adapter is an open API
	instance. Most of the AirPcap API operations are adapter-specific but some of them, like setting the channel, are
	per-device and will be reflected on all the open adapters. These functions will have "Device" in their name, e.g.
	AirpcapSetDeviceChannel().

	\b Sections:

	- \ref airpcapfuncs
	- \ref airpcapdefs
	- \ref radiotap
*/
/*
 * Register all the plugin types that are part of libwireshark.
 *
 * Must be called before init_plugins(), which must be called before
 * any registration routines are called, i.e. before epan_init().
 *
 * Must be called only once in a program.
 */
WS_DLL_PUBLIC void epan_register_plugin_types(void);

/**
 * Init the whole epan module.
 *
 * Must be called only once in a program.
 *
 * Returns TRUE on success, FALSE on failure.
 */
WS_DLL_PUBLIC
gboolean epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	           void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	           register_cb cb, void *client_data);

/**
 * Load all settings, from the current profile, that affect epan.
 */
WS_DLL_PUBLIC
e_prefs *epan_load_settings(void);

/** cleanup the whole epan module, this is used to be called only once in a program */
WS_DLL_PUBLIC
void epan_cleanup(void);

/**
 * 初始化流管理模块，
 * Initialize the table of conversations.  Conversations are identified by
 * their endpoints; they are used for protocols such as IP, TCP, and UDP,
 * where packets contain endpoint information but don't contain a single
 * value indicating to which flow the packet belongs.
 * 单个包虽然包含了endpoint，但是没有信息标识出属于那条流，所以用conversation模块记录
 */
void epan_conversation_init(void);

/**
 * Initialize the table of circuits.  Circuits are identified by a
 * circuit ID; they are used for protocols where packets *do* contain
 * a circuit ID value indicating to which flow the packet belongs.
 *
 * We might want to make a superclass for both endpoint-specified
 * conversations and circuit ID-specified circuits, so we can attach
 * information either to a circuit or a conversation with common
 * code.
 * Circuit ID，一般是指代在协议中添加固定数据来标识这个包的所属信息，
 * 一般在电话交换机等中有使用，具体可以参考https://en.wikipedia.org/wiki/Circuit_ID
 */
void epan_circuit_init(void);
void epan_circuit_cleanup(void);

/** A client will create one epan_t for an entire dissection session.
 * A single epan_t will be used to analyze the entire sequence of packets,
 * sequentially, in a single session. A session corresponds to a single
 * packet trace file（一条会话相当于一个单包跟踪文件？应该是说会话相当于一个有序的包文件）. 
 * The reasons epan_t exists is that some packets in
 * some protocols cannot be decoded without knowledge of previous packets.
 * This inter-packet "state" is stored in the epan_t.
 * 为单独的会话创建epan_t，用来解析内部数据，因为有些协议必须关联前期数据，
 * 才能解析出后续的数据内容。
 * 具体哪些协议后续补充
 */
typedef struct epan_session epan_t;

WS_DLL_PUBLIC epan_t *epan_new(void);

WS_DLL_PUBLIC const char *epan_get_user_comment(const epan_t *session, const frame_data *fd);

WS_DLL_PUBLIC const char *epan_get_interface_name(const epan_t *session, guint32 interface_id);

WS_DLL_PUBLIC const char *epan_get_interface_description(const epan_t *session, guint32 interface_id);

const nstime_t *epan_get_frame_ts(const epan_t *session, guint32 frame_num);

WS_DLL_PUBLIC void epan_free(epan_t *session);

WS_DLL_PUBLIC const gchar*
epan_get_version(void);

/**
 * Set/unset the tree to always be visible when epan_dissect_init() is called.
 * This state change sticks until cleared, rather than being done per function call.
 * This is currently used when Lua scripts request all fields be generated.
 * By default it only becomes visible if epan_dissect_init() makes it so, usually
 * only when a packet is selected.
 * Setting this overrides that so it's always visible, although it will still not be
 * created if create_proto_tree is false in the call to epan_dissect_init().
 * Clearing this reverts the decision to epan_dissect_init() and proto_tree_visible.
 */
void epan_set_always_visible(gboolean force);

/** initialize an existing single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

/** get a new single packet dissection 获取一个新的单包解析器
 * should be freed using epan_dissect_free() after packet dissection completed
 */
WS_DLL_PUBLIC
epan_dissect_t*
epan_dissect_new(epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

WS_DLL_PUBLIC
void
epan_dissect_reset(epan_dissect_t *edt);

/** Indicate whether we should fake protocols or not */
WS_DLL_PUBLIC
void
epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols);

/** run a single packet dissection */
/*运行单包解析器，具体with_taps具体原因还需确认补充，tap在wireshark中用来标识协议跟踪的
 * 因为单个包解析以后，有些数据不能保存，该条流的下一个包过来可能需要，就利用tap机制，
 * 将需要的数据enquene到tap中，后续使用*/
WS_DLL_PUBLIC
void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

/** run a single file packet dissection 运行单文件包解析器，应该是会话解析器--需确认*/
WS_DLL_PUBLIC
void
epan_dissect_file_run(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

/*以下是proto_tree的填充方式，用dfilter/hfid/hfid_array等*/
/** Prime an epan_dissect_t's proto_tree using the fields/protocols used in a dfilter. */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/** Prime an epan_dissect_t's proto_tree with a field/protocol specified by its hfid */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid(epan_dissect_t *edt, int hfid);

/** Prime an epan_dissect_t's proto_tree with a set of fields/protocols specified by their hfids in a GArray */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid_array(epan_dissect_t *edt, GArray *hfids);

/** fill the dissect run output into the packet list columns */
WS_DLL_PUBLIC
void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Check whether a dissected packet contains a given named field */
WS_DLL_PUBLIC
gboolean
epan_dissect_packet_contains_field(epan_dissect_t* edt,
                                   const char *field_name);

/** releases resources attached to the packet dissection. DOES NOT free the actual pointer */
WS_DLL_PUBLIC
void
epan_dissect_cleanup(epan_dissect_t* edt);

/** free a single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_free(epan_dissect_t* edt);

/** Sets custom column */
const gchar *
epan_custom_set(epan_dissect_t *edt, GSList *ids, gint occurrence,
				gchar *result, gchar *expr, const int size);

/**
 * Get compile-time information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_get_compiled_version_info(GString *str);

/**
 * Get runtime information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_get_runtime_version_info(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_H__ */
