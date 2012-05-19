/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Giovanni Campagna <scampa.giovanni@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef __GDM_GREETER_UTIL_H
#define __GDM_GREETER_UTIL_H

#include <gio/gio.h>
#include <gdm-greeter-server.h>

G_BEGIN_DECLS

#define GDM_GREETER_ERROR (gdm_greeter_error_quark ())

typedef enum _GdmGreeterError {
        GDM_GREETER_ERROR_GENERIC = 0,
} GdmGreeterError;

GQuark gdm_greeter_error_quark (void);

GdmGreeterServer * gdm_greeter_server_new_for_greeter_sync (GCancellable  *cancellable,
                                                            GError       **error);

GdmGreeterServer * gdm_greeter_server_new_for_display_sync (const char    *display_name,
                                                            GCancellable  *cancellable,
                                                            GError       **error);

void gdm_greeter_server_new_for_display (const char          *display_name,
                                         GCancellable        *cancellable,
                                         GAsyncReadyCallback  callback,
                                         gpointer             user_data);

GdmGreeterServer * gdm_greeter_server_new_for_display_finish (GAsyncResult  *result,
                                                              GError       **error);


G_END_DECLS

#endif
