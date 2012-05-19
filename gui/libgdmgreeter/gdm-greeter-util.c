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

#include "gdm-greeter-util.h"
#include "gdm-display-glue.h"

GQuark
gdm_greeter_error_quark (void)
{
        static GQuark error_quark = 0;

        if (error_quark == 0)
                error_quark = g_quark_from_static_string ("gdm-greeter");

        return error_quark;
}

/**
 * gdm_greeter_server_new_for_greeter_sync:
 *
 * Utility functions that creates a new #GdmGreeterServer to be
 * used inside the greeter session. It uses the environment to find the
 * address to connect to.
 *
 * Returns: (transfer full): a new #GdmGreeterServer, or %NULL if
 *          connecting or creating the proxy failed.
 */
GdmGreeterServer *
gdm_greeter_server_new_for_greeter_sync (GCancellable  *cancellable,
                                         GError       **error)
{
        const char *address;
        GDBusConnection *connection;
        GdmGreeterServer *server;

        address = g_getenv ("GDM_GREETER_DBUS_ADDRESS");

        if (address == NULL) {
                g_set_error (error, GDM_GREETER_ERROR, GDM_GREETER_ERROR_GENERIC,
                             "Missing GreeterServer DBus address. Not a greeter session?");
                return NULL;
        }

        connection = g_dbus_connection_new_for_address_sync (address,
                                                             G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                                             NULL,
                                                             cancellable,
                                                             error);
        if (!connection) {
                return NULL;
        }

        server = gdm_greeter_server_proxy_new_sync (connection,
                                                    G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                                                    NULL,
                                                    "/org/gnome/DisplayManager/GreeterServer",
                                                    cancellable,
                                                    error);

        g_object_unref (connection);

        return server;
}

/**
 * gdm_greeter_server_new_for_display_sync:
 * @display_name: (allow-none): a X11 display name, or %NULL to use default
 *
 * Utility functions that creates a new #GdmGreeterServer to be used
 * inside a logged session, for example to authenticate the user
 * in front of a screen lock.
 *
 * Returns: (transfer full): a new #GdmGreeterServer, or %NULL if
 *          connecting or creating the proxy failed.
 */
GdmGreeterServer *
gdm_greeter_server_new_for_display_sync (const char    *display_name,
                                         GCancellable  *cancellable,
                                         GError       **error)
{
        char *canon_display_name;
        char *display_id;
        char *address;
        GDBusConnection *connection;
        GdmDBusDisplay *display;
        GdmGreeterServer *server;

        if (display_name == NULL)
                display_name = g_getenv ("DISPLAY");

        g_warn_if_fail (display_name != NULL);

        canon_display_name = g_strdelimit (g_strdup (display_name),
                                           ":" G_STR_DELIMITERS, '_');
        display_id = g_strdup_printf ("/org/gnome/DisplayManager/Displays/%s", canon_display_name);

        display = gdm_dbus_display_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                                           G_DBUS_PROXY_FLAGS_NONE,
                                                           "org.gnome.DisplayManager",
                                                           display_id,
                                                           cancellable, error);

        g_free (canon_display_name);
        g_free (display_id); 

        if (!display)
                return NULL;

        address = NULL;
        gdm_dbus_display_call_connect_to_slave_sync (display,
                                                     &address,
                                                     cancellable, error);

        g_object_unref (display);

        if (!address)
                return NULL;

        connection = g_dbus_connection_new_for_address_sync (address,
                                                             G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                                             NULL,
                                                             cancellable,
                                                             error);
        g_free (address);

        if (!connection)
                return NULL;

        server = gdm_greeter_server_proxy_new_sync (connection,
                                                    G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                                                    NULL,
                                                    "/org/gnome/DisplayManager/GreeterServer",
                                                    cancellable,
                                                    error);

        g_object_unref (connection);

        return server;
}

static void
thread_func (GSimpleAsyncResult *res,
             GObject *object,
             GCancellable *cancellable)
{
        GError *error;
        GdmGreeterServer *server;
        const char *display;

        error = NULL;

        display = g_object_get_data (G_OBJECT (res), "x11-display-name");
        server = gdm_greeter_server_new_for_display_sync (display,
                                                          cancellable,
                                                          &error);

        if (server != NULL)
                g_simple_async_result_set_op_res_gpointer (res,
                                                           server,
                                                           NULL);
        else
                g_simple_async_result_take_error (res, error);
}

/**
 * gdm_greeter_server_new_for_display:
 * @display_name: (allow-none): a X11 display name, or %NULL to use default
 *
 * This is just the async version of gdm_greeter_server_new_for_display_sync()
 */
void
gdm_greeter_server_new_for_display (const char          *display_name,
                                    GCancellable        *cancellable,
                                    GAsyncReadyCallback  callback,
                                    gpointer             user_data)
{
        GSimpleAsyncResult *result;

        result = g_simple_async_result_new (NULL, callback, user_data,
                                            gdm_greeter_server_new_for_display);
        g_simple_async_result_set_check_cancellable (result, cancellable);

        g_object_set_data_full (G_OBJECT (result), "x11-display-name",
                                g_strdup (display_name), g_free);

        g_simple_async_result_run_in_thread (result, thread_func, 0, cancellable);
}

/**
 * gdm_greeter_server_new_for_display_finish:
 *
 * Returns: (transfer full): the newly created #GdmGreeterServer
 */
GdmGreeterServer *
gdm_greeter_server_new_for_display_finish (GAsyncResult  *result,
                                           GError       **error)
{
        GSimpleAsyncResult *simple;
        GdmGreeterServer *server;

        g_return_val_if_fail (g_simple_async_result_is_valid (result,
                                                              NULL,
                                                              gdm_greeter_server_new_for_display), NULL);

        simple = G_SIMPLE_ASYNC_RESULT (result);

        if (g_simple_async_result_propagate_error (simple, error))
                return NULL;

        server = g_simple_async_result_get_op_res_gpointer (simple);
        return server;
}
