/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

#include <glib.h>

#include "gdm-display-glue.h"
#include "gdm-greeter-glue.h"

static GMainLoop *loop;

static void
on_ready (GdmDBusGreeterServer *greeter,
          const char           *service_name)
{
        GError *error;
        gboolean ok;

        error = NULL;
        ok = gdm_dbus_greeter_server_call_begin_verification_for_user_sync (greeter,
                                                                            service_name,
                                                                            g_get_user_name (),
                                                                            NULL, &error);
        if (!ok) {
                g_critical ("Failed to start PAM session: %s", error->message);
                exit (1);
        }
}

static void
on_conversation_stopped (GdmDBusGreeterServer *greeter,
                         const char           *service_name)
{
        g_print ("\n** WARNING: conversation stopped\n");

        g_main_loop_quit (loop);
}

static void
on_reset (GdmDBusGreeterServer *greeter)
{
        g_print ("\n** NOTE: reset\n");

        g_main_loop_quit (loop);
}

static void
on_session_opened (GdmDBusGreeterServer *greeter,
                   const char           *service_name)
{
        g_print ("\n** INFO: session opened (authentication OK)\n");

        g_main_loop_quit (loop);
}

static void
on_info_query (GdmDBusGreeterServer *greeter,
               const char           *service_name,
               const char           *query_text)
{
        char  answer[1024];
        char *res;

        g_print ("%s ", query_text);

        answer[0] = '\0';
        res = fgets (answer, sizeof (answer), stdin);
        if (res == NULL) {
                g_warning ("Couldn't get an answer");
        }

        answer[strlen (answer) - 1] = '\0';

        if (answer[0] == '\0') {
                gdm_dbus_greeter_server_call_cancel_sync (greeter,
                                                   NULL, NULL);
                g_main_loop_quit (loop);
        } else {
                gdm_dbus_greeter_server_call_answer_query_sync (greeter,
                                                                service_name,
                                                                answer,
                                                                NULL, NULL);
        }
}

static void
on_info (GdmDBusGreeterServer *greeter,
         const char           *service_name,
         const char           *info)
{
        g_print ("\n** NOTE: %s\n", info);
}

static void
on_problem (GdmDBusGreeterServer *greeter,
            const char           *service_name,
            const char           *problem)
{
        g_print ("\n** WARNING: %s\n", problem);
}

static void
on_secret_info_query (GdmDBusGreeterServer *greeter,
                      const char           *service_name,
                      const char           *query_text)
{
        char           answer[1024];
        char          *res;
        struct termios ts0;
        struct termios ts1;

        tcgetattr (fileno (stdin), &ts0);
        ts1 = ts0;
        ts1.c_lflag &= ~ECHO;

        g_print ("%s", query_text);

        if (tcsetattr (fileno (stdin), TCSAFLUSH, &ts1) != 0) {
                fprintf (stderr, "Could not set terminal attributes\n");
                exit (1);
        }

        answer[0] = '\0';
        res = fgets (answer, sizeof (answer), stdin);
        answer[strlen (answer) - 1] = '\0';
        if (res == NULL) {
                g_warning ("Couldn't get an answer");
        }

        tcsetattr (fileno (stdin), TCSANOW, &ts0);

        g_print ("\n");

        gdm_dbus_greeter_server_call_answer_query_sync (greeter, service_name, answer,
                                                        NULL, NULL);
}

int
main (int   argc,
      char *argv[])
{
        GError *error;
        GdmDBusDisplay *display;
        GdmDBusGreeterServer *greeter;
        GDBusConnection *system_bus;
        GDBusConnection *connection;
        char *address;
        char *display_name;
        char *display_id;
        gboolean ok;

        g_type_init ();

        g_debug ("creating instance of GdmDBusDisplay object...");

        error = NULL;
        system_bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (!system_bus) {
                g_critical ("Failed connecting to the system bus (this is pretty bad): %s", error->message);
                exit (1);
        }

        display_name = g_strdelimit (g_strdup (g_getenv ("DISPLAY")),
                                     ":" G_STR_DELIMITERS, '_');
        display_id = g_strdup_printf ("/org/gnome/DisplayManager/Displays/%s", display_name);

        display = GDM_DBUS_DISPLAY (gdm_dbus_display_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                                                             G_DBUS_PROXY_FLAGS_NONE,
                                                                             "org.gnome.DisplayManager",
                                                                             display_id,
                                                                             NULL, &error));
        if (!display) {
                g_critical ("Failed creating display proxy: %s", error->message);
                exit (1);
        }

        g_free (display_name);
        g_free (display_id);

        address = NULL;
        gdm_dbus_display_call_connect_to_slave_sync (display,
                                                     &address,
                                                     NULL, &error);
        if (!address) {
                g_critical ("Failed obtaining slave address: %s", error->message);
                exit (1);
        }

        connection = g_dbus_connection_new_for_address_sync (address,
                                                             G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                                             NULL,
                                                             NULL, &error);
        if (!connection) {
                g_critical ("Failed connecting to the slave: %s", error->message);
                exit (1);
        }

        greeter = GDM_DBUS_GREETER_SERVER (gdm_dbus_greeter_server_proxy_new_sync (connection,
                                                                                   G_DBUS_PROXY_FLAGS_NONE,
                                                                                   NULL,
                                                                                   "/org/gnome/DisplayManager/GreeterServer",
                                                                                   NULL, &error));
        if (!greeter) {
                g_critical ("Failed creating greeter proxy: %s", error->message);
                exit (1);
        }

        g_signal_connect (greeter, "ready",
                          G_CALLBACK (on_ready), NULL);
        g_signal_connect (greeter, "info",
                          G_CALLBACK (on_info), NULL);
        g_signal_connect (greeter, "problem",
                          G_CALLBACK (on_problem), NULL);
        g_signal_connect (greeter, "info-query",
                          G_CALLBACK (on_info_query), NULL);
        g_signal_connect (greeter, "secret-info-query",
                          G_CALLBACK (on_secret_info_query), NULL);
        g_signal_connect (greeter, "conversation-stopped",
                          G_CALLBACK (on_conversation_stopped), NULL);
        g_signal_connect (greeter, "session-opened",
                          G_CALLBACK (on_session_opened), NULL);
        g_signal_connect (greeter, "reset",
                          G_CALLBACK (on_reset), NULL);

        ok = gdm_dbus_greeter_server_call_start_conversation_sync (greeter,
                                                                   "gdm-password",
                                                                   NULL, &error);
        if (!ok) {
                g_critical ("Failed to start conversation: %s", error->message);
                exit (1);
        }

        loop = g_main_loop_new (NULL, FALSE);
        g_main_loop_run (loop);

        return 0;
}
