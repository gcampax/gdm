/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 William Jon McCann <mccann@jhu.edu>
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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#ifdef  HAVE_LOGINDEVPERM
#include <libdevinfo.h>
#endif  /* HAVE_LOGINDEVPERM */

#include <glib.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#include <glib-object.h>

#include <X11/Xlib.h> /* for Display */

#include "gdm-common.h"

#include "gdm-settings-client.h"
#include "gdm-settings-keys.h"

#include "gdm-simple-slave.h"

#include "gdm-server.h"
#include "gdm-session-direct.h"
#include "gdm-greeter-server.h"
#include "gdm-greeter-session.h"
#include "gdm-settings-direct.h"
#include "gdm-settings-keys.h"

#define GDM_SIMPLE_SLAVE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GDM_TYPE_SIMPLE_SLAVE, GdmSimpleSlavePrivate))

#define GDM_DBUS_NAME              "org.gnome.DisplayManager"
#define GDM_DBUS_DISPLAY_INTERFACE "org.gnome.DisplayManager.Display"

#define MAX_CONNECT_ATTEMPTS  10
#define DEFAULT_PING_INTERVAL 15

/* Each of these structs represents a login session */
typedef struct {
        GdmSimpleSlave    *slave;
        GdmGreeterServer  *greeter_server;
        GdmSessionDirect  *session;

        /* Only valid for the primary session */
        gint               greeter_reset_id;
        guint              start_session_id;
} GdmSlaveSession;

struct GdmSimpleSlavePrivate
{
        GPid               pid;

        char              *start_session_service_name;

        int                ping_interval;

        GPid               server_pid;
        guint              connection_attempts;

        GdmServer         *server;
        GdmSlaveSession   *primary_session;
        GList             *other_sessions;
        GdmGreeterSession *greeter;

        guint              start_session_when_ready : 1;
        guint              waiting_to_start_session : 1;
#ifdef  HAVE_LOGINDEVPERM
        gboolean           use_logindevperm;
#endif
#ifdef  WITH_PLYMOUTH
        guint              plymouth_is_running : 1;
#endif
};

enum {
        PROP_0,
};

static void     gdm_simple_slave_class_init     (GdmSimpleSlaveClass *klass);
static void     gdm_simple_slave_init           (GdmSimpleSlave      *simple_slave);
static void     gdm_simple_slave_finalize       (GObject             *object);

G_DEFINE_TYPE (GdmSimpleSlave, gdm_simple_slave, GDM_TYPE_SLAVE)

static void create_new_session (GdmSlaveSession *slave_session);
static void destroy_session    (GdmSlaveSession *slave_session);
static void start_greeter      (GdmSimpleSlave *slave);
static void start_session      (GdmSlaveSession *slave_session);
static void queue_start_session (GdmSimpleSlave *slave,
                                 const char     *service_name);

static void
free_slave_session (GdmSlaveSession *slave_session)
{
        if (slave_session->greeter_server) {
                gdm_greeter_server_stop (slave_session->greeter_server);
                g_object_unref (slave_session->greeter_server);
        }

        if (slave_session->session) {
                gdm_session_direct_close (slave_session->session);
                g_object_unref (slave_session->session);
        }

        g_slice_free (GdmSlaveSession, slave_session);
}

static void
on_session_started (GdmSessionDirect *session,
                    const char       *service_name,
                    int               pid,
                    GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;
        char *username;

        g_debug ("GdmSimpleSlave: session started %d", pid);

        g_assert (slave_session == slave_session->slave->priv->primary_session);

        slave = slave_session->slave;

        /* Run the PreSession script. gdmslave suspends until script has terminated */
        username = gdm_session_direct_get_username (slave->priv->primary_session->session);
        if (username != NULL) {
                gdm_slave_run_script (GDM_SLAVE (slave), GDMCONFDIR "/PreSession", username);
        }
        g_free (username);

        /* FIXME: should we do something here?
         * Note that error return status from PreSession script should
         * be ignored in the case of a X-GDM-BypassXsession session, which can
         * be checked by calling:
         * gdm_session_direct_bypasses_xsession (session)
         */
}

#ifdef  HAVE_LOGINDEVPERM
static void
gdm_simple_slave_grant_console_permissions (GdmSimpleSlave *slave)
{
        char *username;
        char *display_device;
        struct passwd *passwd_entry;

        username = gdm_session_direct_get_username (slave->priv->session);
        display_device = gdm_session_direct_get_display_device (slave->priv->session);

        if (username != NULL) {
                gdm_get_pwent_for_name (username, &passwd_entry);

                /*
                 * Only do logindevperm processing if /dev/console or
                 * a device associated with a VT
                 */
                if (display_device != NULL &&
                   (strncmp (display_device, "/dev/vt/", strlen ("/dev/vt/")) == 0 ||
                    strcmp  (display_device, "/dev/console") == 0)) {
                        g_debug ("Logindevperm login for user %s, device %s",
                                 username, display_device);
                        (void) di_devperm_login (display_device,
                                                 passwd_entry->pw_uid,
                                                 passwd_entry->pw_gid,
                                                 NULL);
                        slave->priv->use_logindevperm = TRUE;
                }
        }

        if (!slave->priv->use_logindevperm) {
                g_debug ("Not calling di_devperm_login login for user %s, device %s",
                         username, display_device);
        }
}

static void
gdm_simple_slave_revoke_console_permissions (GdmSimpleSlave *slave)
{
        char *username;
        char *display_device;

        username = gdm_session_direct_get_username (slave->priv->session);
        display_device = gdm_session_direct_get_display_device (slave->priv->session);

        /*
         * Only do logindevperm processing if /dev/console or a device
         * associated with a VT.  Do this after processing the PostSession
         * script so that permissions for devices are not returned to root
         * before running the script.
         */
        if (slave->priv->use_logindevperm == TRUE &&
            display_device != NULL &&
           (strncmp (display_device, "/dev/vt/", strlen ("/dev/vt/")) == 0 ||
            strcmp  (display_device, "/dev/console") == 0)) {
                g_debug ("di_devperm_logout for user %s, device %s",
                         username, display_device);
                (void) di_devperm_logout (display_device);
                slave->priv->use_logindevperm = FALSE;
        } else {
                g_debug ("Not calling di_devperm_logout logout for user %s, device %s",
                         username, display_device);
        }

        g_free (username);
        g_free (display_device);
}
#endif  /* HAVE_LOGINDEVPERM */

static void
on_session_exited (GdmSessionDirect *session,
                   int               exit_code,
                   GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: session exited with code %d\n", exit_code);
        if (slave->priv->start_session_service_name == NULL) {
                gdm_slave_stopped (GDM_SLAVE (slave));
        }
}

static void
on_session_died (GdmSessionDirect *session,
                 int               signal_number,
                 GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: session died with signal %d, (%s)",
                 signal_number,
                 g_strsignal (signal_number));

        if (slave->priv->start_session_service_name == NULL) {
                gdm_slave_stopped (GDM_SLAVE (slave));
        }
}

static gboolean
add_user_authorization (GdmSimpleSlave *slave,
                        char          **filename)
{
        char    *username;
        gboolean ret;

        username = gdm_session_direct_get_username (slave->priv->primary_session->session);
        ret = gdm_slave_add_user_authorization (GDM_SLAVE (slave),
                                                username,
                                                filename);
        g_free (username);

        return ret;
}

static void
reset_session (GdmSlaveSession *slave_session)
{
        destroy_session (slave_session);
        create_new_session (slave_session);
}

static gboolean
greeter_reset_timeout (GdmSlaveSession *slave_session)
{
        g_debug ("GdmSimpleSlave: resetting greeter");

        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_reset (slave_session->greeter_server);
                reset_session (slave_session);
        } else {
                start_greeter (slave_session->slave);
                create_new_session (slave_session);
        }
        slave_session->greeter_reset_id = 0;
        return FALSE;
}

static void
queue_greeter_reset (GdmSlaveSession *slave_session)
{
        if (slave_session->greeter_reset_id > 0) {
                return;
        }

        slave_session->greeter_reset_id = g_idle_add ((GSourceFunc)greeter_reset_timeout, slave_session);
}

static void
on_session_service_unavailable (GdmSessionDirect *session,
                                const char       *service_name,
                                GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_service_unavailable (slave_session->greeter_server,
                                                        service_name);
        }

        gdm_session_direct_stop_conversation (session, service_name);
}

static void
on_session_setup_complete (GdmSessionDirect *session,
                           const char       *service_name,
                           GdmSlaveSession  *slave_session)
{
        gdm_session_direct_authenticate (session, service_name);
}

static void
on_session_setup_failed (GdmSessionDirect *session,
                         const char       *service_name,
                         const char       *message,
                         GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_problem (slave_session->greeter_server,
                                            service_name,
                                            message != NULL ? message:  _("Unable to initialize login system"));
        }

        gdm_session_direct_stop_conversation (session, service_name);
}

static void
on_session_authenticated (GdmSessionDirect *session,
                          const char       *service_name,
                          GdmSlaveSession  *slave_session)
{
        gdm_session_direct_authorize (session, service_name);
}

static void
on_session_authentication_failed (GdmSessionDirect *session,
                                  const char       *service_name,
                                  const char       *message,
                                  GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_problem (slave_session->greeter_server,
                                            service_name,
                                            message != NULL ? message : _("Unable to authenticate user"));
        }

        g_debug ("GdmSimpleSlave: Authentication failed - may retry");
        gdm_session_direct_stop_conversation (session, service_name);
}

static void
gdm_simple_slave_start_session_when_ready (GdmSimpleSlave *slave,
                                           const char     *service_name)
{
        if (slave->priv->start_session_when_ready) {
                slave->priv->waiting_to_start_session = FALSE;
                queue_start_session (slave, service_name);
        } else {
                slave->priv->waiting_to_start_session = TRUE;
        }
}

static void
on_session_authorized (GdmSessionDirect *session,
                       const char       *service_name,
                       GdmSlaveSession  *slave_session)
{
        gboolean refresh;

        refresh = !(slave_session == slave_session->slave->priv->primary_session);

        gdm_session_direct_accredit (session, service_name, refresh);
}

static void
on_session_authorization_failed (GdmSessionDirect *session,
                                 const char       *service_name,
                                 const char       *message,
                                 GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_problem (slave_session->greeter_server,
                                            service_name,
                                            message != NULL ? message :  _("Unable to authorize user"));
        }

        gdm_session_direct_stop_conversation (session, service_name);
}

static gboolean
try_migrate_session (GdmSlaveSession *slave_session)
{
        char    *username;
        gboolean res;

        g_debug ("GdmSimpleSlave: trying to migrate session");

        username = gdm_session_direct_get_username (slave_session->session);

        /* try to switch to an existing session */
        res = gdm_slave_switch_to_user_session (GDM_SLAVE (slave_session->slave), username);
        g_free (username);

        return res;
}

static void
stop_greeter (GdmSimpleSlave *slave)
{
        char *username;

        g_debug ("GdmSimpleSlave: Stopping greeter");

        if (slave->priv->greeter == NULL) {
                g_debug ("GdmSimpleSlave: No greeter running");
                return;
        }

        /* Run the PostLogin script. gdmslave suspends until script has terminated */
        username = NULL;
        if (slave->priv->primary_session->session != NULL) {
                username = gdm_session_direct_get_username (slave->priv->primary_session->session);
        }

        if (username != NULL) {
                gdm_slave_run_script (GDM_SLAVE (slave), GDMCONFDIR "/PostLogin", username);
        }
        g_free (username);

        gdm_welcome_session_stop (GDM_WELCOME_SESSION (slave->priv->greeter));
}

static void
start_session (GdmSlaveSession *slave_session)
{
        GdmSimpleSlave *slave;
        char    *auth_file;

        slave = slave_session->slave;
        auth_file = NULL;
        add_user_authorization (slave, &auth_file);

        g_assert (auth_file != NULL);

        g_object_set (slave_session->session,
                      "user-x11-authority-file", auth_file,
                      NULL);

        g_free (auth_file);

        gdm_session_direct_start_session (slave_session->session,
                                          slave->priv->start_session_service_name);

        slave_session->start_session_id = 0;
        g_free (slave->priv->start_session_service_name);
        slave->priv->start_session_service_name = NULL;
}

static gboolean
start_session_timeout (GdmSlaveSession *slave_session)
{
        GdmSimpleSlave *slave;
        gboolean migrated;

        slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: accredited");

        migrated = try_migrate_session (slave_session);
        g_debug ("GdmSimpleSlave: migrated: %d", migrated);
        if (migrated) {
                destroy_session (slave_session);

                /* We don't stop the slave here because
                   when Xorg exits it switches to the VT it was
                   started from.  That interferes with fast
                   user switching. */
                queue_greeter_reset (slave_session);

                slave_session->start_session_id = 0;
                g_free (slave->priv->start_session_service_name);
                slave->priv->start_session_service_name = NULL;
        } else {
                if (slave->priv->greeter == NULL) {
                        /* auto login */
                        start_session (slave_session);
                } else {
                        /* Session actually gets started from on_greeter_session_stop */
                        stop_greeter (slave_session->slave);
                }
        }

        return FALSE;
}

static void
queue_start_session (GdmSimpleSlave *slave,
                     const char     *service_name)
{
        GdmSlaveSession *slave_session = slave->priv->primary_session;

        if (slave_session->start_session_id > 0) {
                return;
        }

        slave_session->start_session_id = g_idle_add ((GSourceFunc)start_session_timeout, slave_session);
        slave->priv->start_session_service_name = g_strdup (service_name);
}

static void
on_session_accredited (GdmSessionDirect *session,
                       const char       *service_name,
                       GdmSlaveSession  *slave_session)
{
        if (slave_session == slave_session->slave->priv->primary_session) {
                gdm_session_direct_open_session (session, service_name);
        } else {
                /* For sessions that are not under slave's control,
                   don't actually open a session, just report it happened
                   and wait for disconnection from the greeter.
                */
                gdm_greeter_server_session_opened (slave_session->greeter_server,
                                                   service_name);
        }
}

static void
on_session_accreditation_failed (GdmSessionDirect *session,
                                 const char       *service_name,
                                 const char       *message,
                                 GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;
        gboolean migrated;

        g_debug ("GdmSimpleSlave: accreditation failed");

        slave = slave_session->slave;

        /* Only try migration if slave_session is the primary session */
        if (slave_session == slave->priv->primary_session)
                migrated = try_migrate_session (slave_session);
        else
                migrated = FALSE;

        /* If we switched to another session we don't care if
           accreditation fails */
        if (! migrated) {
                if (slave_session->greeter_server != NULL) {
                        const char *problem;
                        if (message) {
                                problem = message;
                        } else {
                                problem = _("Unable to establish credentials");
                        }
                        gdm_greeter_server_problem (slave_session->greeter_server,
                                                    service_name,
                                                    problem);
                }
        }

        gdm_session_direct_stop_conversation (session, service_name);
}

static void
on_session_opened (GdmSessionDirect *session,
                   const char       *service_name,
                   GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave = slave_session->slave;

#ifdef  HAVE_LOGINDEVPERM
        gdm_simple_slave_grant_console_permissions (slave);
#endif  /* HAVE_LOGINDEVPERM */

        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_session_opened (slave_session->greeter_server, service_name);
                gdm_simple_slave_start_session_when_ready (slave, service_name);
        } else {
                slave->priv->start_session_when_ready = TRUE;
                gdm_simple_slave_start_session_when_ready (slave, service_name);
        }
}

static void
on_session_open_failed (GdmSessionDirect *session,
                        const char       *service_name,
                        const char       *message,
                        GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_problem (slave_session->greeter_server,
                                            service_name,
                                            _("Unable to open session"));
        }

        gdm_session_direct_stop_conversation (session, service_name);
}

static void
on_session_info (GdmSessionDirect *session,
                 const char       *service_name,
                 const char       *text,
                 GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Info: %s", text);
        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_info (slave_session->greeter_server, service_name, text);
        }
}

static void
on_session_problem (GdmSessionDirect *session,
                    const char       *service_name,
                    const char       *text,
                    GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Problem: %s", text);
        gdm_greeter_server_problem (slave_session->greeter_server, service_name, text);
}

static void
on_session_info_query (GdmSessionDirect *session,
                       const char       *service_name,
                       const char       *text,
                       GdmSlaveSession  *slave_session)
{

        g_debug ("GdmSimpleSlave: Info query: %s", text);
        gdm_greeter_server_info_query (slave_session->greeter_server, service_name, text);
}

static void
on_session_secret_info_query (GdmSessionDirect *session,
                              const char       *service_name,
                              const char       *text,
                              GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Secret info query: %s", text);
        gdm_greeter_server_secret_info_query (slave_session->greeter_server, service_name, text);
}

static void
on_session_conversation_started (GdmSessionDirect *session,
                                 const char       *service_name,
                                 GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;
        gboolean res;
        gboolean enabled;
        char    *username;
        int      delay;

        slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: session conversation started");
        if (slave_session->greeter_server != NULL) {
                res = gdm_greeter_server_ready (slave_session->greeter_server,
                                                service_name);
                if (! res) {
                        g_warning ("Unable to send ready");
                }
        }

        if (slave_session == slave->priv->primary_session) {
                enabled = FALSE;
                gdm_slave_get_timed_login_details (GDM_SLAVE (slave), &enabled, &username, &delay);
                if (! enabled) {
                        return;
                }

                if (slave_session->greeter_server != NULL) {
                        gdm_greeter_server_request_timed_login (slave_session->greeter_server, username, delay);
                } else {
                        g_debug ("GdmSimpleSlave: begin auto login for user '%s'", username);
                        /* service_name will be "gdm-autologin"
                         */
                        gdm_session_direct_setup_for_user (slave_session->session, service_name, username);
                }

                g_free (username);
        }
}

static void
on_session_conversation_stopped (GdmSessionDirect *session,
                                 const char       *service_name,
                                 GdmSlaveSession  *slave_session)
{
        gboolean res;
        g_debug ("GdmSimpleSlave: conversation stopped");

        if (slave_session->greeter_server != NULL) {
                res = gdm_greeter_server_conversation_stopped (slave_session->greeter_server,
                                                               service_name);
                if (! res) {
                        g_warning ("Unable to send conversation stopped");
                }
        }
}

static void
on_session_selected_user_changed (GdmSessionDirect *session,
                                  const char       *text,
                                  GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Selected user changed: %s", text);

        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_selected_user_changed (slave_session->greeter_server, text);
        }
}

static void
on_default_language_name_changed (GdmSessionDirect *session,
                                  const char       *text,
                                  GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Default language name changed: %s", text);

        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_default_language_name_changed (slave_session->greeter_server, text);
        }
}

static void
on_default_session_name_changed (GdmSessionDirect *session,
                                 const char       *text,
                                 GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Default session name changed: %s", text);

        if (slave_session->greeter_server != NULL) {
                gdm_greeter_server_default_session_name_changed (slave_session->greeter_server, text);
        }
}

static void
start_autologin_conversation_if_necessary (GdmSlaveSession *slave_session)
{
        GdmSimpleSlave *slave;
        gboolean enabled;

        slave = slave_session->slave;

        /* Only do autologin for the primary session */
        if (slave_session != slave->priv->primary_session)
                return;

        gdm_slave_get_timed_login_details (GDM_SLAVE (slave), &enabled, NULL, NULL);

        if (!enabled) {
                return;
        }

        g_debug ("GdmSimpleSlave: Starting automatic login conversation");
        gdm_session_direct_start_conversation (slave_session->session, "gdm-autologin");
}

static void
create_new_session (GdmSlaveSession *slave_session)
{
        gboolean       display_is_local;
        char          *display_id;
        char          *display_name;
        char          *display_hostname;
        char          *display_device;
        char          *display_seat_id;
        char          *display_x11_authority_file;

        g_debug ("GdmSimpleSlave: Creating new session");

        g_object_get (slave_session->slave,
                      "display-id", &display_id,
                      "display-name", &display_name,
                      "display-hostname", &display_hostname,
                      "display-is-local", &display_is_local,
                      "display-x11-authority-file", &display_x11_authority_file,
                      "display-seat-id", &display_seat_id,
                      NULL);

        display_device = NULL;
        if (slave_session->slave->priv->server != NULL) {
                display_device = gdm_server_get_display_device (slave_session->slave->priv->server);
        }

        slave_session->session = gdm_session_direct_new (display_id,
                                                  display_name,
                                                  display_hostname,
                                                  display_device,
                                                  display_seat_id,
                                                  display_x11_authority_file,
                                                  display_is_local);
        g_free (display_id);
        g_free (display_name);
        g_free (display_device);
        g_free (display_hostname);

        g_signal_connect (slave_session->session, "conversation-started",
                          G_CALLBACK (on_session_conversation_started),
                          slave_session);
        g_signal_connect (slave_session->session, "conversation-stopped",
                          G_CALLBACK (on_session_conversation_stopped),
                          slave_session);
        g_signal_connect (slave_session->session, "service-unavailable",
                          G_CALLBACK (on_session_service_unavailable),
                          slave_session);
        g_signal_connect (slave_session->session, "setup-complete",
                          G_CALLBACK (on_session_setup_complete),
                          slave_session);
        g_signal_connect (slave_session->session, "setup-failed",
                          G_CALLBACK (on_session_setup_failed),
                          slave_session);
        g_signal_connect (slave_session->session, "authenticated",
                          G_CALLBACK (on_session_authenticated),
                          slave_session);
        g_signal_connect (slave_session->session, "authentication-failed",
                          G_CALLBACK (on_session_authentication_failed),
                          slave_session);
        g_signal_connect (slave_session->session, "authorized",
                          G_CALLBACK (on_session_authorized),
                          slave_session);
        g_signal_connect (slave_session->session, "authorization-failed",
                          G_CALLBACK (on_session_authorization_failed),
                          slave_session);
        g_signal_connect (slave_session->session, "accredited",
                          G_CALLBACK (on_session_accredited),
                          slave_session);
        g_signal_connect (slave_session->session, "accreditation-failed",
                          G_CALLBACK (on_session_accreditation_failed),
                          slave_session);
        g_signal_connect (slave_session->session, "session-opened",
                          G_CALLBACK (on_session_opened),
                          slave_session);
        g_signal_connect (slave_session->session, "session-open-failed",
                          G_CALLBACK (on_session_open_failed),
                          slave_session);
        g_signal_connect (slave_session->session, "info",
                          G_CALLBACK (on_session_info),
                          slave_session);
        g_signal_connect (slave_session->session, "problem",
                          G_CALLBACK (on_session_problem),
                          slave_session);
        g_signal_connect (slave_session->session, "info-query",
                          G_CALLBACK (on_session_info_query),
                          slave_session);
        g_signal_connect (slave_session->session, "secret-info-query",
                          G_CALLBACK (on_session_secret_info_query),
                          slave_session);
        g_signal_connect (slave_session->session, "session-started",
                          G_CALLBACK (on_session_started),
                          slave_session);
        g_signal_connect (slave_session->session, "session-exited",
                          G_CALLBACK (on_session_exited),
                          slave_session);
        g_signal_connect (slave_session->session, "session-died",
                          G_CALLBACK (on_session_died),
                          slave_session);
#if 0
        g_signal_connect (slave_session->session, "closed",
                          G_CALLBACK (on_session_closed),
                          slave_session);
#endif
        g_signal_connect (slave_session->session, "selected-user-changed",
                          G_CALLBACK (on_session_selected_user_changed),
                          slave_session);

        g_signal_connect (slave_session->session, "default-language-name-changed",
                          G_CALLBACK (on_default_language_name_changed),
                          slave_session);

        g_signal_connect (slave_session->session, "default-session-name-changed",
                          G_CALLBACK (on_default_session_name_changed),
                          slave_session);

        start_autologin_conversation_if_necessary (slave_session);
}

static void
destroy_session (GdmSlaveSession *slave_session)
{
        if (slave_session->session == NULL) {
                return;
        }

        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_conversation_started),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_conversation_stopped),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_service_unavailable),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_setup_complete),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_setup_failed),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_authenticated),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_authentication_failed),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_authorized),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_authorization_failed),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_accredited),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_accreditation_failed),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_opened),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_open_failed),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_info),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_problem),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_info_query),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_secret_info_query),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_started),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_exited),
                                              slave_session);
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_died),
                                              slave_session);
#if 0
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_closed),
                                              slave_session);
#endif
        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_session_selected_user_changed),
                                              slave_session);

        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_default_language_name_changed),
                                              slave_session);

        g_signal_handlers_disconnect_by_func (slave_session->session,
                                              G_CALLBACK (on_default_session_name_changed),
                                              slave_session);

        gdm_session_direct_close (slave_session->session);
        g_clear_object (&slave_session->session);
}

static void
on_greeter_session_start (GdmGreeterSession *greeter,
                          GdmSimpleSlave    *slave)
{
        g_debug ("GdmSimpleSlave: Greeter started");
}

static void
on_greeter_session_stop (GdmGreeterSession *greeter,
                         GdmSimpleSlave    *slave)
{
        g_debug ("GdmSimpleSlave: Greeter stopped");
        if (slave->priv->start_session_service_name == NULL) {
                gdm_slave_stopped (GDM_SLAVE (slave));
        } else {
                gdm_greeter_server_stop (slave->priv->primary_session->greeter_server);
                start_session (slave->priv->primary_session);
        }

        g_object_unref (slave->priv->greeter);
        slave->priv->greeter = NULL;

}

static void
on_greeter_session_exited (GdmGreeterSession    *greeter,
                           int                   code,
                           GdmSimpleSlave       *slave)
{
        g_debug ("GdmSimpleSlave: Greeter exited: %d", code);
        if (slave->priv->start_session_service_name == NULL) {
                gdm_slave_stopped (GDM_SLAVE (slave));
        }
}

static void
on_greeter_session_died (GdmGreeterSession    *greeter,
                         int                   signal,
                         GdmSimpleSlave       *slave)
{
        g_debug ("GdmSimpleSlave: Greeter died: %d", signal);
        if (slave->priv->start_session_service_name == NULL) {
                gdm_slave_stopped (GDM_SLAVE (slave));
        }
}

static void
on_greeter_start_conversation (GdmGreeterServer *greeter_server,
                               const char       *service_name,
                               GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_reset_id > 0) {
                return;
        }

        g_debug ("GdmSimpleSlave: our greeter is starting conversation"
                 " with '%s' pam service'", service_name);
        gdm_session_direct_start_conversation (slave_session->session, service_name);
}

static void
on_greeter_begin_verification (GdmGreeterServer *greeter_server,
                               const char       *service_name,
                               GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: begin verification");
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_setup (slave_session->session, service_name);
}

static void
on_greeter_begin_auto_login (GdmGreeterServer *greeter_server,
                             const char       *username,
                             GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: begin auto login for user '%s'", username);
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_setup_for_user (slave_session->session, "gdm-autologin", username);
}

static void
on_greeter_begin_verification_for_user (GdmGreeterServer *greeter_server,
                                        const char       *service_name,
                                        const char       *username,
                                        GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: begin verification");
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_setup_for_user (slave_session->session, service_name, username);
}

static void
on_greeter_answer (GdmGreeterServer *greeter_server,
                   const char       *service_name,
                   const char       *text,
                   GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_answer_query (slave_session->session, service_name, text);
}

static void
on_greeter_session_selected (GdmGreeterServer *greeter_server,
                             const char       *text,
                             GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_select_session (slave_session->session, text);
}

static void
on_greeter_language_selected (GdmGreeterServer *greeter_server,
                              const char       *text,
                              GdmSlaveSession  *slave_session)
{
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        gdm_session_direct_select_language (slave_session->session, text);
}

static void
on_greeter_user_selected (GdmGreeterServer *greeter_server,
                          const char       *text,
                          GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Greeter user selected");
}

static void
on_greeter_cancel (GdmGreeterServer *greeter_server,
                   GdmSlaveSession  *slave_session)
{
        g_debug ("GdmSimpleSlave: Greeter cancelled");
        queue_greeter_reset (slave_session);
}

static void
on_greeter_connected (GdmGreeterServer *greeter_server,
                      GdmSlaveSession  *slave_session)
{
        gboolean display_is_local;

        g_debug ("GdmSimpleSlave: Greeter connected");
        if (slave_session->greeter_reset_id > 0) {
                return;
        }

        g_object_get (slave_session->slave,
                      "display-is-local", &display_is_local,
                      NULL);

        /* If XDMCP stop pinging */
        if ( ! display_is_local) {
                alarm (0);
        }
}

static void
on_greeter_disconnected_greeter (GdmGreeterServer *greeter_server,
                                 GdmSlaveSession  *slave_session)
{
        gboolean display_is_local;

        g_debug ("GdmSimpleSlave: Our greeter disconnected");

        g_object_get (slave_session->slave,
                      "display-is-local", &display_is_local,
                      NULL);

        if ( ! display_is_local) {
                gdm_slave_stopped (GDM_SLAVE (slave_session->slave));
        }
}

static void
on_greeter_disconnected_external (GdmGreeterServer *greeter_server,
                                  GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;

        g_debug ("GdmSimpleSlave: External greeter disconnected");

        slave = slave_session->slave;

        slave->priv->other_sessions = g_list_remove (slave->priv->other_sessions,
                                                     slave_session);
        free_slave_session (slave_session);
}

static void
on_start_session_when_ready (GdmGreeterServer *session,
                             const char       *service_name,
                             GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;

        slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: Will start session when ready");
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        slave->priv->start_session_when_ready = TRUE;

        if (slave->priv->waiting_to_start_session) {
                gdm_simple_slave_start_session_when_ready (slave, service_name);
        }
}

static void
on_start_session_later (GdmGreeterServer *session,
                        const char       *service_name,
                        GdmSlaveSession  *slave_session)
{
        GdmSimpleSlave *slave;

        slave = slave_session->slave;

        g_debug ("GdmSimpleSlave: Will start session when ready and told");
        if (slave_session->greeter_reset_id > 0) {
                return;
        }
        slave->priv->start_session_when_ready = FALSE;
}

#ifdef  WITH_PLYMOUTH
static gboolean
plymouth_is_running (void)
{
        int      status;
        gboolean res;
        GError  *error;

        error = NULL;
        res = g_spawn_command_line_sync ("/bin/plymouth --ping",
                                         NULL, NULL, &status, &error);
        if (! res) {
                g_debug ("Could not ping plymouth: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        return WIFEXITED (status) && WEXITSTATUS (status) == 0;
}

static void
plymouth_prepare_for_transition (GdmSimpleSlave *slave)
{
        gboolean res;
        GError  *error;

        error = NULL;
        res = g_spawn_command_line_sync ("/bin/plymouth deactivate",
                                         NULL, NULL, NULL, &error);
        if (! res) {
                g_warning ("Could not deactivate plymouth: %s", error->message);
                g_error_free (error);
        }
}

static void
plymouth_quit_with_transition (GdmSimpleSlave *slave)
{
        gboolean res;
        GError  *error;

        error = NULL;
        res = g_spawn_command_line_sync ("/bin/plymouth quit --retain-splash",
                                         NULL, NULL, NULL, &error);
        if (! res) {
                g_warning ("Could not quit plymouth: %s", error->message);
                g_error_free (error);
        }
        slave->priv->plymouth_is_running = FALSE;
}

static void
plymouth_quit_without_transition (GdmSimpleSlave *slave)
{
        gboolean res;
        GError  *error;

        error = NULL;
        res = g_spawn_command_line_sync ("/bin/plymouth quit",
                                         NULL, NULL, NULL, &error);
        if (! res) {
                g_warning ("Could not quit plymouth: %s", error->message);
                g_error_free (error);
        }
        slave->priv->plymouth_is_running = FALSE;
}
#endif

static void
setup_server (GdmSimpleSlave *slave)
{
        /* Put cursor out of the way on first head */
        gdm_slave_set_initial_cursor_position (GDM_SLAVE (slave));

        /* Set the busy cursor */
        gdm_slave_set_busy_cursor (GDM_SLAVE (slave));

        /* Set the initial keyboard layout to something reasonable */
        gdm_slave_set_initial_keyboard_layout (GDM_SLAVE (slave));
        /* The root window has a background that may be useful
         * to cross fade or transition from when setting the
         * login screen background.  We read it here, and stuff
         * it into the standard _XROOTPMAP_ID root window property,
         * so gnome-settings-daemon can get at it.
         */
        gdm_slave_save_root_windows (GDM_SLAVE (slave));

#ifdef WITH_PLYMOUTH
        /* Plymouth is waiting for the go-ahead to exit */
        if (slave->priv->plymouth_is_running) {
                plymouth_quit_with_transition (slave);
        }
#endif
}

static void
create_greeter_server (GdmSlaveSession *slave_session,
                       const char      *display_id,
                       gboolean         external)
{
        slave_session->greeter_server = gdm_greeter_server_new (display_id);
        g_signal_connect (slave_session->greeter_server,
                          "start-conversation",
                          G_CALLBACK (on_greeter_start_conversation),
                          slave_session);
        g_signal_connect (slave_session->greeter_server,
                          "begin-verification",
                          G_CALLBACK (on_greeter_begin_verification),
                          slave_session);
        g_signal_connect (slave_session->greeter_server,
                          "begin-verification-for-user",
                          G_CALLBACK (on_greeter_begin_verification_for_user),
                          slave_session);
        g_signal_connect (slave_session->greeter_server,
                          "query-answer",
                          G_CALLBACK (on_greeter_answer),
                          slave_session);
        g_signal_connect (slave_session->greeter_server,
                          "cancelled",
                          G_CALLBACK (on_greeter_cancel),
                          slave_session);

        if (!external) {
                g_signal_connect (slave_session->greeter_server,
                                  "begin-auto-login",
                                  G_CALLBACK (on_greeter_begin_auto_login),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "session-selected",
                                  G_CALLBACK (on_greeter_session_selected),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "language-selected",
                                  G_CALLBACK (on_greeter_language_selected),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "user-selected",
                                  G_CALLBACK (on_greeter_user_selected),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "start-session-when-ready",
                                  G_CALLBACK (on_start_session_when_ready),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "start-session-later",
                                  G_CALLBACK (on_start_session_later),
                                  slave_session);

                g_signal_connect (slave_session->greeter_server,
                                  "connected",
                                  G_CALLBACK (on_greeter_connected),
                                  slave_session);
                g_signal_connect (slave_session->greeter_server,
                                  "disconnected",
                                  G_CALLBACK (on_greeter_disconnected_greeter),
                                  slave_session);
        } else {
                g_signal_connect (slave_session->greeter_server,
                                  "disconnected",
                                  G_CALLBACK (on_greeter_disconnected_external),
                                  slave_session);
        }

        gdm_greeter_server_start (slave_session->greeter_server, external);
}

static void
start_greeter (GdmSimpleSlave *slave)
{
        gboolean       display_is_local;
        char          *display_id;
        char          *display_name;
        char          *seat_id;
        char          *display_device;
        char          *display_hostname;
        char          *auth_file;
        char          *address;
        gboolean       res;

        g_debug ("GdmSimpleSlave: Running greeter");

        display_is_local = FALSE;
        display_id = NULL;
        display_name = NULL;
        seat_id = NULL;
        auth_file = NULL;
        display_device = NULL;
        display_hostname = NULL;

        g_object_get (slave,
                      "display-id", &display_id,
                      "display-is-local", &display_is_local,
                      "display-name", &display_name,
                      "display-seat-id", &seat_id,
                      "display-hostname", &display_hostname,
                      "display-x11-authority-file", &auth_file,
                      NULL);

        g_debug ("GdmSimpleSlave: Creating greeter for %s %s", display_name, display_hostname);

        if (slave->priv->server != NULL) {
                display_device = gdm_server_get_display_device (slave->priv->server);
        }

        /* FIXME: send a signal back to the master */

        /* If XDMCP setup pinging */
        slave->priv->ping_interval = DEFAULT_PING_INTERVAL;
        res = gdm_settings_direct_get_int (GDM_KEY_PING_INTERVAL,
                                           &(slave->priv->ping_interval));

        if ( ! display_is_local && res && slave->priv->ping_interval > 0) {
                alarm (slave->priv->ping_interval);
        }

        /* Run the init script. gdmslave suspends until script has terminated */
        gdm_slave_run_script (GDM_SLAVE (slave), GDMCONFDIR "/Init", GDM_USERNAME);

        create_greeter_server (slave->priv->primary_session,
                               display_id, FALSE);

        g_debug ("GdmSimpleSlave: Creating greeter on %s %s %s", display_name, display_device, display_hostname);
        slave->priv->greeter = gdm_greeter_session_new (display_name,
                                                        seat_id,
                                                        display_device,
                                                        display_hostname,
                                                        display_is_local);
        g_signal_connect (slave->priv->greeter,
                          "started",
                          G_CALLBACK (on_greeter_session_start),
                          slave);
        g_signal_connect (slave->priv->greeter,
                          "stopped",
                          G_CALLBACK (on_greeter_session_stop),
                          slave);
        g_signal_connect (slave->priv->greeter,
                          "exited",
                          G_CALLBACK (on_greeter_session_exited),
                          slave);
        g_signal_connect (slave->priv->greeter,
                          "died",
                          G_CALLBACK (on_greeter_session_died),
                          slave);
        g_object_set (slave->priv->greeter,
                      "x11-authority-file", auth_file,
                      NULL);

        address = gdm_greeter_server_get_address (slave->priv->primary_session->greeter_server);
        gdm_welcome_session_set_server_address (GDM_WELCOME_SESSION (slave->priv->greeter), address);
        g_free (address);
        gdm_welcome_session_start (GDM_WELCOME_SESSION (slave->priv->greeter));

        g_free (display_id);
        g_free (display_name);
        g_free (seat_id);
        g_free (display_device);
        g_free (display_hostname);
        g_free (auth_file);
}

static gboolean
idle_connect_to_display (GdmSimpleSlave *slave)
{
        gboolean res;

        slave->priv->connection_attempts++;

        res = gdm_slave_connect_to_x11_display (GDM_SLAVE (slave));
        if (res) {
                gboolean enabled;
                int      delay;

                /* FIXME: handle wait-for-go */

                setup_server (slave);

                delay = 0;
                enabled = FALSE;
                gdm_slave_get_timed_login_details (GDM_SLAVE (slave), &enabled, NULL, &delay);
                if (! enabled || delay > 0) {
                        start_greeter (slave);
                        create_new_session (slave->priv->primary_session);
                } else {
                        /* Run the init script. gdmslave suspends until script has terminated */
                        gdm_slave_run_script (GDM_SLAVE (slave), GDMCONFDIR "/Init", GDM_USERNAME);
                        reset_session (slave->priv->primary_session);
                }
        } else {
                if (slave->priv->connection_attempts >= MAX_CONNECT_ATTEMPTS) {
                        g_warning ("Unable to connect to display after %d tries - bailing out", slave->priv->connection_attempts);
                        exit (1);
                }
                return TRUE;
        }

        return FALSE;
}

static void
on_server_ready (GdmServer      *server,
                 GdmSimpleSlave *slave)
{
        g_idle_add ((GSourceFunc)idle_connect_to_display, slave);
}

static void
on_server_exited (GdmServer      *server,
                  int             exit_code,
                  GdmSimpleSlave *slave)
{
        g_debug ("GdmSimpleSlave: server exited with code %d\n", exit_code);

        gdm_slave_stopped (GDM_SLAVE (slave));

#ifdef WITH_PLYMOUTH
        if (slave->priv->plymouth_is_running) {
                plymouth_quit_without_transition (slave);
        }
#endif
}

static void
on_server_died (GdmServer      *server,
                int             signal_number,
                GdmSimpleSlave *slave)
{
        g_debug ("GdmSimpleSlave: server died with signal %d, (%s)",
                 signal_number,
                 g_strsignal (signal_number));

        gdm_slave_stopped (GDM_SLAVE (slave));

#ifdef WITH_PLYMOUTH
        if (slave->priv->plymouth_is_running) {
                plymouth_quit_without_transition (slave);
        }
#endif
}

static gboolean
gdm_simple_slave_run (GdmSimpleSlave *slave)
{
        char    *display_name;
        char    *auth_file;
        char    *seat_id;
        gboolean display_is_local;

        g_object_get (slave,
                      "display-is-local", &display_is_local,
                      "display-name", &display_name,
                      "display-seat-id", &seat_id,
                      "display-x11-authority-file", &auth_file,
                      NULL);

        /* if this is local display start a server if one doesn't
         * exist */
        if (display_is_local) {
                gboolean res;
                gboolean disable_tcp;

                slave->priv->server = gdm_server_new (display_name, seat_id, auth_file);

                disable_tcp = TRUE;
                if (gdm_settings_client_get_boolean (GDM_KEY_DISALLOW_TCP,
                                                     &disable_tcp)) {
                        g_object_set (slave->priv->server,
                                      "disable-tcp", disable_tcp,
                                      NULL);
                }

                g_signal_connect (slave->priv->server,
                                  "exited",
                                  G_CALLBACK (on_server_exited),
                                  slave);
                g_signal_connect (slave->priv->server,
                                  "died",
                                  G_CALLBACK (on_server_died),
                                  slave);
                g_signal_connect (slave->priv->server,
                                  "ready",
                                  G_CALLBACK (on_server_ready),
                                  slave);

#ifdef WITH_PLYMOUTH
                slave->priv->plymouth_is_running = plymouth_is_running ();

                if (slave->priv->plymouth_is_running) {
                        plymouth_prepare_for_transition (slave);
                        res = gdm_server_start_on_active_vt (slave->priv->server);
                } else
#endif
                {
                        res = gdm_server_start (slave->priv->server);
                }
                if (! res) {
                        g_warning (_("Could not start the X "
                                     "server (your graphical environment) "
                                     "due to an internal error. "
                                     "Please contact your system administrator "
                                     "or check your syslog to diagnose. "
                                     "In the meantime this display will be "
                                     "disabled.  Please restart GDM when "
                                     "the problem is corrected."));
#ifdef WITH_PLYMOUTH
                        if (slave->priv->plymouth_is_running) {
                                plymouth_quit_without_transition (slave);
                        }
#endif
                        exit (1);
                }

                g_debug ("GdmSimpleSlave: Started X server");
        } else {
                g_timeout_add (500, (GSourceFunc)idle_connect_to_display, slave);
        }

        g_free (display_name);
        g_free (auth_file);

        return TRUE;
}

static gboolean
gdm_simple_slave_get_private_connection (GdmSlave    *slave,
                                         const char  *session_id,
                                         char       **address,
                                         GError     **error)
{
        GdmSimpleSlave *self = GDM_SIMPLE_SLAVE (slave);
        char *actual_session_id;
        char *display_id;
        GdmSlaveSession *slave_session;

        actual_session_id = gdm_session_direct_get_session_id (self->priv->primary_session->session);
        if (actual_session_id && strcmp(actual_session_id, session_id) != 0) {
                g_set_error (error, GDM_SLAVE_ERROR, GDM_SLAVE_ERROR_WRONG_SESSION,
                             "Session ID of the caller does not match the one currently supervised"
                             "by this slave");

                g_free (actual_session_id);
                return FALSE;
        }
        g_free (actual_session_id);

        g_object_get (self, "display-id", &display_id, NULL);

        slave_session = g_slice_new0 (GdmSlaveSession);
        slave_session->slave = self;

        create_greeter_server (slave_session, display_id, TRUE);
        create_new_session (slave_session);

        *address = gdm_greeter_server_get_address (slave_session->greeter_server);

        g_free (display_id);
        return TRUE;
}

static gboolean
gdm_simple_slave_start (GdmSlave *slave)
{
        GDM_SLAVE_CLASS (gdm_simple_slave_parent_class)->start (slave);

        gdm_simple_slave_run (GDM_SIMPLE_SLAVE (slave));

        return TRUE;
}

static gboolean
gdm_simple_slave_stop (GdmSlave *slave)
{
        GdmSimpleSlave *self = GDM_SIMPLE_SLAVE (slave);

        g_debug ("GdmSimpleSlave: Stopping simple_slave");

        GDM_SLAVE_CLASS (gdm_simple_slave_parent_class)->stop (slave);

        if (self->priv->greeter != NULL) {
                stop_greeter (self);
        }

        g_list_free_full (self->priv->other_sessions, (GDestroyNotify) free_slave_session);
        self->priv->other_sessions = NULL;

        if (self->priv->primary_session->session != NULL) {
                char *username;

                /* Run the PostSession script. gdmslave suspends until script
                 * has terminated
                 */
                username = gdm_session_direct_get_username (self->priv->primary_session->session);
                if (username != NULL) {
                        gdm_slave_run_script (slave, GDMCONFDIR "/PostSession", username);
                }
                g_free (username);

#ifdef  HAVE_LOGINDEVPERM
                gdm_simple_slave_revoke_console_permissions (self);
#endif

                gdm_session_direct_close (self->priv->primary_session->session);
                g_clear_object (&self->priv->primary_session->session);
        }

        if (self->priv->server != NULL) {
                gdm_server_stop (self->priv->server);
                g_clear_object (&self->priv->server);
        }

        return TRUE;
}

static void
gdm_simple_slave_set_property (GObject      *object,
                               guint          prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
        switch (prop_id) {
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
gdm_simple_slave_get_property (GObject    *object,
                               guint       prop_id,
                               GValue      *value,
                               GParamSpec *pspec)
{
        switch (prop_id) {
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static GObject *
gdm_simple_slave_constructor (GType                  type,
                              guint                  n_construct_properties,
                              GObjectConstructParam *construct_properties)
{
        GdmSimpleSlave      *simple_slave;

        simple_slave = GDM_SIMPLE_SLAVE (G_OBJECT_CLASS (gdm_simple_slave_parent_class)->constructor (type,
                                                                                 n_construct_properties,
                                                                                 construct_properties));

        return G_OBJECT (simple_slave);
}

static void
gdm_simple_slave_class_init (GdmSimpleSlaveClass *klass)
{
        GObjectClass  *object_class = G_OBJECT_CLASS (klass);
        GdmSlaveClass *slave_class = GDM_SLAVE_CLASS (klass);

        object_class->get_property = gdm_simple_slave_get_property;
        object_class->set_property = gdm_simple_slave_set_property;
        object_class->constructor = gdm_simple_slave_constructor;
        object_class->finalize = gdm_simple_slave_finalize;

        slave_class->start = gdm_simple_slave_start;
        slave_class->stop = gdm_simple_slave_stop;
        slave_class->get_private_connection = gdm_simple_slave_get_private_connection;

        g_type_class_add_private (klass, sizeof (GdmSimpleSlavePrivate));
}

static void
gdm_simple_slave_init (GdmSimpleSlave *slave)
{
        slave->priv = GDM_SIMPLE_SLAVE_GET_PRIVATE (slave);
#ifdef  HAVE_LOGINDEVPERM
        slave->priv->use_logindevperm = FALSE;
#endif

        slave->priv->primary_session = g_slice_new0 (GdmSlaveSession);
        slave->priv->primary_session->slave = slave;
}

static void
gdm_simple_slave_finalize (GObject *object)
{
        GdmSimpleSlave *simple_slave;

        g_return_if_fail (object != NULL);
        g_return_if_fail (GDM_IS_SIMPLE_SLAVE (object));

        simple_slave = GDM_SIMPLE_SLAVE (object);

        g_return_if_fail (simple_slave->priv != NULL);

        gdm_simple_slave_stop (GDM_SLAVE (simple_slave));

        if (simple_slave->priv->primary_session->greeter_reset_id > 0) {
                g_source_remove (simple_slave->priv->primary_session->greeter_reset_id);
                simple_slave->priv->primary_session->greeter_reset_id = 0;
        }

        G_OBJECT_CLASS (gdm_simple_slave_parent_class)->finalize (object);
}

GdmSlave *
gdm_simple_slave_new (const char *id)
{
        GObject *object;

        object = g_object_new (GDM_TYPE_SIMPLE_SLAVE,
                               "display-id", id,
                               NULL);

        return GDM_SLAVE (object);
}
