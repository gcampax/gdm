/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
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
#include <pwd.h>
#include <grp.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <gdk/gdkx.h>
#include <gtk/gtk.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <X11/Xlib.h> /* for Display */

#include "gdm-common.h"

#include "gdm-slave.h"
#include "gdm-slave-glue.h"

#include "gdm-server.h"
#include "gdm-session.h"
#include "gdm-greeter-proxy.h"

extern char **environ;

#define GDM_SLAVE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GDM_TYPE_SLAVE, GdmSlavePrivate))

#define GDM_SLAVE_COMMAND LIBEXECDIR"/gdm-slave"

#define GDM_DBUS_NAME	           "org.gnome.DisplayManager"
#define GDM_DBUS_DISPLAY_INTERFACE "org.gnome.DisplayManager.Display"

#define MAX_CONNECT_ATTEMPTS 10

struct GdmSlavePrivate
{
	char            *id;
	GPid             pid;
        guint            output_watch_id;
        guint            error_watch_id;

	int              ping_interval;

	GPid             server_pid;
	Display         *server_display;
	guint            connection_attempts;

	/* cached display values */
	char            *display_id;
	char            *display_name;
	int             *display_number;
	char            *display_hostname;
	gboolean         display_is_local;
	gboolean         display_is_parented;
	char            *display_x11_authority_file;
	char            *display_x11_cookie;
	char            *parent_display_name;
	char            *parent_display_x11_authority_file;

	/* user selected */
	char            *selected_session;
	char            *selected_language;

	GdmServer       *server;
	GdmGreeterProxy *greeter;
	GdmSession      *session;
	DBusGProxy      *display_proxy;
        DBusGConnection *connection;
};

enum {
	PROP_0,
	PROP_DISPLAY_ID,
};

enum {
	SESSION_STARTED,
	SESSION_EXITED,
	SESSION_DIED,
	LAST_SIGNAL
};

static guint signals [LAST_SIGNAL] = { 0, };

static void	gdm_slave_class_init	(GdmSlaveClass *klass);
static void	gdm_slave_init	        (GdmSlave      *slave);
static void	gdm_slave_finalize	(GObject            *object);

G_DEFINE_TYPE (GdmSlave, gdm_slave, G_TYPE_OBJECT)

static void
set_busy_cursor (GdmSlave *slave)
{
	if (slave->priv->server_display != NULL) {
		Cursor xcursor;

		xcursor = XCreateFontCursor (slave->priv->server_display, GDK_WATCH);
		XDefineCursor (slave->priv->server_display,
			       DefaultRootWindow (slave->priv->server_display),
			       xcursor);
		XFreeCursor (slave->priv->server_display, xcursor);
		XSync (slave->priv->server_display, False);
	}
}

static void
gdm_slave_whack_temp_auth_file (GdmSlave *slave)
{
#if 0
	uid_t old;

	old = geteuid ();
	if (old != 0)
		seteuid (0);
	if (d->parent_temp_auth_file != NULL) {
		VE_IGNORE_EINTR (g_unlink (d->parent_temp_auth_file));
	}
	g_free (d->parent_temp_auth_file);
	d->parent_temp_auth_file = NULL;
	if (old != 0)
		seteuid (old);
#endif
}


static void
create_temp_auth_file (GdmSlave *slave)
{
#if 0
	if (d->type == TYPE_FLEXI_XNEST &&
	    d->parent_auth_file != NULL) {
		if (d->parent_temp_auth_file != NULL) {
			VE_IGNORE_EINTR (g_unlink (d->parent_temp_auth_file));
		}
		g_free (d->parent_temp_auth_file);
		d->parent_temp_auth_file =
			copy_auth_file (d->server_uid,
					gdm_daemon_config_get_gdmuid (),
					d->parent_auth_file);
	}
#endif
}

static void
listify_hash (const char *key,
	      const char *value,
	      GPtrArray  *env)
{
	char *str;
	str = g_strdup_printf ("%s=%s", key, value);
	g_debug ("environment: %s", str);
	g_ptr_array_add (env, str);
}

static GPtrArray *
get_script_environment (GdmSlave   *slave,
			const char *username)
{
	GPtrArray     *env;
	GHashTable    *hash;
	struct passwd *pwent;
	char          *x_servers_file;

	env = g_ptr_array_new ();

	/* create a hash table of current environment, then update keys has necessary */
	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	/* modify environment here */
	g_hash_table_insert (hash, g_strdup ("HOME"), g_strdup ("/"));
	g_hash_table_insert (hash, g_strdup ("PWD"), g_strdup ("/"));
	g_hash_table_insert (hash, g_strdup ("SHELL"), g_strdup ("/bin/sh"));

	g_hash_table_insert (hash, g_strdup ("LOGNAME"), g_strdup (username));
	g_hash_table_insert (hash, g_strdup ("USER"), g_strdup (username));
	g_hash_table_insert (hash, g_strdup ("USERNAME"), g_strdup (username));

	pwent = getpwnam (username);
	if (pwent != NULL) {
		if (pwent->pw_dir != NULL && pwent->pw_dir[0] != '\0') {
			g_hash_table_insert (hash, g_strdup ("HOME"), g_strdup (pwent->pw_dir));
			g_hash_table_insert (hash, g_strdup ("PWD"), g_strdup (pwent->pw_dir));
		}

		g_hash_table_insert (hash, g_strdup ("SHELL"), g_strdup (pwent->pw_shell));
	}

	if (slave->priv->display_is_parented) {
		g_hash_table_insert (hash, g_strdup ("GDM_PARENT_DISPLAY"), g_strdup (slave->priv->parent_display_name));

		/*g_hash_table_insert (hash, "GDM_PARENT_XAUTHORITY"), slave->priv->parent_temp_auth_file));*/
	}

	/* some env for use with the Pre and Post scripts */
	x_servers_file = gdm_make_filename (AUTHDIR,
					    slave->priv->display_name,
					    ".Xservers");
	g_hash_table_insert (hash, g_strdup ("X_SERVERS"), x_servers_file);

	if (! slave->priv->display_is_local) {
		g_hash_table_insert (hash, g_strdup ("REMOTE_HOST"), g_strdup (slave->priv->display_hostname));
	}

	/* Runs as root */
	g_hash_table_insert (hash, g_strdup ("XAUTHORITY"), g_strdup (slave->priv->display_x11_authority_file));
	g_hash_table_insert (hash, g_strdup ("DISPLAY"), g_strdup (slave->priv->display_name));

	/*g_setenv ("PATH", gdm_daemon_config_get_value_string (GDM_KEY_ROOT_PATH), TRUE);*/

	g_hash_table_insert (hash, g_strdup ("RUNNING_UNDER_GDM"), g_strdup ("true"));

#if 0
	if ( ! ve_string_empty (d->theme_name))
		g_setenv ("GDM_GTK_THEME", d->theme_name, TRUE);
#endif
	g_hash_table_remove (hash, "MAIL");


	g_hash_table_foreach (hash, (GHFunc)listify_hash, env);
	g_hash_table_destroy (hash);

	g_ptr_array_add (env, NULL);

	return env;
}

static gboolean
gdm_slave_exec_script (GdmSlave      *slave,
		       const char    *dir,
		       const char    *login)
{
	char      *script;
	char     **argv;
	gint       status;
	GError    *error;
	GPtrArray *env;
	gboolean   res;
	gboolean   ret;

	g_assert (dir != NULL);
	g_assert (login != NULL);

	script = g_build_filename (dir, slave->priv->display_name, NULL);
	if (g_access (script, R_OK|X_OK) != 0) {
		g_free (script);
		script = NULL;
	}

	if (script == NULL &&
	    slave->priv->display_hostname != NULL) {
		script = g_build_filename (dir, slave->priv->display_hostname, NULL);
		if (g_access (script, R_OK|X_OK) != 0) {
			g_free (script);
			script = NULL;
		}
	}

#if 0
	if (script == NULL &&
	    SERVER_IS_XDMCP (d)) {
		script = g_build_filename (dir, "XDMCP", NULL);
		if (g_access (script, R_OK|X_OK) != 0) {
			g_free (script);
			script = NULL;
		}
	}
	if (script == NULL &&
	    SERVER_IS_FLEXI (d)) {
		script = g_build_filename (dir, "Flexi", NULL);
		if (g_access (script, R_OK|X_OK) != 0) {
			g_free (script);
			script = NULL;
		}
	}
#endif

	if (script == NULL) {
		script = g_build_filename (dir, "Default", NULL);
		if (g_access (script, R_OK|X_OK) != 0) {
			g_free (script);
			script = NULL;
		}
	}

	if (script == NULL) {
		return TRUE;
	}

	create_temp_auth_file (slave);

	g_debug ("Running process: %s", script);
	error = NULL;
	if (! g_shell_parse_argv (script, NULL, &argv, &error)) {
		g_warning ("Could not parse command: %s", error->message);
		g_error_free (error);
		goto out;
	}

	env = get_script_environment (slave, login);

	res = g_spawn_sync (NULL,
			    argv,
			    (char **)env->pdata,
			    G_SPAWN_SEARCH_PATH,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    &status,
			    &error);

	g_ptr_array_foreach (env, (GFunc)g_free, NULL);
        g_ptr_array_free (env, TRUE);

	gdm_slave_whack_temp_auth_file (slave);

	if (WIFEXITED (status)) {
		ret = WEXITSTATUS (status) != 0;
	} else {
		ret = TRUE;
	}

 out:
	g_free (script);

	return ret;
}

static void
on_session_started (GdmSession *session,
                    GPid        pid,
		    GdmSlave   *slave)
{
	g_debug ("session started on pid %d\n", (int) pid);
	g_signal_emit (slave, signals [SESSION_STARTED], 0, pid);
}

static void
on_session_exited (GdmSession *session,
                   int         exit_code,
		   GdmSlave   *slave)
{
	g_debug ("session exited with code %d\n", exit_code);
	g_signal_emit (slave, signals [SESSION_EXITED], 0, exit_code);
}

static void
on_session_died (GdmSession *session,
                 int         signal_number,
		 GdmSlave   *slave)
{
	g_debug ("session died with signal %d, (%s)",
		 signal_number,
		 g_strsignal (signal_number));
	g_signal_emit (slave, signals [SESSION_DIED], 0, signal_number);
}

static gboolean
is_prog_in_path (const char *prog)
{
	char    *f;
	gboolean ret;

	f = g_find_program_in_path (prog);
	ret = (f != NULL);
	g_free (f);
	return ret;
}

static gboolean
get_session_command (const char *file,
		     char      **command)
{
	GKeyFile   *key_file;
	GError     *error;
	char       *full_path;
	char       *exec;
	gboolean    ret;
	gboolean    res;
	const char *search_dirs[] = {
		"/etc/X11/sessions/",
		DMCONFDIR "/Sessions/",
		DATADIR "/gdm/BuiltInSessions/",
		DATADIR "/xsessions/",
		NULL
	};

	exec = NULL;
	ret = FALSE;
	if (command != NULL) {
		*command = NULL;
	}

	key_file = g_key_file_new ();

	error = NULL;
	full_path = NULL;
	res = g_key_file_load_from_dirs (key_file,
					 file,
					 search_dirs,
					 &full_path,
					 G_KEY_FILE_NONE,
					 &error);
	if (! res) {
		g_debug ("File '%s' not found: %s", file, error->message);
		g_error_free (error);
		if (command != NULL) {
			*command = NULL;
		}
		goto out;
	}

	error = NULL;
	res = g_key_file_get_boolean (key_file,
				      G_KEY_FILE_DESKTOP_GROUP,
				      G_KEY_FILE_DESKTOP_KEY_HIDDEN,
				      &error);
	if (error == NULL && res) {
		g_debug ("Session %s is marked as hidden", file);
		goto out;
	}

	error = NULL;
	exec = g_key_file_get_string (key_file,
				      G_KEY_FILE_DESKTOP_GROUP,
				      G_KEY_FILE_DESKTOP_KEY_TRY_EXEC,
				      &error);
	if (exec == NULL) {
		g_debug ("%s key not found", G_KEY_FILE_DESKTOP_KEY_TRY_EXEC);
		goto out;
	}

	res = is_prog_in_path (exec);
	g_free (exec);

	if (! res) {
		g_debug ("Command not found: %s", G_KEY_FILE_DESKTOP_KEY_TRY_EXEC);
		goto out;
	}

	error = NULL;
	exec = g_key_file_get_string (key_file,
				      G_KEY_FILE_DESKTOP_GROUP,
				      G_KEY_FILE_DESKTOP_KEY_EXEC,
				      &error);
	if (error != NULL) {
		g_debug ("%s key not found: %s",
			 G_KEY_FILE_DESKTOP_KEY_EXEC,
			 error->message);
		g_error_free (error);
		goto out;
	}

	if (command != NULL) {
		*command = g_strdup (exec);
	}
	ret = TRUE;

out:
	g_free (exec);

	return ret;
}

static void
setup_session_environment (GdmSlave *slave)
{

	gdm_session_set_environment_variable (slave->priv->session,
					      "GDMSESSION",
					      slave->priv->selected_session);
	gdm_session_set_environment_variable (slave->priv->session,
					      "DESKTOP_SESSION",
					      slave->priv->selected_session);

	gdm_session_set_environment_variable (slave->priv->session,
					      "LANG",
					      slave->priv->selected_language);
	gdm_session_set_environment_variable (slave->priv->session,
					      "GDM_LANG",
					      slave->priv->selected_language);

	gdm_session_set_environment_variable (slave->priv->session,
					      "DISPLAY",
					      slave->priv->display_name);
	gdm_session_set_environment_variable (slave->priv->session,
					      "XAUTHORITY",
					      slave->priv->display_x11_authority_file);

	gdm_session_set_environment_variable (slave->priv->session,
					      "PATH",
					      "/bin:/usr/bin:" BINDIR);
}

static void
on_user_verified (GdmSession *session,
		  GdmSlave   *slave)
{
	char    *username;
	int      argc;
	char   **argv;
	char    *command;
	char    *filename;
	GError  *error;
	gboolean res;

	gdm_greeter_proxy_stop (slave->priv->greeter);

	username = gdm_session_get_username (session);

	g_debug ("%s%ssuccessfully authenticated\n",
		 username ? username : "",
		 username ? " " : "");
	g_free (username);

	if (slave->priv->selected_session != NULL) {
		filename = g_strdup (slave->priv->selected_session);
	} else {
		filename = g_strdup ("gnome.desktop");
	}

	setup_session_environment (slave);

	res = get_session_command (filename, &command);
	if (! res) {
		g_warning ("Could find session file: %s", filename);
		return;
	}

	error = NULL;
	res = g_shell_parse_argv (command, &argc, &argv, &error);
	if (! res) {
		g_warning ("Could not parse command: %s", error->message);
		g_error_free (error);
	}

	gdm_session_start_program (session,
				   argc,
				   (const char **)argv);

	g_free (filename);
	g_free (command);
	g_strfreev (argv);
}

static void
on_user_verification_error (GdmSession *session,
                            GError     *error,
			    GdmSlave   *slave)
{
	char *username;

	username = gdm_session_get_username (session);

	g_debug ("%s%scould not be successfully authenticated: %s\n",
		 username ? username : "",
		 username ? " " : "",
		 error->message);

	g_free (username);
}

static void
on_info (GdmSession *session,
         const char *text,
	 GdmSlave   *slave)
{
	g_debug ("Info: %s", text);
	gdm_greeter_proxy_info (slave->priv->greeter, text);
}

static void
on_problem (GdmSession *session,
            const char *text,
	    GdmSlave   *slave)
{
	g_debug ("Problem: %s", text);
	gdm_greeter_proxy_problem (slave->priv->greeter, text);
}

static void
on_info_query (GdmSession *session,
               const char *text,
	       GdmSlave   *slave)
{

	g_debug ("Info query: %s", text);
	gdm_greeter_proxy_info_query (slave->priv->greeter, text);
}

static void
on_secret_info_query (GdmSession *session,
                      const char *text,
		      GdmSlave   *slave)
{
	g_debug ("Secret info query: %s", text);
	gdm_greeter_proxy_secret_info_query (slave->priv->greeter, text);
}

static void
on_greeter_answer (GdmGreeterProxy *greeter,
		   const char      *text,
		   GdmSlave        *slave)
{
	gdm_session_answer_query (slave->priv->session, text);
}

static void
on_greeter_session_selected (GdmGreeterProxy *greeter,
			     const char      *text,
			     GdmSlave        *slave)
{
	g_free (slave->priv->selected_session);
	slave->priv->selected_session = g_strdup (text);
}

static void
on_greeter_language_selected (GdmGreeterProxy *greeter,
			      const char      *text,
			      GdmSlave        *slave)
{
	g_free (slave->priv->selected_language);
	slave->priv->selected_language = g_strdup (text);
}

static void
on_greeter_start (GdmGreeterProxy *greeter,
		  GdmSlave        *slave)
{
	g_debug ("Greeter started");

	gdm_session_open (slave->priv->session,
			  "gdm",
			  NULL /* hostname */,
			  "/dev/console",
			  STDOUT_FILENO,
			  STDERR_FILENO,
			  NULL);

	/* If XDMCP stop pinging */
	if ( ! slave->priv->display_is_local) {
		alarm (0);
	}
}

static void
run_greeter (GdmSlave *slave)
{

	/* Set the busy cursor */
	set_busy_cursor (slave);

	/* FIXME: send a signal back to the master */

#if 0

	/* OK from now on it's really the user whacking us most likely,
	 * we have already started up well */
	do_xfailed_on_xio_error = FALSE;
#endif

	/* If XDMCP setup pinging */
	if ( ! slave->priv->display_is_local && slave->priv->ping_interval > 0) {
		alarm (slave->priv->ping_interval);
	}

#if 0
	/* checkout xinerama */
	gdm_screen_init (slave);
#endif

#ifdef HAVE_TSOL
	/* Check out Solaris Trusted Xserver extension */
	gdm_tsol_init (d);
#endif

	/* Run the init script. gdmslave suspends until script has terminated */
	gdm_slave_exec_script (slave,
			       GDMCONFDIR"/Init",
			       "gdm");

	slave->priv->session = gdm_session_new ();

	g_signal_connect (slave->priv->session,
			  "info",
			  G_CALLBACK (on_info),
			  slave);

	g_signal_connect (slave->priv->session,
			  "problem",
			  G_CALLBACK (on_problem),
			  slave);

	g_signal_connect (slave->priv->session,
			  "info-query",
			  G_CALLBACK (on_info_query),
			  slave);

	g_signal_connect (slave->priv->session,
			  "secret-info-query",
			  G_CALLBACK (on_secret_info_query),
			  slave);

	g_signal_connect (slave->priv->session,
			  "user-verified",
			  G_CALLBACK (on_user_verified),
			  slave);

	g_signal_connect (slave->priv->session,
			  "user-verification-error",
			  G_CALLBACK (on_user_verification_error),
			  slave);

	g_signal_connect (slave->priv->session,
			  "session-started",
			  G_CALLBACK (on_session_started),
			  slave);
	g_signal_connect (slave->priv->session,
			  "session-exited",
			  G_CALLBACK (on_session_exited),
			  slave);
	g_signal_connect (slave->priv->session,
			  "session-died",
			  G_CALLBACK (on_session_died),
			  slave);

	slave->priv->greeter = gdm_greeter_proxy_new (slave->priv->display_name);
	g_signal_connect (slave->priv->greeter,
			  "query-answer",
			  G_CALLBACK (on_greeter_answer),
			  slave);
	g_signal_connect (slave->priv->greeter,
			  "session-selected",
			  G_CALLBACK (on_greeter_session_selected),
			  slave);
	g_signal_connect (slave->priv->greeter,
			  "language-selected",
			  G_CALLBACK (on_greeter_language_selected),
			  slave);
	g_signal_connect (slave->priv->greeter,
			  "started",
			  G_CALLBACK (on_greeter_start),
			  slave);
	g_object_set (slave->priv->greeter,
		      "x11-authority-file", slave->priv->display_x11_authority_file,
		      NULL);
	gdm_greeter_proxy_start (slave->priv->greeter);
}

static void
set_local_auth (GdmSlave *slave)
{
	GString *binary_cookie;
	GString *cookie;

	g_debug ("Setting authorization key for display %s", slave->priv->display_x11_cookie);

	cookie = g_string_new (slave->priv->display_x11_cookie);
	binary_cookie = g_string_new (NULL);
	if (! gdm_string_hex_decode (cookie,
				     0,
				     NULL,
				     binary_cookie,
				     0)) {
		g_warning ("Unable to decode hex cookie");
		goto out;
	}

	g_debug ("Decoded cookie len %d", binary_cookie->len);

	XSetAuthorization ("MIT-MAGIC-COOKIE-1",
			   (int) strlen ("MIT-MAGIC-COOKIE-1"),
			   (char *)binary_cookie->str,
			   binary_cookie->len);

 out:
	g_string_free (binary_cookie, TRUE);
	g_string_free (cookie, TRUE);
}

static gboolean
connect_to_display (GdmSlave *slave)
{
	/* We keep our own (windowless) connection (dsp) open to avoid the
	 * X server resetting due to lack of active connections. */

	g_debug ("Server is ready - opening display %s", slave->priv->display_name);

	g_setenv ("DISPLAY", slave->priv->display_name, TRUE);
	g_unsetenv ("XAUTHORITY"); /* just in case it's set */



	set_local_auth (slave);

#if 0
	/* X error handlers to avoid the default one (i.e. exit (1)) */
	do_xfailed_on_xio_error = TRUE;
	XSetErrorHandler (gdm_slave_xerror_handler);
	XSetIOErrorHandler (gdm_slave_xioerror_handler);
#endif

	gdm_sigchld_block_push ();
	slave->priv->server_display = XOpenDisplay (slave->priv->display_name);
	gdm_sigchld_block_pop ();

	if (slave->priv->server_display == NULL) {
		g_warning ("Unable to connect to display %s", slave->priv->display_name);
		return FALSE;
	} else {
		g_debug ("Connected to display %s", slave->priv->display_name);
	}

	return TRUE;
}

static gboolean
idle_connect_to_display (GdmSlave *slave)
{
	gboolean res;

	slave->priv->connection_attempts++;

	res = connect_to_display (slave);
	if (res) {
		/* FIXME: handle wait-for-go */

		run_greeter (slave);
	} else {
		if (slave->priv->connection_attempts >= MAX_CONNECT_ATTEMPTS) {
			g_warning ("Unable to connect to display after %d tries - bailing out", slave->priv->connection_attempts);
			exit (1);
		}
	}

	return FALSE;
}

static void
server_ready_cb (GdmServer *server,
		 GdmSlave  *slave)
{
	g_timeout_add (500, (GSourceFunc)idle_connect_to_display, slave);
}

static gboolean
gdm_slave_run (GdmSlave *slave)
{
	/* if this is local display start a server if one doesn't
	 * exist */
	if (slave->priv->display_is_local) {
		gboolean res;

		slave->priv->server = gdm_server_new (slave->priv->display_name);

		g_signal_connect (slave->priv->server,
				  "ready",
				  G_CALLBACK (server_ready_cb),
				  slave);

		res = gdm_server_start (slave->priv->server);
		if (! res) {
			g_warning (_("Could not start the X "
				     "server (your graphical environment) "
				     "due to some internal error. "
				     "Please contact your system administrator "
				     "or check your syslog to diagnose. "
				     "In the meantime this display will be "
				     "disabled.  Please restart GDM when "
				     "the problem is corrected."));
			exit (1);
		}

		g_debug ("Started X server");
	} else {
		g_timeout_add (500, (GSourceFunc)idle_connect_to_display, slave);
	}

	return TRUE;
}

gboolean
gdm_slave_start (GdmSlave *slave)
{
	gboolean res;
	char    *id;
	GError  *error;

	g_debug ("Starting slave");

	g_assert (slave->priv->display_proxy == NULL);

	g_debug ("Creating proxy for %s", slave->priv->display_id);
	slave->priv->display_proxy = dbus_g_proxy_new_for_name (slave->priv->connection,
								GDM_DBUS_NAME,
								slave->priv->display_id,
								GDM_DBUS_DISPLAY_INTERFACE);
	if (slave->priv->display_proxy == NULL) {
		g_warning ("Unable to create display proxy");
		return FALSE;
	}

	/* Make sure display ID works */
	error = NULL;
	res = dbus_g_proxy_call (slave->priv->display_proxy,
				 "GetId",
				 &error,
				 G_TYPE_INVALID,
				 DBUS_TYPE_G_OBJECT_PATH, &id,
				 G_TYPE_INVALID);
	if (! res) {
		if (error != NULL) {
			g_warning ("Failed to get display id %s: %s", slave->priv->display_id, error->message);
			g_error_free (error);
		} else {
			g_warning ("Failed to get display id %s", slave->priv->display_id);
		}

		return FALSE;
	}

	g_debug ("Got display id: %s", id);

	if (strcmp (id, slave->priv->display_id) != 0) {
		g_critical ("Display ID doesn't match");
		exit (1);
	}

	/* cache some values up front */
	error = NULL;
	res = dbus_g_proxy_call (slave->priv->display_proxy,
				 "IsLocal",
				 &error,
				 G_TYPE_INVALID,
				 G_TYPE_BOOLEAN, &slave->priv->display_is_local,
				 G_TYPE_INVALID);
	if (! res) {
		if (error != NULL) {
			g_warning ("Failed to get value: %s", error->message);
			g_error_free (error);
		} else {
			g_warning ("Failed to get value");
		}

		return FALSE;
	}

	error = NULL;
	res = dbus_g_proxy_call (slave->priv->display_proxy,
				 "GetX11Display",
				 &error,
				 G_TYPE_INVALID,
				 G_TYPE_STRING, &slave->priv->display_name,
				 G_TYPE_INVALID);
	if (! res) {
		if (error != NULL) {
			g_warning ("Failed to get value: %s", error->message);
			g_error_free (error);
		} else {
			g_warning ("Failed to get value");
		}

		return FALSE;
	}

	error = NULL;
	res = dbus_g_proxy_call (slave->priv->display_proxy,
				 "GetX11Cookie",
				 &error,
				 G_TYPE_INVALID,
				 G_TYPE_STRING, &slave->priv->display_x11_cookie,
				 G_TYPE_INVALID);
	if (! res) {
		if (error != NULL) {
			g_warning ("Failed to get value: %s", error->message);
			g_error_free (error);
		} else {
			g_warning ("Failed to get value");
		}

		return FALSE;
	}

	error = NULL;
	res = dbus_g_proxy_call (slave->priv->display_proxy,
				 "GetX11AuthorityFile",
				 &error,
				 G_TYPE_INVALID,
				 G_TYPE_STRING, &slave->priv->display_x11_authority_file,
				 G_TYPE_INVALID);
	if (! res) {
		if (error != NULL) {
			g_warning ("Failed to get value: %s", error->message);
			g_error_free (error);
		} else {
			g_warning ("Failed to get value");
		}

		return FALSE;
	}

	gdm_slave_run (slave);

	return TRUE;
}

static gboolean
gdm_slave_stop (GdmSlave *slave)
{
	g_debug ("Stopping slave");

	if (slave->priv->greeter != NULL) {
		gdm_greeter_proxy_stop (slave->priv->greeter);
		g_object_unref (slave->priv->greeter);
		slave->priv->greeter = NULL;
	}

	if (slave->priv->session != NULL) {
		gdm_session_close (slave->priv->session);
		g_object_unref (slave->priv->session);
		slave->priv->session = NULL;
	}

	if (slave->priv->server != NULL) {
		gdm_server_stop (slave->priv->server);
		g_object_unref (slave->priv->server);
		slave->priv->server = NULL;
	}

	if (slave->priv->display_proxy != NULL) {
		g_object_unref (slave->priv->display_proxy);
	}

	return TRUE;
}

static void
_gdm_slave_set_display_id (GdmSlave   *slave,
			   const char *id)
{
        g_free (slave->priv->display_id);
        slave->priv->display_id = g_strdup (id);
}

static void
gdm_slave_set_property (GObject      *object,
			guint	      prop_id,
			const GValue *value,
			GParamSpec   *pspec)
{
	GdmSlave *self;

	self = GDM_SLAVE (object);

	switch (prop_id) {
	case PROP_DISPLAY_ID:
		_gdm_slave_set_display_id (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gdm_slave_get_property (GObject    *object,
			guint       prop_id,
			GValue	   *value,
			GParamSpec *pspec)
{
	GdmSlave *self;

	self = GDM_SLAVE (object);

	switch (prop_id) {
	case PROP_DISPLAY_ID:
		g_value_set_string (value, self->priv->display_id);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
register_slave (GdmSlave *slave)
{
        GError *error = NULL;

        error = NULL;
        slave->priv->connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (slave->priv->connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                exit (1);
        }

        dbus_g_connection_register_g_object (slave->priv->connection, slave->priv->id, G_OBJECT (slave));

        return TRUE;
}


static GObject *
gdm_slave_constructor (GType                  type,
		       guint                  n_construct_properties,
		       GObjectConstructParam *construct_properties)
{
        GdmSlave      *slave;
        GdmSlaveClass *klass;
	gboolean       res;
	const char    *id;

        klass = GDM_SLAVE_CLASS (g_type_class_peek (GDM_TYPE_SLAVE));

        slave = GDM_SLAVE (G_OBJECT_CLASS (gdm_slave_parent_class)->constructor (type,
										 n_construct_properties,
										 construct_properties));

	id = NULL;
	if (g_str_has_prefix (slave->priv->display_id, "/org/gnome/DisplayManager/Display")) {
		id = slave->priv->display_id + strlen ("/org/gnome/DisplayManager/Display");
	}

	slave->priv->id = g_strdup_printf ("/org/gnome/DisplayManager/Slave%s", id);
	g_debug ("Registering %s", slave->priv->id);

        res = register_slave (slave);
        if (! res) {
		g_warning ("Unable to register slave with system bus");
        }

        return G_OBJECT (slave);
}

static void
gdm_slave_class_init (GdmSlaveClass *klass)
{
	GObjectClass    *object_class = G_OBJECT_CLASS (klass);

	object_class->get_property = gdm_slave_get_property;
	object_class->set_property = gdm_slave_set_property;
        object_class->constructor = gdm_slave_constructor;
	object_class->finalize = gdm_slave_finalize;

	g_type_class_add_private (klass, sizeof (GdmSlavePrivate));

	g_object_class_install_property (object_class,
					 PROP_DISPLAY_ID,
					 g_param_spec_string ("display-id",
							      "id",
							      "id",
							      NULL,
							      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	signals [SESSION_STARTED] =
		g_signal_new ("session-started",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GdmSlaveClass, session_started),
			      NULL,
			      NULL,
			      g_cclosure_marshal_VOID__INT,
			      G_TYPE_NONE,
			      1,
			      G_TYPE_INT);

	signals [SESSION_EXITED] =
		g_signal_new ("session-exited",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GdmSlaveClass, session_exited),
			      NULL,
			      NULL,
			      g_cclosure_marshal_VOID__INT,
			      G_TYPE_NONE,
			      1,
			      G_TYPE_INT);

	signals [SESSION_DIED] =
		g_signal_new ("session-died",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (GdmSlaveClass, session_exited),
			      NULL,
			      NULL,
			      g_cclosure_marshal_VOID__INT,
			      G_TYPE_NONE,
			      1,
			      G_TYPE_INT);

	dbus_g_object_type_install_info (GDM_TYPE_SLAVE, &dbus_glib_gdm_slave_object_info);
}

static void
gdm_slave_init (GdmSlave *slave)
{

	slave->priv = GDM_SLAVE_GET_PRIVATE (slave);

	slave->priv->pid = -1;
}

static void
gdm_slave_finalize (GObject *object)
{
	GdmSlave *slave;

	g_return_if_fail (object != NULL);
	g_return_if_fail (GDM_IS_SLAVE (object));

	slave = GDM_SLAVE (object);

	g_return_if_fail (slave->priv != NULL);

	gdm_slave_stop (slave);

	G_OBJECT_CLASS (gdm_slave_parent_class)->finalize (object);
}

GdmSlave *
gdm_slave_new (const char *id)
{
	GObject *object;

	object = g_object_new (GDM_TYPE_SLAVE,
			       "display-id", id,
			       NULL);

	return GDM_SLAVE (object);
}