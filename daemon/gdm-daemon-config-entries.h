/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 William Jon McCann <mccann@jhu.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _GDM_DAEMON_CONFIG_ENTRIES_H
#define _GDM_DAEMON_CONFIG_ENTRIES_H

#include <glib.h>

#include "gdm-config.h"

G_BEGIN_DECLS

#define GDM_CONFIG_GROUP_NONE       NULL
#define GDM_CONFIG_GROUP_DAEMON     "daemon"
#define GDM_CONFIG_GROUP_SECURITY   "security"
#define GDM_CONFIG_GROUP_XDMCP      "xdmcp"
#define GDM_CONFIG_GROUP_GREETER    "greeter"
#define GDM_CONFIG_GROUP_GUI        "gui"
#define GDM_CONFIG_GROUP_CUSTOM_CMD "customcommand"
#define GDM_CONFIG_GROUP_CHOOSER    "chooser"
#define GDM_CONFIG_GROUP_SERVERS    "servers"
#define GDM_CONFIG_GROUP_DEBUG      "debug"

#define GDM_CONFIG_GROUP_SERVER_PREFIX "server-"

#include "gdm-daemon-config-keys.h"

typedef enum {
	GDM_ID_NONE,
	GDM_ID_DEBUG,
	GDM_ID_DEBUG_GESTURES,
	GDM_ID_CHOOSER,
	GDM_ID_AUTOMATIC_LOGIN_ENABLE,
	GDM_ID_AUTOMATIC_LOGIN,
	GDM_ID_ALWAYS_RESTART_SERVER,
	GDM_ID_GREETER,
	GDM_ID_REMOTE_GREETER,
	GDM_ID_ADD_GTK_MODULES,
	GDM_ID_GTK_MODULES_LIST,
	GDM_ID_GROUP,
	GDM_ID_HALT,
	GDM_ID_DISPLAY_INIT_DIR,
	GDM_ID_KILL_INIT_CLIENTS,
	GDM_ID_LOG_DIR,
	GDM_ID_PATH,
	GDM_ID_PID_FILE,
	GDM_ID_POSTSESSION,
	GDM_ID_PRESESSION,
	GDM_ID_POSTLOGIN,
	GDM_ID_FAILSAFE_XSERVER,
	GDM_ID_X_KEEPS_CRASHING,
	GDM_ID_REBOOT ,
	GDM_ID_CUSTOM_CMD_TEMPLATE,
	GDM_ID_CUSTOM_CMD_LABEL_TEMPLATE,
	GDM_ID_CUSTOM_CMD_LR_LABEL_TEMPLATE,
	GDM_ID_CUSTOM_CMD_TEXT_TEMPLATE,
	GDM_ID_CUSTOM_CMD_TOOLTIP_TEMPLATE,
	GDM_ID_CUSTOM_CMD_NO_RESTART_TEMPLATE,
	GDM_ID_CUSTOM_CMD_IS_PERSISTENT_TEMPLATE,
	GDM_ID_ROOT_PATH,
	GDM_ID_SERV_AUTHDIR,
	GDM_ID_SESSION_DESKTOP_DIR,
	GDM_ID_BASE_XSESSION,
	GDM_ID_DEFAULT_SESSION,
	GDM_ID_SUSPEND,
	GDM_ID_USER_AUTHDIR,
	GDM_ID_USER_AUTHDIR_FALLBACK,
	GDM_ID_USER_AUTHFILE,
	GDM_ID_USER,
	GDM_ID_CONSOLE_NOTIFY,
	GDM_ID_DOUBLE_LOGIN_WARNING,
	GDM_ID_ALWAYS_LOGIN_CURRENT_SESSION,
	GDM_ID_DISPLAY_LAST_LOGIN,
	GDM_ID_TIMED_LOGIN_ENABLE,
	GDM_ID_TIMED_LOGIN,
	GDM_ID_TIMED_LOGIN_DELAY,
	GDM_ID_FLEXI_REAP_DELAY_MINUTES,
	GDM_ID_STANDARD_XSERVER,
	GDM_ID_FLEXIBLE_XSERVERS,
	GDM_ID_DYNAMIC_XSERVERS,
	GDM_ID_XNEST,
	GDM_ID_XNEST_UNSCALED_FONT_PATH,
	GDM_ID_FIRST_VT,
	GDM_ID_VT_ALLOCATION,
	GDM_ID_CONSOLE_CANNOT_HANDLE,
	GDM_ID_XSERVER_TIMEOUT,
	GDM_ID_SERVER_PREFIX,
	GDM_ID_SERVER_NAME,
	GDM_ID_SERVER_COMMAND,
	GDM_ID_SERVER_FLEXIBLE,
	GDM_ID_SERVER_CHOOSABLE,
	GDM_ID_SERVER_HANDLED,
	GDM_ID_SERVER_CHOOSER,
	GDM_ID_SERVER_PRIORITY,
	GDM_ID_ALLOW_ROOT,
	GDM_ID_ALLOW_REMOTE_ROOT,
	GDM_ID_ALLOW_REMOTE_AUTOLOGIN,
	GDM_ID_USER_MAX_FILE,
	GDM_ID_RELAX_PERM,
	GDM_ID_CHECK_DIR_OWNER,
	GDM_ID_SUPPORT_AUTOMOUNT,
	GDM_ID_RETRY_DELAY,
	GDM_ID_DISALLOW_TCP,
	GDM_ID_PAM_STACK,
	GDM_ID_NEVER_PLACE_COOKIES_ON_NFS,
	GDM_ID_PASSWORD_REQUIRED,
	GDM_ID_XDMCP,
	GDM_ID_MAX_PENDING,
	GDM_ID_MAX_SESSIONS,
	GDM_ID_MAX_WAIT,
	GDM_ID_DISPLAYS_PER_HOST,
	GDM_ID_UDP_PORT,
	GDM_ID_INDIRECT,
	GDM_ID_MAX_INDIRECT,
	GDM_ID_MAX_WAIT_INDIRECT,
	GDM_ID_PING_INTERVAL,
	GDM_ID_WILLING,
	GDM_ID_XDMCP_PROXY,
	GDM_ID_XDMCP_PROXY_XSERVER,
	GDM_ID_XDMCP_PROXY_RECONNECT,
	GDM_ID_GTK_THEME,
	GDM_ID_GTKRC,
	GDM_ID_MAX_ICON_WIDTH,
	GDM_ID_MAX_ICON_HEIGHT,
	GDM_ID_ALLOW_GTK_THEME_CHANGE,
	GDM_ID_GTK_THEMES_TO_ALLOW,
	GDM_ID_BROWSER,
	GDM_ID_INCLUDE,
	GDM_ID_EXCLUDE,
	GDM_ID_INCLUDE_ALL,
	GDM_ID_MINIMAL_UID,
	GDM_ID_DEFAULT_FACE,
	GDM_ID_GLOBAL_FACE_DIR,
	GDM_ID_LOCALE_FILE,
	GDM_ID_LOGO,
	GDM_ID_CHOOSER_BUTTON_LOGO,
	GDM_ID_QUIVER,
	GDM_ID_SYSTEM_MENU,
	GDM_ID_CONFIGURATOR,
	GDM_ID_CONFIG_AVAILABLE,
	GDM_ID_CHOOSER_BUTTON,
	GDM_ID_TITLE_BAR,
	GDM_ID_DEFAULT_WELCOME,
	GDM_ID_DEFAULT_REMOTE_WELCOME,
	GDM_ID_WELCOME,
	GDM_ID_REMOTE_WELCOME,
	GDM_ID_XINERAMA_SCREEN,
	GDM_ID_BACKGROUND_PROGRAM,
	GDM_ID_RUN_BACKGROUND_PROGRAM_ALWAYS,
	GDM_ID_BACKGROUND_PROGRAM_INITIAL_DELAY,
	GDM_ID_RESTART_BACKGROUND_PROGRAM,
	GDM_ID_BACKGROUND_PROGRAM_RESTART_DELAY,
	GDM_ID_BACKGROUND_IMAGE,
	GDM_ID_BACKGROUND_COLOR,
	GDM_ID_BACKGROUND_TYPE,
	GDM_ID_BACKGROUND_SCALE_TO_FIT,
	GDM_ID_BACKGROUND_REMOTE_ONLY_COLOR,
	GDM_ID_LOCK_POSITION,
	GDM_ID_SET_POSITION,
	GDM_ID_POSITION_X,
	GDM_ID_POSITION_Y,
	GDM_ID_USE_24_CLOCK,
	GDM_ID_ENTRY_CIRCLES,
	GDM_ID_ENTRY_INVISIBLE,
	GDM_ID_GRAPHICAL_THEME,
	GDM_ID_GRAPHICAL_THEMES,
	GDM_ID_GRAPHICAL_THEME_RAND,
	GDM_ID_GRAPHICAL_THEME_DIR,
	GDM_ID_GRAPHICAL_THEMED_COLOR,
	GDM_ID_INFO_MSG_FILE,
	GDM_ID_INFO_MSG_FONT,
	GDM_ID_PRE_FETCH_PROGRAM,
	GDM_ID_SOUND_ON_LOGIN,
	GDM_ID_SOUND_ON_LOGIN_SUCCESS,
	GDM_ID_SOUND_ON_LOGIN_FAILURE,
	GDM_ID_SOUND_ON_LOGIN_FILE,
	GDM_ID_SOUND_ON_LOGIN_SUCCESS_FILE,
	GDM_ID_SOUND_ON_LOGIN_FAILURE_FILE,
	GDM_ID_SOUND_PROGRAM,
	GDM_ID_SCAN_TIME,
	GDM_ID_DEFAULT_HOST_IMG,
	GDM_ID_HOST_IMAGE_DIR,
	GDM_ID_HOSTS,
	GDM_ID_MULTICAST,
	GDM_ID_MULTICAST_ADDR,
	GDM_ID_BROADCAST,
	GDM_ID_ALLOW_ADD,
	GDM_ID_SECTION_GREETER,
	GDM_ID_SECTION_SERVERS,
	GDM_ID_SHOW_GNOME_FAILSAFE,
	GDM_ID_SHOW_XTERM_FAILSAFE,
	GDM_ID_SHOW_LAST_SESSION,
	GDK_KEY_LAST
} GdmConfigKey;


/*
 * The following section contains keys used by the GDM configuration files.
 * The key/value pairs defined in the GDM configuration files are considered
 * "stable" interface and should only change in ways that are backwards
 * compatible.  Please keep this in mind when changing GDM configuration.
 *
 * Developers who add new configuration options should ensure that they do the
 * following:
 *
 * + Edit the config/gdm.conf file to include the default setting.
 *
 * + Specify the same default in this file as in the config/gdm.conf.in file.
 *
 * + Update the gdm_daemon_config_entries[] to add the
 *   new key.  Include some documentation about the new key, following the
 *   style of existing comments.
 *
 * + Add any validation to the validate_cb function in
 *   gdm-daemon-config.c, if validation is needed.
 *
 * + If GDM_UPDATE_CONFIG should not respond to this configuration setting,
 *   update the update_config function in gdmconfig.c to return FALSE for
 *   this key.  Examples include changing the PidFile, ServAuthDir, or
 *   other values that GDM should not change until it is restarted.  If
 *   this is true, the next bullet can be ignored.
 *
 * + If the option should cause the greeter (gdmlogin/gdmgreeter) program to
 *   be updated immediately, make sure to update the appropriate
 *   _gdm_set_value_* function in gdmconfig.c.  This function calls the
 *   notify_displays_* function to call when this value is changed, so you
 *   will need to add your new config value to the list of values sending
 *   such notification.  Supporting logic will need to be added to
 *   gdm_slave_handle_notify function in slave.c to process the notify.
 *   It should be clear to see how to do this from the existing code.
 *
 * + Add the key to the gdm_read_config and gdm_reread_config functions in
 *   gui/gdmlogin.c, gui/gdmchooser.c, and gui/greeter/greeter.c
 *   if the key is used by those programs.  Note that all GDM slaves load
 *   all their configuration data between calls to gdmcomm_comm_bulk_start()
 *   and gdmcomm_comm_bulk_stop().  This makes sure that the slave only uses
 *   a single sockets connection to get all configuration data.  If a new
 *   config value is read by a slave, make sure to load the key in this
 *   code section for best performance.
 *
 * + The gui/gdmsetup.c program should be updated to support the new option
 *   unless there's a good reason not to (like it is a configuration value
 *   that only someone who really knows what they are doing should change
 *   like GDM_ID_PID_FILE).
 *
 * + Currently GDM treats any key in the "gui" and "greeter" categories,
 *   and security/PamStack as available for per-display configuration.
 *   If a key is appropriate for per-display configuration, and is not
 *   in the "gui" or "greeter" categories, then it will need to be added
 *   to the gdm_config_key_to_string_per_display function.  It may make
 *   sense for some keys used by the daemon to be per-display so this
 *   will need to be coded (refer to GDM_ID_PAM_STACK for an example).
 *
 * + Update the docs/C/gdm.xml file to include information about the new
 *   option.  Include information about any other interfaces (such as
 *   ENVIRONMENT variables) that may affect the configuration option.
 *   Patches without documentation will not be accepted.
 *
 * Please do this work *before* submitting an patch.  Patches that are not
 * complete will not likely be accepted.
 */

#define GDM_DEFAULT_WELCOME_MSG "Welcome"
#define GDM_DEFAULT_REMOTE_WELCOME_MSG "Welcome to %n"

/* These are processed in order so debug should always be first */
static const GdmConfigEntry gdm_daemon_config_entries [] = {
	{ GDM_CONFIG_GROUP_DEBUG, "Enable", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_DEBUG },
	{ GDM_CONFIG_GROUP_DEBUG, "Gestures", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_DEBUG_GESTURES },


	{ GDM_CONFIG_GROUP_DAEMON, "Chooser", GDM_CONFIG_VALUE_STRING, LIBEXECDIR "/gdmchooser", GDM_ID_CHOOSER },
	{ GDM_CONFIG_GROUP_DAEMON, "AutomaticLoginEnable", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_AUTOMATIC_LOGIN_ENABLE },
	{ GDM_CONFIG_GROUP_DAEMON, "AutomaticLogin", GDM_CONFIG_VALUE_STRING, "", GDM_ID_AUTOMATIC_LOGIN },

	/* The SDTLOGIN feature is Solaris specific, and causes the Xserver to be
	 * run with user permissionsinstead of as root, which adds security but,
	 * disables the AlwaysRestartServer option as highlighted in the gdm
	 * documentation */

	{ GDM_CONFIG_GROUP_DAEMON, "AlwaysRestartServer", GDM_CONFIG_VALUE_BOOL, ALWAYS_RESTART_SERVER, GDM_ID_ALWAYS_RESTART_SERVER },
	{ GDM_CONFIG_GROUP_DAEMON, "Greeter", GDM_CONFIG_VALUE_STRING, LIBEXECDIR "/gdmlogin", GDM_ID_GREETER },
	{ GDM_CONFIG_GROUP_DAEMON, "RemoteGreeter", GDM_CONFIG_VALUE_STRING, LIBEXECDIR "/gdmlogin", GDM_ID_REMOTE_GREETER },
	{ GDM_CONFIG_GROUP_DAEMON, "AddGtkModules", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_ADD_GTK_MODULES },
	{ GDM_CONFIG_GROUP_DAEMON, "GtkModulesList", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_GTK_MODULES_LIST },

	{ GDM_CONFIG_GROUP_DAEMON, "User", GDM_CONFIG_VALUE_STRING, "gdm", GDM_ID_USER },
	{ GDM_CONFIG_GROUP_DAEMON, "Group", GDM_CONFIG_VALUE_STRING, "gdm", GDM_ID_GROUP },

	{ GDM_CONFIG_GROUP_DAEMON, "HaltCommand", GDM_CONFIG_VALUE_STRING_ARRAY, HALT_COMMAND, GDM_ID_HALT },
	{ GDM_CONFIG_GROUP_DAEMON, "RebootCommand", GDM_CONFIG_VALUE_STRING_ARRAY, REBOOT_COMMAND, GDM_ID_REBOOT },
	{ GDM_CONFIG_GROUP_DAEMON, "SuspendCommand", GDM_CONFIG_VALUE_STRING_ARRAY, SUSPEND_COMMAND, GDM_ID_SUSPEND },

	{ GDM_CONFIG_GROUP_DAEMON, "DisplayInitDir", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/Init", GDM_ID_DISPLAY_INIT_DIR },
	{ GDM_CONFIG_GROUP_DAEMON, "KillInitClients", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_KILL_INIT_CLIENTS },
	{ GDM_CONFIG_GROUP_DAEMON, "LogDir", GDM_CONFIG_VALUE_STRING, LOGDIR, GDM_ID_LOG_DIR },
	{ GDM_CONFIG_GROUP_DAEMON, "DefaultPath", GDM_CONFIG_VALUE_STRING, GDM_USER_PATH, GDM_ID_PATH },
	{ GDM_CONFIG_GROUP_DAEMON, "PidFile", GDM_CONFIG_VALUE_STRING, "/var/run/gdm.pid", GDM_ID_PID_FILE },
	{ GDM_CONFIG_GROUP_DAEMON, "PostSessionScriptDir", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/PostSession/", GDM_ID_POSTSESSION },
	{ GDM_CONFIG_GROUP_DAEMON, "PreSessionScriptDir", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/PreSession/", GDM_ID_PRESESSION },
	{ GDM_CONFIG_GROUP_DAEMON, "PostLoginScriptDir", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/PreSession/", GDM_ID_POSTLOGIN },
	{ GDM_CONFIG_GROUP_DAEMON, "FailsafeXServer", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_FAILSAFE_XSERVER },
	{ GDM_CONFIG_GROUP_DAEMON, "XKeepsCrashing", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/XKeepsCrashing", GDM_ID_X_KEEPS_CRASHING },
	{ GDM_CONFIG_GROUP_DAEMON, "RootPath", GDM_CONFIG_VALUE_STRING, "/sbin:/usr/sbin:" GDM_USER_PATH, GDM_ID_ROOT_PATH },
	{ GDM_CONFIG_GROUP_DAEMON, "ServAuthDir", GDM_CONFIG_VALUE_STRING, AUTHDIR, GDM_ID_SERV_AUTHDIR },
	{ GDM_CONFIG_GROUP_DAEMON, "SessionDesktopDir", GDM_CONFIG_VALUE_STRING, "/etc/X11/sessions/:" DMCONFDIR "/Sessions/:" DATADIR "/gdm/BuiltInSessions/:" DATADIR "/xsessions/", GDM_ID_SESSION_DESKTOP_DIR },
	{ GDM_CONFIG_GROUP_DAEMON, "BaseXsession", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/Xsession", GDM_ID_BASE_XSESSION },
	{ GDM_CONFIG_GROUP_DAEMON, "DefaultSession", GDM_CONFIG_VALUE_STRING, "gnome.desktop", GDM_ID_DEFAULT_SESSION },

	{ GDM_CONFIG_GROUP_DAEMON, "UserAuthDir", GDM_CONFIG_VALUE_STRING, "", GDM_ID_USER_AUTHDIR },
	{ GDM_CONFIG_GROUP_DAEMON, "UserAuthFBDir", GDM_CONFIG_VALUE_STRING, "/tmp", GDM_ID_USER_AUTHDIR_FALLBACK },
	{ GDM_CONFIG_GROUP_DAEMON, "UserAuthFile", GDM_CONFIG_VALUE_STRING, ".Xauthority", GDM_ID_USER_AUTHFILE },
	{ GDM_CONFIG_GROUP_DAEMON, "ConsoleNotify", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_CONSOLE_NOTIFY },

	{ GDM_CONFIG_GROUP_DAEMON, "DoubleLoginWarning", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_DOUBLE_LOGIN_WARNING },
	{ GDM_CONFIG_GROUP_DAEMON, "AlwaysLoginCurrentSession", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_ALWAYS_LOGIN_CURRENT_SESSION },

	{ GDM_CONFIG_GROUP_DAEMON, "DisplayLastLogin", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_DISPLAY_LAST_LOGIN },

	{ GDM_CONFIG_GROUP_DAEMON, "TimedLoginEnable", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_TIMED_LOGIN_ENABLE },
	{ GDM_CONFIG_GROUP_DAEMON, "TimedLogin", GDM_CONFIG_VALUE_STRING, "", GDM_ID_TIMED_LOGIN },
	{ GDM_CONFIG_GROUP_DAEMON, "TimedLoginDelay", GDM_CONFIG_VALUE_INT, "30", GDM_ID_TIMED_LOGIN_DELAY },

	{ GDM_CONFIG_GROUP_DAEMON, "FlexiReapDelayMinutes", GDM_CONFIG_VALUE_INT, "5", GDM_ID_FLEXI_REAP_DELAY_MINUTES },

	{ GDM_CONFIG_GROUP_DAEMON, "StandardXServer", GDM_CONFIG_VALUE_STRING, X_SERVER, GDM_ID_STANDARD_XSERVER },
	{ GDM_CONFIG_GROUP_DAEMON, "FlexibleXServers", GDM_CONFIG_VALUE_INT, "5", GDM_ID_FLEXIBLE_XSERVERS },
	{ GDM_CONFIG_GROUP_DAEMON, "DynamicXServers", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_DYNAMIC_XSERVERS },
	{ GDM_CONFIG_GROUP_DAEMON, "Xnest", GDM_CONFIG_VALUE_STRING, X_XNEST_CMD ", " X_XNEST_CONFIG_OPTIONS, GDM_ID_XNEST },
	{ GDM_CONFIG_GROUP_DAEMON, "XnestUnscaledFontPath", GDM_CONFIG_VALUE_BOOL, X_XNEST_UNSCALED_FONTPATH, GDM_ID_XNEST_UNSCALED_FONT_PATH },

	/* Keys for automatic VT allocation rather then letting it up to the X server */
	{ GDM_CONFIG_GROUP_DAEMON, "FirstVT", GDM_CONFIG_VALUE_INT, "7", GDM_ID_FIRST_VT },
	{ GDM_CONFIG_GROUP_DAEMON, "VTAllocation", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_VT_ALLOCATION },

	{ GDM_CONFIG_GROUP_DAEMON, "ConsoleCannotHandle", GDM_CONFIG_VALUE_STRING, "am,ar,az,bn,el,fa,gu,hi,ja,ko,ml,mr,pa,ta,zh", GDM_ID_CONSOLE_CANNOT_HANDLE },

	/* How long to wait before assuming an Xserver has timed out */
	{ GDM_CONFIG_GROUP_DAEMON, "GdmXserverTimeout", GDM_CONFIG_VALUE_INT, "10", GDM_ID_XSERVER_TIMEOUT },

	{ GDM_CONFIG_GROUP_SECURITY, "AllowRoot", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_ALLOW_ROOT },
	{ GDM_CONFIG_GROUP_SECURITY, "AllowRemoteRoot", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_ALLOW_REMOTE_ROOT },
	{ GDM_CONFIG_GROUP_SECURITY, "AllowRemoteAutoLogin", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_ALLOW_REMOTE_AUTOLOGIN },
	{ GDM_CONFIG_GROUP_SECURITY, "UserMaxFile", GDM_CONFIG_VALUE_INT, "65536", GDM_ID_USER_MAX_FILE },
	{ GDM_CONFIG_GROUP_SECURITY, "RelaxPermissions", GDM_CONFIG_VALUE_INT, "0", GDM_ID_RELAX_PERM },
	{ GDM_CONFIG_GROUP_SECURITY, "CheckDirOwner", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_CHECK_DIR_OWNER },
	{ GDM_CONFIG_GROUP_SECURITY, "SupportAutomount", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SUPPORT_AUTOMOUNT },
	{ GDM_CONFIG_GROUP_SECURITY, "RetryDelay", GDM_CONFIG_VALUE_INT, "1", GDM_ID_RETRY_DELAY },
	{ GDM_CONFIG_GROUP_SECURITY, "DisallowTCP", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_DISALLOW_TCP },
	{ GDM_CONFIG_GROUP_SECURITY, "PamStack", GDM_CONFIG_VALUE_STRING, "gdm", GDM_ID_PAM_STACK },

	{ GDM_CONFIG_GROUP_SECURITY, "NeverPlaceCookiesOnNFS", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_NEVER_PLACE_COOKIES_ON_NFS },
	{ GDM_CONFIG_GROUP_SECURITY, "PasswordRequired", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_PASSWORD_REQUIRED },

	{ GDM_CONFIG_GROUP_XDMCP, "Enable", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_XDMCP },
	{ GDM_CONFIG_GROUP_XDMCP, "MaxPending", GDM_CONFIG_VALUE_INT, "4", GDM_ID_MAX_PENDING },
	{ GDM_CONFIG_GROUP_XDMCP, "MaxSessions", GDM_CONFIG_VALUE_INT, "16", GDM_ID_MAX_SESSIONS },
	{ GDM_CONFIG_GROUP_XDMCP, "MaxWait", GDM_CONFIG_VALUE_INT, "15", GDM_ID_MAX_WAIT },
	{ GDM_CONFIG_GROUP_XDMCP, "DisplaysPerHost", GDM_CONFIG_VALUE_INT, "2", GDM_ID_DISPLAYS_PER_HOST },
	{ GDM_CONFIG_GROUP_XDMCP, "Port", GDM_CONFIG_VALUE_INT, "177", GDM_ID_UDP_PORT },
	{ GDM_CONFIG_GROUP_XDMCP, "HonorIndirect", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_INDIRECT },
	{ GDM_CONFIG_GROUP_XDMCP, "MaxPendingIndirect", GDM_CONFIG_VALUE_INT, "4", GDM_ID_MAX_INDIRECT },
	{ GDM_CONFIG_GROUP_XDMCP, "MaxWaitIndirect", GDM_CONFIG_VALUE_INT, "15", GDM_ID_MAX_WAIT_INDIRECT },
	{ GDM_CONFIG_GROUP_XDMCP, "PingIntervalSeconds", GDM_CONFIG_VALUE_INT, "15", GDM_ID_PING_INTERVAL },
	{ GDM_CONFIG_GROUP_XDMCP, "Willing", GDM_CONFIG_VALUE_STRING, GDMCONFDIR "/Xwilling", GDM_ID_WILLING },

	{ GDM_CONFIG_GROUP_XDMCP, "EnableProxy", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_XDMCP_PROXY },
	{ GDM_CONFIG_GROUP_XDMCP, "ProxyXServer", GDM_CONFIG_VALUE_STRING, "", GDM_ID_XDMCP_PROXY_XSERVER },
	{ GDM_CONFIG_GROUP_XDMCP, "ProxyReconnect", GDM_CONFIG_VALUE_STRING, "", GDM_ID_XDMCP_PROXY_RECONNECT },

	{ GDM_CONFIG_GROUP_GUI, "GtkTheme", GDM_CONFIG_VALUE_STRING, "Default", GDM_ID_GTK_THEME },
	{ GDM_CONFIG_GROUP_GUI, "GtkRC", GDM_CONFIG_VALUE_STRING, DATADIR "/themes/Default/gtk-2.0/gtkrc", GDM_ID_GTKRC },
	{ GDM_CONFIG_GROUP_GUI, "MaxIconWidth", GDM_CONFIG_VALUE_INT, "128", GDM_ID_MAX_ICON_WIDTH },
	{ GDM_CONFIG_GROUP_GUI, "MaxIconHeight", GDM_CONFIG_VALUE_INT, "128", GDM_ID_MAX_ICON_HEIGHT },

	{ GDM_CONFIG_GROUP_GUI, "AllowGtkThemeChange", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_ALLOW_GTK_THEME_CHANGE },
	{ GDM_CONFIG_GROUP_GUI, "GtkThemesToAllow", GDM_CONFIG_VALUE_STRING, "all", GDM_ID_GTK_THEMES_TO_ALLOW },

	{ GDM_CONFIG_GROUP_GREETER, "Browser", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_BROWSER },
	{ GDM_CONFIG_GROUP_GREETER, "Include", GDM_CONFIG_VALUE_STRING, "", GDM_ID_INCLUDE },
	{ GDM_CONFIG_GROUP_GREETER, "Exclude", GDM_CONFIG_VALUE_STRING, "bin,daemon,adm,lp,sync,shutdown,halt,mail,news,uucp,operator,nobody,gdm,postgres,pvm,rpm,nfsnobody,pcap", GDM_ID_EXCLUDE },
	{ GDM_CONFIG_GROUP_GREETER, "IncludeAll", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_INCLUDE_ALL },
	{ GDM_CONFIG_GROUP_GREETER, "MinimalUID", GDM_CONFIG_VALUE_INT, "100", GDM_ID_MINIMAL_UID },
	{ GDM_CONFIG_GROUP_GREETER, "DefaultFace", GDM_CONFIG_VALUE_STRING, PIXMAPDIR "/nobody.png", GDM_ID_DEFAULT_FACE },
	{ GDM_CONFIG_GROUP_GREETER, "GlobalFaceDir", GDM_CONFIG_VALUE_STRING, DATADIR "/pixmaps/faces/", GDM_ID_GLOBAL_FACE_DIR },
	{ GDM_CONFIG_GROUP_GREETER, "LocaleFile", GDM_CONFIG_VALUE_STRING, GDMLOCALEDIR "/locale.alias", GDM_ID_LOCALE_FILE },
	{ GDM_CONFIG_GROUP_GREETER, "Logo", GDM_CONFIG_VALUE_STRING, PIXMAPDIR "/gdm-foot-logo.png", GDM_ID_LOGO },
	{ GDM_CONFIG_GROUP_GREETER, "ChooserButtonLogo", GDM_CONFIG_VALUE_STRING, PIXMAPDIR "/gdm-foot-logo.png", GDM_ID_CHOOSER_BUTTON_LOGO },
	{ GDM_CONFIG_GROUP_GREETER, "Quiver", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_QUIVER },
	{ GDM_CONFIG_GROUP_GREETER, "SystemMenu", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SYSTEM_MENU },
	{ GDM_CONFIG_GROUP_DAEMON, "Configurator", GDM_CONFIG_VALUE_STRING, SBINDIR "/gdmsetup --disable-sound --disable-crash-dialog", GDM_ID_CONFIGURATOR },
	{ GDM_CONFIG_GROUP_GREETER, "ConfigAvailable", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_CONFIG_AVAILABLE },
	{ GDM_CONFIG_GROUP_GREETER, "ChooserButton", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_CHOOSER_BUTTON },
	{ GDM_CONFIG_GROUP_GREETER, "TitleBar", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_TITLE_BAR },

	/*
	 * For backwards compatibility, do not set values for DEFAULT_WELCOME or
	 * DEFAULT_REMOTEWELCOME.  This will cause these values to always be
	 * read from the config file, and will cause them to return FALSE if
	 * no value is set in the config file.  We want the value, "FALSE" if
	 * the values don't exist in the config file.  The daemon will compare
	 * the Welcome/RemoveWelcome value with the default string and
	 * automatically translate the text if the string is the same as the
	 * default string.  We set the default values of GDM_ID_WELCOME and
	 * GDM_ID_REMOTEWELCOME so that the default value is returned when
	 * you run GET_CONFIG on these keys.
	 */
	{ GDM_CONFIG_GROUP_GREETER, "DefaultWelcome", GDM_CONFIG_VALUE_BOOL, "", GDM_ID_DEFAULT_WELCOME },
	{ GDM_CONFIG_GROUP_GREETER, "DefaultRemoteWelcome", GDM_CONFIG_VALUE_BOOL, "", GDM_ID_DEFAULT_REMOTE_WELCOME },
	{ GDM_CONFIG_GROUP_GREETER, "Welcome", GDM_CONFIG_VALUE_STRING, GDM_DEFAULT_WELCOME_MSG, GDM_ID_WELCOME },
	{ GDM_CONFIG_GROUP_GREETER, "RemoteWelcome", GDM_CONFIG_VALUE_STRING, GDM_DEFAULT_REMOTE_WELCOME_MSG, GDM_ID_REMOTE_WELCOME },
	{ GDM_CONFIG_GROUP_GREETER, "XineramaScreen", GDM_CONFIG_VALUE_INT, "0", GDM_ID_XINERAMA_SCREEN },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundProgram", GDM_CONFIG_VALUE_STRING, "", GDM_ID_BACKGROUND_PROGRAM },
	{ GDM_CONFIG_GROUP_GREETER, "RunBackgroundProgramAlways", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_RUN_BACKGROUND_PROGRAM_ALWAYS },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundProgramInitialDelay", GDM_CONFIG_VALUE_INT, "30", GDM_ID_BACKGROUND_PROGRAM_INITIAL_DELAY },
	{ GDM_CONFIG_GROUP_GREETER, "RestartBackgroundProgram", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_RESTART_BACKGROUND_PROGRAM },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundProgramRestartDelay", GDM_CONFIG_VALUE_INT, "30", GDM_ID_BACKGROUND_PROGRAM_RESTART_DELAY },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundImage", GDM_CONFIG_VALUE_STRING, "", GDM_ID_BACKGROUND_IMAGE },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundColor", GDM_CONFIG_VALUE_STRING, "#76848F", GDM_ID_BACKGROUND_COLOR },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundType", GDM_CONFIG_VALUE_INT, "2", GDM_ID_BACKGROUND_TYPE },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundScaleToFit", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_BACKGROUND_SCALE_TO_FIT },
	{ GDM_CONFIG_GROUP_GREETER, "BackgroundRemoteOnlyColor", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_BACKGROUND_REMOTE_ONLY_COLOR },
	{ GDM_CONFIG_GROUP_GREETER, "LockPosition", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_LOCK_POSITION },
	{ GDM_CONFIG_GROUP_GREETER, "SetPosition", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SET_POSITION },
	{ GDM_CONFIG_GROUP_GREETER, "PositionX", GDM_CONFIG_VALUE_INT, "0", GDM_ID_POSITION_X },
	{ GDM_CONFIG_GROUP_GREETER, "PositionY", GDM_CONFIG_VALUE_INT, "0", GDM_ID_POSITION_Y },
	{ GDM_CONFIG_GROUP_GREETER, "Use24Clock", GDM_CONFIG_VALUE_STRING, "auto", GDM_ID_USE_24_CLOCK },
	{ GDM_CONFIG_GROUP_GREETER, "UseCirclesInEntry", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_ENTRY_CIRCLES },
	{ GDM_CONFIG_GROUP_GREETER, "UseInvisibleInEntry", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_ENTRY_INVISIBLE },
	{ GDM_CONFIG_GROUP_GREETER, "GraphicalTheme", GDM_CONFIG_VALUE_STRING, "circles", GDM_ID_GRAPHICAL_THEME },
	{ GDM_CONFIG_GROUP_GREETER, "GraphicalThemes", GDM_CONFIG_VALUE_STRING, "circles/:happygnome", GDM_ID_GRAPHICAL_THEMES },
	{ GDM_CONFIG_GROUP_GREETER, "GraphicalThemeRand", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_GRAPHICAL_THEME_RAND },
	{ GDM_CONFIG_GROUP_GREETER, "GraphicalThemeDir", GDM_CONFIG_VALUE_STRING, DATADIR "/gdm/themes/", GDM_ID_GRAPHICAL_THEME_DIR },
	{ GDM_CONFIG_GROUP_GREETER, "GraphicalThemedColor", GDM_CONFIG_VALUE_STRING, "#76848F", GDM_ID_GRAPHICAL_THEMED_COLOR },

	{ GDM_CONFIG_GROUP_GREETER, "InfoMsgFile", GDM_CONFIG_VALUE_STRING, "", GDM_ID_INFO_MSG_FILE },
	{ GDM_CONFIG_GROUP_GREETER, "InfoMsgFont", GDM_CONFIG_VALUE_STRING, "", GDM_ID_INFO_MSG_FONT },

	{ GDM_CONFIG_GROUP_GREETER, "PreFetchProgram", GDM_CONFIG_VALUE_STRING, "", GDM_ID_PRE_FETCH_PROGRAM },

	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLogin", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SOUND_ON_LOGIN },
	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLoginSuccess", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SOUND_ON_LOGIN_SUCCESS },
	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLoginFailure", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SOUND_ON_LOGIN_FAILURE },
	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLoginFile", GDM_CONFIG_VALUE_STRING, "", GDM_ID_SOUND_ON_LOGIN_FILE },
	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLoginSuccessFile", GDM_CONFIG_VALUE_STRING, "", GDM_ID_SOUND_ON_LOGIN_SUCCESS_FILE },
	{ GDM_CONFIG_GROUP_GREETER, "SoundOnLoginFailureFile", GDM_CONFIG_VALUE_STRING, "", GDM_ID_SOUND_ON_LOGIN_FAILURE_FILE },
	{ GDM_CONFIG_GROUP_DAEMON, "SoundProgram", GDM_CONFIG_VALUE_STRING, SOUND_PROGRAM, GDM_ID_SOUND_PROGRAM },

	{ GDM_CONFIG_GROUP_CHOOSER, "ScanTime", GDM_CONFIG_VALUE_INT, "4", GDM_ID_SCAN_TIME },
	{ GDM_CONFIG_GROUP_CHOOSER, "DefaultHostImg", GDM_CONFIG_VALUE_STRING, PIXMAPDIR "/nohost.png", GDM_ID_DEFAULT_HOST_IMG },
	{ GDM_CONFIG_GROUP_CHOOSER, "HostImageDir", GDM_CONFIG_VALUE_STRING, DATADIR "/hosts/", GDM_ID_HOST_IMAGE_DIR },
	{ GDM_CONFIG_GROUP_CHOOSER, "Hosts", GDM_CONFIG_VALUE_STRING, "", GDM_ID_HOSTS },
	{ GDM_CONFIG_GROUP_CHOOSER, "Multicast", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_MULTICAST },
	{ GDM_CONFIG_GROUP_CHOOSER, "MulticastAddr", GDM_CONFIG_VALUE_STRING, "ff02::1", GDM_ID_MULTICAST_ADDR },
	{ GDM_CONFIG_GROUP_CHOOSER, "Broadcast", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_BROADCAST },
	{ GDM_CONFIG_GROUP_CHOOSER, "AllowAdd", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_ALLOW_ADD },

	{ GDM_CONFIG_GROUP_GREETER, "ShowGnomeFailsafeSession", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SHOW_GNOME_FAILSAFE },
	{ GDM_CONFIG_GROUP_GREETER, "ShowXtermFailsafeSession", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SHOW_XTERM_FAILSAFE },
	{ GDM_CONFIG_GROUP_GREETER, "ShowLastSession", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SHOW_LAST_SESSION },

	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand0", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel0", GDM_CONFIG_VALUE_STRING, "Custom_0", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel0", GDM_CONFIG_VALUE_STRING, "Execute custom command _0", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText0", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip0", GDM_CONFIG_VALUE_STRING, "Execute custom command 0", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart0", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent0", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand1", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel1", GDM_CONFIG_VALUE_STRING, "Custom_1", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel1", GDM_CONFIG_VALUE_STRING, "Execute custom command _1", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText1", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip1", GDM_CONFIG_VALUE_STRING, "Execute custom command 1", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart1", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent1", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand2", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel2", GDM_CONFIG_VALUE_STRING, "Custom_2", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel2", GDM_CONFIG_VALUE_STRING, "Execute custom command _2", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText2", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip2", GDM_CONFIG_VALUE_STRING, "Execute custom command 2", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart2", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent2", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand3", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel3", GDM_CONFIG_VALUE_STRING, "Custom_3", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel3", GDM_CONFIG_VALUE_STRING, "Execute custom command _3", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText3", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip3", GDM_CONFIG_VALUE_STRING, "Execute custom command 3", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart3", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent3", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand4", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel4", GDM_CONFIG_VALUE_STRING, "Custom_4", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel4", GDM_CONFIG_VALUE_STRING, "Execute custom command _4", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText4", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip4", GDM_CONFIG_VALUE_STRING, "Execute custom command 4", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart4", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent4", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand5", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel5", GDM_CONFIG_VALUE_STRING, "Custom_5", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel5", GDM_CONFIG_VALUE_STRING, "Execute custom command _5", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText5", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip5", GDM_CONFIG_VALUE_STRING, "Execute custom command 5", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart5", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent5", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand6", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel6", GDM_CONFIG_VALUE_STRING, "Custom_6", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel6", GDM_CONFIG_VALUE_STRING, "Execute custom command _6", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText6", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip6", GDM_CONFIG_VALUE_STRING, "Execute custom command 6", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart6", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent6", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand7", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel7", GDM_CONFIG_VALUE_STRING, "Custom_7", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel7", GDM_CONFIG_VALUE_STRING, "Execute custom command _7", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText7", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip7", GDM_CONFIG_VALUE_STRING, "Execute custom command 7", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart7", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent7", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand8", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel8", GDM_CONFIG_VALUE_STRING, "Custom_8", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel8", GDM_CONFIG_VALUE_STRING, "Execute custom command _8", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText8", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip8", GDM_CONFIG_VALUE_STRING, "Execute custom command 8", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart8", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent8", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommand9", GDM_CONFIG_VALUE_STRING, NULL, GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLabel9", GDM_CONFIG_VALUE_STRING, "Custom_9", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandLRLabel9", GDM_CONFIG_VALUE_STRING, "Execute custom command _9", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandText9", GDM_CONFIG_VALUE_STRING, "Are you sure?", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandTooltip9", GDM_CONFIG_VALUE_STRING, "Execute custom command 9", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandNoRestart9", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },
	{ GDM_CONFIG_GROUP_CUSTOM_CMD, "CustomCommandIsPersistent9", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_NONE },

	{ NULL }
};

static const GdmConfigEntry gdm_daemon_server_config_entries [] = {
	/* Per server definitions */
	{ GDM_CONFIG_GROUP_NONE, "name", GDM_CONFIG_VALUE_STRING, "Standard server", GDM_ID_SERVER_NAME },
	{ GDM_CONFIG_GROUP_NONE, "command", GDM_CONFIG_VALUE_STRING, X_SERVER, GDM_ID_SERVER_COMMAND },
	/* runnable as flexi server */
	{ GDM_CONFIG_GROUP_NONE, "flexible", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SERVER_FLEXIBLE },
	/* choosable from the login screen */
	{ GDM_CONFIG_GROUP_NONE, "choosable", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SERVER_CHOOSABLE },
	/* Login is handled by gdm, otherwise it's a remote server */
	{ GDM_CONFIG_GROUP_NONE, "handled", GDM_CONFIG_VALUE_BOOL, "true", GDM_ID_SERVER_HANDLED },
	/* Instead of the greeter run the chooser */
	{ GDM_CONFIG_GROUP_NONE, "chooser", GDM_CONFIG_VALUE_BOOL, "false", GDM_ID_SERVER_CHOOSER },
	/* select a nice level to run the X server at */
	{ GDM_CONFIG_GROUP_NONE, "priority", GDM_CONFIG_VALUE_INT, "0", GDM_ID_SERVER_PRIORITY },
};

G_END_DECLS

#endif /* _GDM_DAEMON_CONFIG_ENTRIES_H */