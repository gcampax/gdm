/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 1998, 1999, 2000 Martin K. Petersen <mkp@mkp.net>
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/ioctl.h>

#include <errno.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>

#include <X11/Xlib.h>
#include <X11/Xmd.h>
#include <X11/Xdmcp.h>

#include "gdm-common.h"
#include "gdm-xdmcp-display.h"
#include "gdm-display-factory.h"
#include "gdm-xdmcp-display-factory.h"
#include "gdm-display-store.h"

#include "auth.h"
#include "choose.h"

/*
 * On Sun, we need to define allow_severity and deny_severity to link
 * against libwrap.
 */
#ifdef __sun
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif

#define GDM_XDMCP_DISPLAY_FACTORY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GDM_TYPE_XDMCP_DISPLAY_FACTORY, GdmXdmcpDisplayFactoryPrivate))

#define DEFAULT_PORT                  177
#define DEFAULT_USE_MULTICAST         FALSE
#define DEFAULT_MULTICAST_ADDRESS     "ff02::1"
#define DEFAULT_HONOR_INDIRECT        TRUE
#define DEFAULT_MAX_DISPLAYS_PER_HOST 2
#define DEFAULT_MAX_DISPLAYS          16
#define DEFAULT_MAX_PENDING_DISPLAYS  4
#define DEFAULT_MAX_WAIT              15

#define GDM_MAX_FORWARD_QUERIES 10
#define GDM_FORWARD_QUERY_TIMEOUT 30
#define MANAGED_FORWARD_INTERVAL 1500 /* 1.5 seconds */

/* some extra XDMCP opcodes that xdm will happily ignore since they'll be
 * the wrong XDMCP version anyway */
#define GDM_XDMCP_PROTOCOL_VERSION 1001
enum {
        GDM_XDMCP_FIRST_OPCODE = 1000, /*just a marker, not an opcode */

        GDM_XDMCP_MANAGED_FORWARD = 1000,
                /* manager (master) -> manager
                 * A packet with MANAGED_FORWARD is sent to the
                 * manager that sent the forward query from the manager to
                 * which forward query was sent.  It indicates that the forward
                 * was fully processed and that the client now has either
                 * a managed session, or has been sent denial, refuse or failed.
                 * (if the denial gets lost then client gets dumped into the
                 * chooser again).  This should be resent a few times
                 * until some (short) timeout or until GOT_MANAGED_FORWARD
                 * is sent.  GDM sends at most 3 packates with 1.5 seconds
                 * between each.
                 *
                 * Argument is ARRAY8 with the address of the originating host */
        GDM_XDMCP_GOT_MANAGED_FORWARD,
                /* manager -> manager (master)
                 * A single packet with GOT_MANAGED_FORWARD is sent to indicate
                 * that we did receive the MANAGED_FORWARD packet.  The argument
                 * must match the MANAGED_FORWARD one or it will just be ignored.
                 *
                 * Argument is ARRAY8 with the address of the originating host */
        GDM_XDMCP_LAST_OPCODE /*just a marker, not an opcode */
};

/*
 * We don't support XDM-AUTHENTICATION-1 and XDM-AUTHORIZATION-1.
 *
 * The latter would be quite useful to avoid sending unencrypted
 * cookies over the wire. Unfortunately it isn't supported without
 * XDM-AUTHENTICATION-1 which requires a key database with private
 * keys from all X terminals on your LAN. Fun, fun, fun.
 *
 * Furthermore user passwords go over the wire in cleartext anyway,
 * so protecting cookies is not that important.
 */

typedef struct _XdmAuth {
        ARRAY8 authentication;
        ARRAY8 authorization;
} XdmAuthRec, *XdmAuthPtr;

static XdmAuthRec serv_authlist = {
        { (CARD16) 0, (CARD8 *) 0 },
        { (CARD16) 0, (CARD8 *) 0 }
};

/* NOTE: Timeout and max are hardcoded */
typedef struct _GdmForwardQuery {
        time_t      acctime;
        GdmAddress *dsp_address;
        GdmAddress *from_address;
} GdmForwardQuery;

typedef struct {
        int              times;
        guint            handler;
        GdmAddress      *manager;
        GdmAddress      *origin;
        GdmXdmcpDisplayFactory *xdmcp_display_factory;
} ManagedForward;

struct GdmXdmcpDisplayFactoryPrivate
{
        GSList          *forward_queries;
        GSList          *managed_forwards;

        int              socket_fd;
        gint32           session_serial;
        guint            socket_watch_id;
        XdmcpBuffer      buf;

        guint            num_sessions;
        guint            num_pending_sessions;

        char            *sysid;
        char            *hostname;
        ARRAY8           servhost;

        /* configuration */
        guint            port;
        gboolean         use_multicast;
        char            *multicast_address;
        gboolean         honor_indirect;
        char            *willing_script;
        guint            max_displays_per_host;
        guint            max_displays;
        guint            max_pending_displays;
        guint            max_wait;
};

enum {
        PROP_0,
        PROP_PORT,
        PROP_USE_MULTICAST,
        PROP_MULTICAST_ADDRESS,
        PROP_HONOR_INDIRECT,
        PROP_WILLING_SCRIPT,
        PROP_MAX_DISPLAYS_PER_HOST,
        PROP_MAX_DISPLAYS,
        PROP_MAX_PENDING_DISPLAYS,
        PROP_MAX_WAIT,
};

static void     gdm_xdmcp_display_factory_class_init    (GdmXdmcpDisplayFactoryClass *klass);
static void     gdm_xdmcp_display_factory_init          (GdmXdmcpDisplayFactory      *manager);
static void     gdm_xdmcp_display_factory_finalize      (GObject              *object);

static gpointer xdmcp_display_factory_object = NULL;

G_DEFINE_TYPE (GdmXdmcpDisplayFactory, gdm_xdmcp_display_factory, GDM_TYPE_DISPLAY_FACTORY)

/* Theory of operation:
 *
 * Process idles waiting for UDP packets on port 177.
 * Incoming packets are decoded and checked against tcp_wrapper.
 *
 * A typical session looks like this:
 *
 * Display sends Query/BroadcastQuery to Manager.
 *
 * Manager selects an appropriate authentication scheme from the
 * display's list of supported ones and sends Willing/Unwilling.
 *
 * Assuming the display accepts the auth. scheme it sends back a
 * Request.
 *
 * If the manager accepts to service the display (i.e. loadavg is low)
 * it sends back an Accept containing a unique SessionID. The
 * SessionID is stored in an accept queue by the Manager. Should the
 * manager refuse to start a session a Decline is sent to the display.
 *
 * The display returns a Manage request containing the supplied
 * SessionID. The manager will then start a session on the display. In
 * case the SessionID is not on the accept queue the manager returns
 * Refuse. If the manager fails to open the display for connections
 * Failed is returned.
 *
 * During the session the display periodically sends KeepAlive packets
 * to the manager. The manager responds with Alive.
 *
 * Similarly the manager xpings the display once in a while and shuts
 * down the connection on failure.
 *
 */

GQuark
gdm_xdmcp_display_factory_error_quark (void)
{
        static GQuark ret = 0;
        if (ret == 0) {
                ret = g_quark_from_static_string ("gdm_xdmcp_display_factory_error");
        }

        return ret;
}

static gint32
get_next_session_serial (GdmXdmcpDisplayFactory *factory)
{
        gint32 serial;

 again:
        if (factory->priv->session_serial != G_MAXINT32) {
                serial = factory->priv->session_serial++;
        } else {
                serial = g_random_int ();
        }

        if (serial == 0) {
                goto again;
        }

        return serial;
}

/* for debugging */
static const char *
ai_family_str (struct addrinfo *ai)
{
        const char *str;
        switch (ai->ai_family) {
        case AF_INET:
                str = "inet";
                break;
        case AF_INET6:
                str = "inet6";
                break;
        case AF_UNIX:
                str = "unix";
                break;
        case AF_UNSPEC:
                str = "unspecified";
                break;
        default:
                str = "unknown";
                break;
        }
        return str;
}

/* for debugging */
static const char *
ai_type_str (struct addrinfo *ai)
{
        const char *str;
        switch (ai->ai_socktype) {
        case SOCK_STREAM:
                str = "stream";
                break;
        case SOCK_DGRAM:
                str = "datagram";
                break;
        case SOCK_SEQPACKET:
                str = "seqpacket";
                break;
        case SOCK_RAW:
                str = "raw";
                break;
        default:
                str = "unknown";
                break;
        }
        return str;
}

/* for debugging */
static const char *
ai_protocol_str (struct addrinfo *ai)
{
        const char *str;
        switch (ai->ai_protocol) {
        case 0:
                str = "default";
                break;
        case IPPROTO_TCP:
                str = "TCP";
                break;
        case IPPROTO_UDP:
                str = "UDP";
                break;
        case IPPROTO_RAW:
                str = "raw";
                break;
        default:
                str = "unknown";
                break;
        }

        return str;
}

/* for debugging */
static char *
ai_flags_str (struct addrinfo *ai)
{
        GString *str;

        str = g_string_new ("");
        if (ai->ai_flags == 0) {
                g_string_append (str, "none");
        } else {
                if (ai->ai_flags & AI_PASSIVE) {
                        g_string_append (str, "passive ");
                }
                if (ai->ai_flags & AI_CANONNAME) {
                        g_string_append (str, "canon ");
                }
                if (ai->ai_flags & AI_NUMERICHOST) {
                        g_string_append (str, "numhost ");
                }
                if (ai->ai_flags & AI_NUMERICSERV) {
                        g_string_append (str, "numserv ");
                }
                if (ai->ai_flags & AI_V4MAPPED) {
                        g_string_append (str, "v4mapped ");
                }
                if (ai->ai_flags & AI_ALL) {
                        g_string_append (str, "all ");
                }
        }
        return g_string_free (str, FALSE);
}

/* for debugging */
static void
debug_addrinfo (struct addrinfo *ai)
{
        char *str;
        str = ai_flags_str (ai);
        g_debug ("XDMCP: addrinfo family=%s type=%s proto=%s flags=%s",
                 ai_family_str (ai),
                 ai_type_str (ai),
                 ai_protocol_str (ai),
                 str);
        g_free (str);
}

static int
create_socket (struct addrinfo *ai)
{
        int sock;

        sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
                g_warning ("socket: %s", g_strerror (errno));
                return sock;
        }

        if (bind (sock, ai->ai_addr, ai->ai_addrlen) < 0) {
                g_warning ("bind: %s", g_strerror (errno));
                close (sock);
                return -1;
        }

        return sock;
}

static int
do_bind (guint                     port,
         int                       family,
         struct sockaddr_storage * hostaddr)
{
        struct addrinfo  hints;
        struct addrinfo *ai_list;
        struct addrinfo *ai;
        char             strport[NI_MAXSERV];
        int              gaierr;
        int              sock;

        sock = -1;

        memset (&hints, 0, sizeof (hints));
        hints.ai_family = family;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        snprintf (strport, sizeof (strport), "%u", port);

        ai_list = NULL;
        if ((gaierr = getaddrinfo (NULL, strport, &hints, &ai_list)) != 0) {
                g_error ("Unable to connect to socket: %s", gai_strerror (gaierr));
                return -1;
        }

        /* should only be one but.. */
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
                if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
                        continue;
                }

                debug_addrinfo (ai);

                if (sock < 0) {
                        char       *host;
                        char       *serv;
                        GdmAddress *addr;

                        addr = gdm_address_new_from_sockaddr_storage ((struct sockaddr_storage *)ai->ai_addr);

                        host = NULL;
                        serv = NULL;
                        gdm_address_get_numeric_info (addr, &host, &serv);
                        g_debug ("XDMCP: Attempting to bind to host %s port %s", host, serv);
                        g_free (host);
                        g_free (serv);
                        gdm_address_free (addr);

                        sock = create_socket (ai);
                        if (sock >= 0) {
                                if (hostaddr != NULL) {
                                        memcpy (hostaddr, ai->ai_addr, ai->ai_addrlen);
                                }
                        }
                }
        }

        freeaddrinfo (ai_list);

        return sock;
}

static void
setup_multicast (GdmXdmcpDisplayFactory *factory)
{
#ifdef ENABLE_IPV6
        /* Checking and Setting Multicast options */
        {
                /*
                 * socktemp is a temporary socket for getting info about
                 * available interfaces
                 */
                int              socktemp;
                int              i;
                int              num;
                char            *buf;
                struct ipv6_mreq mreq;

                /* For interfaces' list */
                struct ifconf    ifc;
                struct ifreq    *ifr;

                socktemp = socket (AF_INET, SOCK_DGRAM, 0);
#ifdef SIOCGIFNUM
                if (ioctl (socktemp, SIOCGIFNUM, &num) < 0) {
                        num = 64;
                }
#else
                num = 64;
#endif /* SIOCGIFNUM */
                ifc.ifc_len = sizeof (struct ifreq) * num;
                ifc.ifc_buf = buf = malloc (ifc.ifc_len);

                if (ioctl (socktemp, SIOCGIFCONF, &ifc) >= 0) {
                        ifr = ifc.ifc_req;
                        num = ifc.ifc_len / sizeof (struct ifreq); /* No of interfaces */

                        /* Joining multicast group with all interfaces */
                        for (i = 0 ; i < num ; i++) {
                                struct ifreq ifreq;
                                int          ifindex;

                                memset (&ifreq, 0, sizeof (ifreq));
                                strncpy (ifreq.ifr_name, ifr[i].ifr_name, sizeof (ifreq.ifr_name));
                                /* paranoia */
                                ifreq.ifr_name[sizeof (ifreq.ifr_name) - 1] = '\0';

                                if (ioctl (socktemp, SIOCGIFFLAGS, &ifreq) < 0) {
                                        g_debug ("XDMCP: Could not get SIOCGIFFLAGS for %s",
                                                 ifr[i].ifr_name);
                                }

                                ifindex = if_nametoindex (ifr[i].ifr_name);

                                if ((!(ifreq.ifr_flags & IFF_UP) ||
                                     (ifreq.ifr_flags & IFF_LOOPBACK)) ||
                                    ((ifindex == 0 ) && (errno == ENXIO))) {
                                        /* Not a valid interface or loopback interface*/
                                        continue;
                                }

                                mreq.ipv6mr_interface = ifindex;
                                inet_pton (AF_INET6,
                                           factory->priv->multicast_address,
                                           &mreq.ipv6mr_multiaddr);

                                setsockopt (factory->priv->socket_fd,
                                            IPPROTO_IPV6,
                                            IPV6_JOIN_GROUP,
                                            &mreq,
                                            sizeof (mreq));
                        }
                }
                g_free (buf);
                close (socktemp);
        }
#endif /* ENABLE_IPV6 */
}

static gboolean
open_port (GdmXdmcpDisplayFactory *factory)
{
        struct sockaddr_storage serv_sa = { 0 };

        g_debug ("XDMCP: Start up on host %s, port %d",
                 factory->priv->hostname,
                 factory->priv->port);

        /* Open socket for communications */
#ifdef ENABLE_IPV6
        factory->priv->socket_fd = do_bind (factory->priv->port, AF_INET6, &serv_sa);
        if (factory->priv->socket_fd < 0)
#endif
                factory->priv->socket_fd = do_bind (factory->priv->port, AF_INET, &serv_sa);

        if G_UNLIKELY (factory->priv->socket_fd < 0) {
                g_warning (_("Could not create socket!"));
                return FALSE;
        }

        gdm_fd_set_close_on_exec (factory->priv->socket_fd);

        if (factory->priv->use_multicast) {
                setup_multicast (factory);
        }

        return TRUE;
}

static gboolean
gdm_xdmcp_host_allow (GdmAddress *address)
{
#ifdef HAVE_TCPWRAPPERS

        /*
         * Avoids a warning, my tcpd.h file doesn't include this prototype, even
         * though the library does include the function and the manpage mentions it
         */
        extern int hosts_ctl (char *daemon,
                              char *client_name,
                              char *client_addr,
                              char *client_user);

        char       *client;
        char       *host;
        gboolean    ret;

        host = NULL;
        client = NULL;

        /* Find client hostname */
        gdm_address_get_hostname (address, &client);
        gdm_address_get_numeric_info (address, &host, NULL);

        /* Check with tcp_wrappers if client is allowed to access */
        ret = hosts_ctl ("gdm", client, host, "");

        g_free (host);
        g_free (client);

        return ret;
#else /* HAVE_TCPWRAPPERS */
        return (TRUE);
#endif /* HAVE_TCPWRAPPERS */
}

typedef struct {
        GdmAddress *address;
        int         count;
} CountDisplayData;

static gboolean
count_displays_from_host (const char       *id,
                          GdmDisplay       *display,
                          CountDisplayData *data)
{
        GdmAddress *address;

        if (GDM_IS_XDMCP_DISPLAY (display)) {
                address = gdm_xdmcp_display_get_remote_address (GDM_XDMCP_DISPLAY (display));

                if (gdm_address_equal (address, data->address)) {
                        data->count++;
                }
        }

        return TRUE;
}

static int
gdm_xdmcp_num_displays_from_host (GdmXdmcpDisplayFactory *factory,
                                  GdmAddress             *address)
{
        CountDisplayData data;
        GdmDisplayStore *store;

        data.count = 0;
        data.address = address;

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        gdm_display_store_foreach (store,
                                   (GdmDisplayStoreFunc)count_displays_from_host,
                                   &data);

        return data.count;
}

typedef struct {
        GdmAddress *address;
        int         display_num;
} LookupHostData;

static gboolean
lookup_by_host (const char     *id,
                GdmDisplay     *display,
                LookupHostData *data)
{
        GdmAddress *this_address;
        int         disp_num;

        if (! GDM_IS_XDMCP_DISPLAY (display)) {
                return FALSE;
        }

        this_address = gdm_xdmcp_display_get_remote_address (GDM_XDMCP_DISPLAY (display));
        gdm_display_get_x11_display_number (display, &disp_num, NULL);

        if (gdm_address_equal (this_address, data->address)
            && disp_num == data->display_num) {
                return TRUE;
        }

        return FALSE;
}

static GdmDisplay *
gdm_xdmcp_display_lookup_by_host (GdmXdmcpDisplayFactory *factory,
                                  GdmAddress      *address,
                                  int              display_num)
{
        GdmDisplay      *display;
        LookupHostData  *data;
        GdmDisplayStore *store;

        data = g_new0 (LookupHostData, 1);
        data->address = address;
        data->display_num = display_num;

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        display = gdm_display_store_find (store,
                                          (GdmDisplayStoreFunc)lookup_by_host,
                                          data);
        g_free (data);

        return display;
}

static char *
get_willing_output (GdmXdmcpDisplayFactory *factory)
{
        char  *output;
        char **argv;
        FILE  *fd;
        char   buf[256];

        output = NULL;
        buf[0] = '\0';

        if (factory->priv->willing_script == NULL) {
                goto out;
        }

        argv = NULL;
        if (! g_shell_parse_argv (factory->priv->willing_script, NULL, &argv, NULL)) {
                goto out;
        }

        if (argv == NULL ||
            argv[0] == NULL ||
            g_access (argv[0], X_OK) != 0) {
                goto out;
        }

        fd = popen (factory->priv->willing_script, "r");
        if (fd == NULL) {
                goto out;
        }

        if (fgets (buf, sizeof (buf), fd) == NULL) {
                pclose (fd);
                goto out;
        }

        pclose (fd);

        output = g_strdup (buf);

 out:
        return output;
}

static void
gdm_xdmcp_send_willing (GdmXdmcpDisplayFactory *factory,
                        GdmAddress      *address)
{
        ARRAY8        status;
        XdmcpHeader   header;
        static char  *last_status = NULL;
        static time_t last_willing = 0;
        char         *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Sending WILLING to %s", host);
        g_free (host);

        if (last_willing == 0 || time (NULL) - 3 > last_willing) {
                char *s;

                g_free (last_status);

                s = get_willing_output (factory);
                if (s != NULL) {
                        g_free (last_status);
                        last_status = s;
                } else {
                        last_status = g_strdup (factory->priv->sysid);
                }
        }

        if (! gdm_address_is_local (address) &&
            gdm_xdmcp_num_displays_from_host (factory, address) >= factory->priv->max_displays_per_host) {
                /*
                 * Don't translate, this goes over the wire to servers where we
                 * don't know the charset or language, so it must be ascii
                 */
                status.data = (CARD8 *) g_strdup_printf ("%s (Server is busy)",
                                                         last_status);
        } else {
                status.data = (CARD8 *) g_strdup (last_status);
        }

        status.length = strlen ((char *) status.data);

        header.opcode   = (CARD16) WILLING;
        header.length   = 6 + serv_authlist.authentication.length;
        header.length  += factory->priv->servhost.length + status.length;
        header.version  = XDM_PROTOCOL_VERSION;
        XdmcpWriteHeader (&factory->priv->buf, &header);

        /* Hardcoded authentication */
        XdmcpWriteARRAY8 (&factory->priv->buf, &serv_authlist.authentication);
        XdmcpWriteARRAY8 (&factory->priv->buf, &factory->priv->servhost);
        XdmcpWriteARRAY8 (&factory->priv->buf, &status);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        g_free (status.data);
}

static void
gdm_xdmcp_send_unwilling (GdmXdmcpDisplayFactory *factory,
                          GdmAddress      *address,
                          int              type)
{
        ARRAY8        status;
        XdmcpHeader   header;
        static time_t last_time = 0;
        char         *host;

        /* only send at most one packet per second,
           no harm done if we don't send it at all */
        if (last_time + 1 >= time (NULL)) {
                return;
        }

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Sending UNWILLING to %s", host);
        g_warning (_("Denied XDMCP query from host %s"), host);
        g_free (host);

        /*
         * Don't translate, this goes over the wire to servers where we
         * don't know the charset or language, so it must be ascii
         */
        status.data = (CARD8 *) "Display not authorized to connect";
        status.length = strlen ((char *) status.data);

        header.opcode = (CARD16) UNWILLING;
        header.length = 4 + factory->priv->servhost.length + status.length;
        header.version = XDM_PROTOCOL_VERSION;
        XdmcpWriteHeader (&factory->priv->buf, &header);

        XdmcpWriteARRAY8 (&factory->priv->buf, &factory->priv->servhost);
        XdmcpWriteARRAY8 (&factory->priv->buf, &status);
        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        last_time = time (NULL);
}

#define SIN(__s)   ((struct sockaddr_in *) __s)
#define SIN6(__s)  ((struct sockaddr_in6 *) __s)

static void
set_port_for_request (GdmAddress *address,
                      ARRAY8     *port)
{
        struct sockaddr_storage *ss;

        ss = gdm_address_peek_sockaddr_storage (address);

        /* we depend on this being 2 elsewhere as well */
        port->length = 2;

        switch (ss->ss_family) {
        case AF_INET:
                port->data = (CARD8 *)g_memdup (&(SIN (ss)->sin_port), port->length);
                break;
        case AF_INET6:
                port->data = (CARD8 *)g_memdup (&(SIN6 (ss)->sin6_port), port->length);
                break;
        default:
                port->data = NULL;
                break;
        }
}

static void
set_address_for_request (GdmAddress *address,
                         ARRAY8     *addr)
{
        struct sockaddr_storage *ss;

        ss = gdm_address_peek_sockaddr_storage (address);

        switch (ss->ss_family) {
        case AF_INET:
                addr->length = sizeof (struct in_addr);
                addr->data = g_memdup (&SIN (ss)->sin_addr, addr->length);
                break;
        case AF_INET6:
                addr->length = sizeof (struct in6_addr);
                addr->data = g_memdup (&SIN6 (ss)->sin6_addr, addr->length);
                break;
        default:
                addr->length = 0;
                addr->data = NULL;
                break;
        }

}

static void
gdm_xdmcp_send_forward_query (GdmXdmcpDisplayFactory         *factory,
                              GdmIndirectDisplay      *id,
                              GdmAddress              *address,
                              GdmAddress              *display_address,
                              ARRAYofARRAY8Ptr         authlist)
{
        XdmcpHeader              header;
        int                      i;
        ARRAY8                   addr;
        ARRAY8                   port;
        char                    *host;
        char                    *serv;

        g_assert (id != NULL);
        g_assert (id->chosen_host != NULL);

        host = NULL;
        gdm_address_get_numeric_info (id->chosen_host, &host, NULL);
        g_debug ("XDMCP: Sending forward query to %s",
                   host);
        g_free (host);

        host = NULL;
        serv = NULL;
        gdm_address_get_numeric_info (display_address, &host, &serv);
        g_debug ("gdm_xdmcp_send_forward_query: Query contains %s:%s",
                 host, serv);
        g_free (host);
        g_free (serv);

        set_port_for_request (address, &port);
        set_address_for_request (display_address, &addr);

        header.version = XDM_PROTOCOL_VERSION;
        header.opcode = (CARD16) FORWARD_QUERY;
        header.length = 0;
        header.length += 2 + addr.length;
        header.length += 2 + port.length;
        header.length += 1;
        for (i = 0; i < authlist->length; i++) {
                header.length += 2 + authlist->data[i].length;
        }

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteARRAY8 (&factory->priv->buf, &addr);
        XdmcpWriteARRAY8 (&factory->priv->buf, &port);
        XdmcpWriteARRAYofARRAY8 (&factory->priv->buf, authlist);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (id->chosen_host),
                    (int)sizeof (struct sockaddr_storage));

        g_free (port.data);
        g_free (addr.data);
}

static void
handle_any_query (GdmXdmcpDisplayFactory         *factory,
                  GdmAddress              *address,
                  ARRAYofARRAY8Ptr         authentication_names,
                  int                      type)
{
        gdm_xdmcp_send_willing (factory, address);
}

static void
handle_direct_query (GdmXdmcpDisplayFactory         *factory,
                     GdmAddress              *address,
                     int                      len,
                     int                      type)
{
        ARRAYofARRAY8 clnt_authlist;
        int           expected_len;
        int           i;
        int           res;

        res = XdmcpReadARRAYofARRAY8 (&factory->priv->buf, &clnt_authlist);
        if G_UNLIKELY (! res) {
                g_warning (_("Could not extract authlist from packet"));
                return;
        }

        expected_len = 1;

        for (i = 0 ; i < clnt_authlist.length ; i++) {
                expected_len += 2 + clnt_authlist.data[i].length;
        }

        if (len == expected_len) {
                handle_any_query (factory, address, &clnt_authlist, type);
        } else {
                g_warning (_("Error in checksum"));
        }

        XdmcpDisposeARRAYofARRAY8 (&clnt_authlist);
}

static void
gdm_xdmcp_handle_broadcast_query (GdmXdmcpDisplayFactory *factory,
                                  GdmAddress      *address,
                                  int              len)
{
        if (gdm_xdmcp_host_allow (address)) {
                handle_direct_query (factory, address, len, BROADCAST_QUERY);
        } else {
                /* just ignore it */
        }
}

static void
gdm_xdmcp_handle_query (GdmXdmcpDisplayFactory *factory,
                        GdmAddress      *address,
                        int              len)
{
        if (gdm_xdmcp_host_allow (address)) {
                handle_direct_query (factory, address, len, QUERY);
        } else {
                gdm_xdmcp_send_unwilling (factory, address, QUERY);
        }
}

static void
gdm_xdmcp_handle_indirect_query (GdmXdmcpDisplayFactory *factory,
                                 GdmAddress      *address,
                                 int              len)
{
        ARRAYofARRAY8       clnt_authlist;
        int                 expected_len;
        int                 i;
        int                 res;
        GdmIndirectDisplay *id;

        if (! gdm_xdmcp_host_allow (address)) {
                /* ignore the request */
                return;
        }

        if (! factory->priv->honor_indirect) {
                /* ignore it */
                return;
        }

        res = XdmcpReadARRAYofARRAY8 (&factory->priv->buf, &clnt_authlist);
        if G_UNLIKELY (! res) {
                g_warning (_("Could not extract authlist from packet"));
                return;
        }

        expected_len = 1;

        for (i = 0 ; i < clnt_authlist.length ; i++) {
                expected_len += 2 + clnt_authlist.data[i].length;
        }

        /* Try to look up the display in
         * the pending list. If found send a FORWARD_QUERY to the
         * chosen factory. Otherwise alloc a new indirect display. */

        if (len != expected_len) {
                g_warning (_("Error in checksum"));
                goto out;
        }


        id = gdm_choose_indirect_lookup (address);

        if (id != NULL && id->chosen_host != NULL) {
                /* if user chose us, then just send willing */
                if (gdm_address_is_local (id->chosen_host)) {
                        /* get rid of indirect, so that we don't get
                         * the chooser */
                        gdm_choose_indirect_dispose (id);
                        gdm_xdmcp_send_willing (factory, address);
                } else if (gdm_address_is_loopback (address)) {
                        /* woohoo! fun, I have no clue how to get
                         * the correct ip, SO I just send forward
                         * queries with all the different IPs */
                        const GList *list = gdm_address_peek_local_list ();

                        while (list != NULL) {
                                GdmAddress *saddr = list->data;

                                if (! gdm_address_is_loopback (saddr)) {
                                        /* forward query to * chosen host */
                                        gdm_xdmcp_send_forward_query (factory,
                                                                      id,
                                                                      address,
                                                                      saddr,
                                                                      &clnt_authlist);
                                }

                                list = list->next;
                        }
                } else {
                        /* or send forward query to chosen host */
                        gdm_xdmcp_send_forward_query (factory,
                                                      id,
                                                      address,
                                                      address,
                                                      &clnt_authlist);
                }
        } else if (id == NULL) {
                id = gdm_choose_indirect_alloc (address);
                if (id != NULL) {
                        gdm_xdmcp_send_willing (factory, address);
                }
        } else  {
                gdm_xdmcp_send_willing (factory, address);
        }

out:
        XdmcpDisposeARRAYofARRAY8 (&clnt_authlist);
}

static void
gdm_forward_query_dispose (GdmXdmcpDisplayFactory *factory,
                           GdmForwardQuery *q)
{
        if (q == NULL) {
                return;
        }

        factory->priv->forward_queries = g_slist_remove (factory->priv->forward_queries, q);

        q->acctime = 0;

        {
                char *host;

                host = NULL;
                gdm_address_get_numeric_info (q->dsp_address, &host, NULL);
                g_debug ("gdm_forward_query_dispose: Disposing %s", host);
                g_free (host);
        }

        g_free (q->dsp_address);
        q->dsp_address = NULL;
        g_free (q->from_address);
        q->from_address = NULL;

        g_free (q);
}

static gboolean
remove_oldest_forward (GdmXdmcpDisplayFactory *factory)
{
        GSList          *li;
        GdmForwardQuery *oldest = NULL;

        for (li = factory->priv->forward_queries; li != NULL; li = li->next) {
                GdmForwardQuery *query = li->data;

                if (oldest == NULL || query->acctime < oldest->acctime) {
                        oldest = query;
                }
        }

        if (oldest != NULL) {
                gdm_forward_query_dispose (factory, oldest);
                return TRUE;
        } else {
                return FALSE;
        }
}

static GdmForwardQuery *
gdm_forward_query_alloc (GdmXdmcpDisplayFactory *factory,
                         GdmAddress      *mgr_address,
                         GdmAddress      *dsp_address)
{
        GdmForwardQuery *q;
        int              count;

        count = g_slist_length (factory->priv->forward_queries);

        while (count > GDM_MAX_FORWARD_QUERIES && remove_oldest_forward (factory)) {
                count--;
        }

        q = g_new0 (GdmForwardQuery, 1);
        q->dsp_address = gdm_address_copy (dsp_address);
        q->from_address = gdm_address_copy (mgr_address);

        factory->priv->forward_queries = g_slist_prepend (factory->priv->forward_queries, q);

        return q;
}

static GdmForwardQuery *
gdm_forward_query_lookup (GdmXdmcpDisplayFactory *factory,
                          GdmAddress      *address)
{
        GSList          *li;
        GSList          *qlist;
        GdmForwardQuery *ret;
        time_t           curtime;

        curtime = time (NULL);
        ret = NULL;

        qlist = g_slist_copy (factory->priv->forward_queries);

        for (li = qlist; li != NULL; li = li->next) {
                GdmForwardQuery *q;
                char            *host;
                char            *serv;

                q = (GdmForwardQuery *) li->data;

                if (q == NULL) {
                        continue;
                }

                host = NULL;
                serv = NULL;
                gdm_address_get_numeric_info (q->dsp_address, &host, &serv);

                g_debug ("gdm_forward_query_lookup: comparing %s:%s", host, serv);
                if (gdm_address_equal (q->dsp_address, address)) {
                        ret = q;
                        g_free (host);
                        g_free (serv);
                        break;
                }

                if (q->acctime > 0 &&  curtime > q->acctime + GDM_FORWARD_QUERY_TIMEOUT) {
                        g_debug ("gdm_forward_query_lookup: Disposing stale forward query from %s:%s",
                                 host, serv);

                        gdm_forward_query_dispose (factory, q);
                }

                g_free (host);
                g_free (serv);
        }

        g_slist_free (qlist);

        if (ret == NULL) {
                char *host;

                host = NULL;
                gdm_address_get_numeric_info (address, &host, NULL);
                g_debug ("gdm_forward_query_lookup: Host %s not found",
                         host);
                g_free (host);
        }

        return ret;
}

static gboolean
create_address_from_request (ARRAY8      *req_addr,
                             ARRAY8      *req_port,
                             int          family,
                             GdmAddress **address)
{
        uint16_t         port;
        char             host_buf [NI_MAXHOST];
        char             serv_buf [NI_MAXSERV];
        char            *serv;
        const char      *host;
        struct addrinfo  hints;
        struct addrinfo *ai_list;
        struct addrinfo *ai;
        int              gaierr;
        gboolean         found;

        if (address != NULL) {
                *address = NULL;
        }

        if (req_addr == NULL) {
                return FALSE;
        }

        serv = NULL;
        if (req_port != NULL) {
                /* port must always be length 2 */
                if (req_port->length != 2) {
                        return FALSE;
                }

                memcpy (&port, req_port->data, 2);
                snprintf (serv_buf, sizeof (serv_buf), "%d", ntohs (port));
                serv = serv_buf;
        } else {
                /* assume XDM_UDP_PORT */
                snprintf (serv_buf, sizeof (serv_buf), "%d", XDM_UDP_PORT);
                serv = serv_buf;
        }

        host = NULL;
        if (req_addr->length == 4) {
                host = inet_ntop (AF_INET,
                                  (const void *)req_addr->data,
                                  host_buf,
                                  sizeof (host_buf));
        } else if (req_addr->length == 16) {
                host = inet_ntop (AF_INET6,
                                  (const void *)req_addr->data,
                                  host_buf,
                                  sizeof (host_buf));
        }

        if (host == NULL) {
                g_warning (_("Bad address"));
                return FALSE;
        }

        memset (&hints, 0, sizeof (hints));
        hints.ai_family = family;
        hints.ai_flags = AI_V4MAPPED; /* this should convert IPv4 address to IPv6 if needed */
        if ((gaierr = getaddrinfo (host, serv, &hints, &ai_list)) != 0) {
                g_warning ("Unable get address: %s", gai_strerror (gaierr));
                return FALSE;
        }

        /* just take the first one */
        ai = ai_list;

        found = FALSE;
        if (ai != NULL) {
                found = TRUE;
                if (address != NULL) {
                        *address = gdm_address_new_from_sockaddr_storage ((struct sockaddr_storage *)ai->ai_addr);
                }
        }

        freeaddrinfo (ai_list);

        return found;
}

static void
gdm_xdmcp_whack_queued_managed_forwards (GdmXdmcpDisplayFactory *factory,
                                         GdmAddress      *address,
                                         GdmAddress      *origin)
{
        GSList *li;

        for (li = factory->priv->managed_forwards; li != NULL; li = li->next) {
                ManagedForward *mf = li->data;

                if (gdm_address_equal (mf->manager, address) &&
                    gdm_address_equal (mf->origin, origin)) {
                        factory->priv->managed_forwards = g_slist_remove_link (factory->priv->managed_forwards, li);
                        g_slist_free_1 (li);
                        g_source_remove (mf->handler);
                        /* mf freed by glib */
                        return;
                }
        }
}

static void
gdm_xdmcp_handle_forward_query (GdmXdmcpDisplayFactory *factory,
                                GdmAddress      *address,
                                int              len)
{
        ARRAY8                   clnt_addr;
        ARRAY8                   clnt_port;
        ARRAYofARRAY8            clnt_authlist;
        int                      i;
        int                      explen;
        GdmAddress              *disp_address;
        char                    *host;
        char                    *serv;

        disp_address = NULL;

        /* Check with tcp_wrappers if client is allowed to access */
        if (! gdm_xdmcp_host_allow (address)) {
                char *host;

                host = NULL;
                gdm_address_get_numeric_info (address, &host, NULL);

                g_warning ("%s: Got FORWARD_QUERY from banned host %s",
                           "gdm_xdmcp_handle_forward query",
                           host);
                g_free (host);
                return;
        }

        /* Read display address */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_addr)) {
                g_warning (_("%s: Could not read display address"),
                           "gdm_xdmcp_handle_forward_query");
                return;
        }

        /* Read display port */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_port)) {
                XdmcpDisposeARRAY8 (&clnt_addr);
                g_warning (_("%s: Could not read display port number"),
                           "gdm_xdmcp_handle_forward_query");
                return;
        }

        /* Extract array of authentication names from Xdmcp packet */
        if G_UNLIKELY (! XdmcpReadARRAYofARRAY8 (&factory->priv->buf, &clnt_authlist)) {
                XdmcpDisposeARRAY8 (&clnt_addr);
                XdmcpDisposeARRAY8 (&clnt_port);
                g_warning (_("%s: Could not extract authlist from packet"),
                           "gdm_xdmcp_handle_forward_query");
                return;
        }

        /* Crude checksumming */
        explen = 1;
        explen += 2 + clnt_addr.length;
        explen += 2 + clnt_port.length;

        for (i = 0 ; i < clnt_authlist.length ; i++) {
                char *s = g_strndup ((char *) clnt_authlist.data[i].data,
                                     clnt_authlist.length);
                g_debug ("gdm_xdmcp_handle_forward_query: authlist: %s", s);
                g_free (s);

                explen += 2 + clnt_authlist.data[i].length;
        }

        if G_UNLIKELY (len != explen) {
                g_warning (_("%s: Error in checksum"),
                           "gdm_xdmcp_handle_forward_query");
                goto out;
        }

        if (! create_address_from_request (&clnt_addr, &clnt_port, gdm_address_get_family_type (address), &disp_address)) {
                g_warning ("Unable to parse address for request");
                goto out;
        }

        gdm_xdmcp_whack_queued_managed_forwards (factory,
                                                 address,
                                                 disp_address);

        host = NULL;
        serv = NULL;
        gdm_address_get_numeric_info (disp_address, &host, &serv);
        g_debug ("gdm_xdmcp_handle_forward_query: Got FORWARD_QUERY for display: %s, port %s",
                 host, serv);
        g_free (host);
        g_free (serv);

        /* Check with tcp_wrappers if display is allowed to access */
        if (gdm_xdmcp_host_allow (disp_address)) {
                GdmForwardQuery *q;

                q = gdm_forward_query_lookup (factory, disp_address);
                if (q != NULL) {
                        gdm_forward_query_dispose (factory, q);
                }

                gdm_forward_query_alloc (factory, address, disp_address);

                gdm_xdmcp_send_willing (factory, disp_address);
        }

 out:

        gdm_address_free (disp_address);

        XdmcpDisposeARRAYofARRAY8 (&clnt_authlist);
        XdmcpDisposeARRAY8 (&clnt_port);
        XdmcpDisposeARRAY8 (&clnt_addr);
}

static void
gdm_xdmcp_really_send_managed_forward (GdmXdmcpDisplayFactory *factory,
                                       GdmAddress      *address,
                                       GdmAddress      *origin)
{
        ARRAY8      addr;
        XdmcpHeader header;
        char       *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Sending MANAGED_FORWARD to %s", host);
        g_free (host);

        set_address_for_request (origin, &addr);

        header.opcode = (CARD16) GDM_XDMCP_MANAGED_FORWARD;
        header.length = 4 + addr.length;
        header.version = GDM_XDMCP_PROTOCOL_VERSION;
        XdmcpWriteHeader (&factory->priv->buf, &header);

        XdmcpWriteARRAY8 (&factory->priv->buf, &addr);
        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        g_free (addr.data);
}

static gboolean
managed_forward_handler (ManagedForward *mf)
{
        if (mf->xdmcp_display_factory->priv->socket_fd > 0) {
                gdm_xdmcp_really_send_managed_forward (mf->xdmcp_display_factory,
                                                       mf->manager,
                                                       mf->origin);
        }

        mf->times++;
        if (mf->xdmcp_display_factory->priv->socket_fd <= 0 || mf->times >= 2) {
                mf->xdmcp_display_factory->priv->managed_forwards = g_slist_remove (mf->xdmcp_display_factory->priv->managed_forwards, mf);
                mf->handler = 0;
                /* mf freed by glib */
                return FALSE;
        }
        return TRUE;
}

static void
managed_forward_free (ManagedForward *mf)
{
        gdm_address_free (mf->origin);
        gdm_address_free (mf->manager);
        g_free (mf);
}

static void
gdm_xdmcp_send_managed_forward (GdmXdmcpDisplayFactory *factory,
                                GdmAddress      *address,
                                GdmAddress      *origin)
{
        ManagedForward *mf;

        gdm_xdmcp_really_send_managed_forward (factory, address, origin);

        mf = g_new0 (ManagedForward, 1);
        mf->times = 0;
        mf->xdmcp_display_factory = factory;

        mf->manager = gdm_address_copy (address);
        mf->origin = gdm_address_copy (origin);

        mf->handler = g_timeout_add_full (G_PRIORITY_DEFAULT,
                                          MANAGED_FORWARD_INTERVAL,
                                          (GSourceFunc)managed_forward_handler,
                                          mf,
                                          (GDestroyNotify)managed_forward_free);
        factory->priv->managed_forwards = g_slist_prepend (factory->priv->managed_forwards, mf);
}

static void
gdm_xdmcp_send_got_managed_forward (GdmXdmcpDisplayFactory *factory,
                                    GdmAddress      *address,
                                    GdmAddress      *origin)
{
        ARRAY8      addr;
        XdmcpHeader header;
        char       *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Sending GOT_MANAGED_FORWARD to %s", host);
        g_free (host);

        set_address_for_request (origin, &addr);

        header.opcode = (CARD16) GDM_XDMCP_GOT_MANAGED_FORWARD;
        header.length = 4 + addr.length;
        header.version = GDM_XDMCP_PROTOCOL_VERSION;
        XdmcpWriteHeader (&factory->priv->buf, &header);

        XdmcpWriteARRAY8 (&factory->priv->buf, &addr);
        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));
}

static gboolean
count_sessions (const char      *id,
                GdmDisplay      *display,
                GdmXdmcpDisplayFactory *factory)
{
        if (GDM_IS_XDMCP_DISPLAY (display)) {
                int status;

                status = gdm_display_get_status (display);

                if (status == GDM_DISPLAY_MANAGED) {
                        factory->priv->num_sessions++;
                } else if (status == GDM_DISPLAY_UNMANAGED) {
                        factory->priv->num_pending_sessions++;
                }
        }

        return TRUE;
}

static void
gdm_xdmcp_recount_sessions (GdmXdmcpDisplayFactory *factory)
{
        GdmDisplayStore *store;

        factory->priv->num_sessions = 0;
        factory->priv->num_pending_sessions = 0;

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        gdm_display_store_foreach (store,
                                   (GdmDisplayStoreFunc)count_sessions,
                                   factory);
}

static gboolean
purge_displays (const char      *id,
                GdmDisplay      *display,
                GdmXdmcpDisplayFactory *factory)
{
        if (GDM_IS_XDMCP_DISPLAY (display)) {
                int status;
                time_t currtime;
                time_t acctime;

                currtime = time (NULL);
                status = gdm_display_get_status (display);
                acctime = gdm_display_get_creation_time (display);

                if (status == GDM_DISPLAY_UNMANAGED &&
                    currtime > acctime + factory->priv->max_wait) {
                        /* return TRUE to remove display */
                        return TRUE;
                }
        }

        return FALSE;
}

static void
gdm_xdmcp_displays_purge (GdmXdmcpDisplayFactory *factory)
{
        GdmDisplayStore *store;

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));

        gdm_display_store_foreach_remove (store,
                                          (GdmDisplayStoreFunc)purge_displays,
                                          factory);

        gdm_xdmcp_recount_sessions (factory);
}

typedef struct {
        const char *hostname;
        int         display_num;
} RemoveHostData;

static gboolean
remove_host (const char     *id,
             GdmDisplay     *display,
             RemoveHostData *data)
{
        char *hostname;
        int   disp_num;

        if (! GDM_IS_XDMCP_DISPLAY (display)) {
                return FALSE;
        }

        gdm_display_get_remote_hostname (display, &hostname, NULL);
        gdm_display_get_x11_display_number (display, &disp_num, NULL);

        if (disp_num == data->display_num &&
            hostname != NULL &&
            data->hostname != NULL &&
            strcmp (hostname, data->hostname) == 0) {
                /* return TRUE to remove */
                return TRUE;
        }

        return FALSE;
}

static void
display_dispose_check (GdmXdmcpDisplayFactory *factory,
                       const char      *hostname,
                       int              display_num)
{
        RemoveHostData  *data;
        GdmDisplayStore *store;

        if (hostname == NULL) {
                return;
        }

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));

        g_debug ("display_dispose_check (%s:%d)", hostname, display_num);

        data = g_new0 (RemoveHostData, 1);
        data->hostname = hostname;
        data->display_num = display_num;
        gdm_display_store_foreach_remove (store,
                                          (GdmDisplayStoreFunc)remove_host,
                                          data);
        g_free (data);

        gdm_xdmcp_recount_sessions (factory);
}

static void
gdm_xdmcp_send_decline (GdmXdmcpDisplayFactory *factory,
                        GdmAddress      *address,
                        const char      *reason)
{
        XdmcpHeader      header;
        ARRAY8           authentype;
        ARRAY8           authendata;
        ARRAY8           status;
        GdmForwardQuery *fq;
        char            *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XMDCP: Sending DECLINE to %s", host);
        g_free (host);

        authentype.data   = (CARD8 *) 0;
        authentype.length = (CARD16)  0;

        authendata.data   = (CARD8 *) 0;
        authendata.length = (CARD16)  0;

        status.data       = (CARD8 *) reason;
        status.length     = strlen ((char *) status.data);

        header.version    = XDM_PROTOCOL_VERSION;
        header.opcode     = (CARD16) DECLINE;
        header.length     = 2 + status.length;
        header.length    += 2 + authentype.length;
        header.length    += 2 + authendata.length;

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteARRAY8 (&factory->priv->buf, &status);
        XdmcpWriteARRAY8 (&factory->priv->buf, &authentype);
        XdmcpWriteARRAY8 (&factory->priv->buf, &authendata);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        /* Send MANAGED_FORWARD to indicate that the connection
         * reached some sort of resolution */
        fq = gdm_forward_query_lookup (factory, address);
        if (fq != NULL) {
                gdm_xdmcp_send_managed_forward (factory, fq->from_address, address);
                gdm_forward_query_dispose (factory, fq);
        }
}

static GdmDisplay *
gdm_xdmcp_display_alloc (GdmXdmcpDisplayFactory *factory,
                         const char             *hostname,
                         GdmAddress             *address,
                         int                     displaynum)
{
        GdmDisplay      *display;
        GdmDisplayStore *store;

        g_debug ("Creating xdmcp display for %s:%d", hostname, displaynum);

        display = gdm_xdmcp_display_new (hostname,
                                         displaynum,
                                         address,
                                         get_next_session_serial (factory));
        if (display == NULL) {
                goto out;
        }

        if (! gdm_display_create_authority (display)) {
                g_object_unref (display);
                display = NULL;
                goto out;
        }

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        gdm_display_store_add (store, display);

        factory->priv->num_pending_sessions++;
 out:

        return display;
}

static void
gdm_xdmcp_send_accept (GdmXdmcpDisplayFactory *factory,
                       GdmAddress             *address,
                       CARD32                  session_id,
                       ARRAY8Ptr               authentication_name,
                       ARRAY8Ptr               authentication_data,
                       ARRAY8Ptr               authorization_name,
                       ARRAY8Ptr               authorization_data)
{
        XdmcpHeader header;
        char       *host;

        header.version    = XDM_PROTOCOL_VERSION;
        header.opcode     = (CARD16) ACCEPT;
        header.length     = 4;
        header.length    += 2 + authentication_name->length;
        header.length    += 2 + authentication_data->length;
        header.length    += 2 + authorization_name->length;
        header.length    += 2 + authorization_data->length;

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteCARD32 (&factory->priv->buf, session_id);
        XdmcpWriteARRAY8 (&factory->priv->buf, authentication_name);
        XdmcpWriteARRAY8 (&factory->priv->buf, authentication_data);
        XdmcpWriteARRAY8 (&factory->priv->buf, authorization_name);
        XdmcpWriteARRAY8 (&factory->priv->buf, authorization_data);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Sending ACCEPT to %s with SessionID=%ld",
                 host,
                 (long)session_id);
        g_free (host);
}

static void
gdm_xdmcp_handle_request (GdmXdmcpDisplayFactory *factory,
                          GdmAddress      *address,
                          int              len)
{
        CARD16        clnt_dspnum;
        ARRAY16       clnt_conntyp;
        ARRAYofARRAY8 clnt_addr;
        ARRAY8        clnt_authname;
        ARRAY8        clnt_authdata;
        ARRAYofARRAY8 clnt_authorization_names;
        ARRAY8        clnt_manufacturer;
        int           explen;
        int           i;
        gboolean      mitauth;
        gboolean      entered;
        char         *hostname;

        mitauth = FALSE;
        entered = FALSE;

        hostname = NULL;
        gdm_address_get_numeric_info (address, &hostname, NULL);
        g_debug ("gdm_xdmcp_handle_request: Got REQUEST from %s", hostname);

        /* Check with tcp_wrappers if client is allowed to access */
        if (! gdm_xdmcp_host_allow (address)) {
                g_warning (_("%s: Got REQUEST from banned host %s"),
                           "gdm_xdmcp_handle_request",
                           hostname);
                goto out;
        }

        gdm_xdmcp_displays_purge (factory); /* Purge pending displays */

        /* Remote display number */
        if G_UNLIKELY (! XdmcpReadCARD16 (&factory->priv->buf, &clnt_dspnum)) {
                g_warning (_("%s: Could not read Display Number"),
                           "gdm_xdmcp_handle_request");
                goto out;
        }

        /* We don't care about connection type. Address says it all */
        if G_UNLIKELY (! XdmcpReadARRAY16 (&factory->priv->buf, &clnt_conntyp)) {
                g_warning (_("%s: Could not read Connection Type"),
                           "gdm_xdmcp_handle_request");
                goto out;
        }

        /* This is TCP/IP - we don't care */
        if G_UNLIKELY (! XdmcpReadARRAYofARRAY8 (&factory->priv->buf, &clnt_addr)) {
                g_warning (_("%s: Could not read Client Address"),
                           "gdm_xdmcp_handle_request");
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                goto out;
        }

        /* Read authentication type */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_authname)) {
                g_warning (_("%s: Could not read Authentication Names"),
                           "gdm_xdmcp_handle_request");
                XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                goto out;
        }

        /* Read authentication data */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_authdata)) {
                g_warning (_("%s: Could not read Authentication Data"),
                           "gdm_xdmcp_handle_request");
                XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                XdmcpDisposeARRAY8 (&clnt_authname);
                goto out;
        }

        /* Read and select from supported authorization list */
        if G_UNLIKELY (! XdmcpReadARRAYofARRAY8 (&factory->priv->buf, &clnt_authorization_names)) {
                g_warning (_("%s: Could not read Authorization List"),
                           "gdm_xdmcp_handle_request");
                XdmcpDisposeARRAY8 (&clnt_authdata);
                XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                XdmcpDisposeARRAY8 (&clnt_authname);
                goto out;
        }

        /* libXdmcp doesn't terminate strings properly so we cheat and use strncmp () */
        for (i = 0 ; i < clnt_authorization_names.length ; i++) {
                if (clnt_authorization_names.data[i].length == 18 &&
                    strncmp ((char *) clnt_authorization_names.data[i].data, "MIT-MAGIC-COOKIE-1", 18) == 0) {
                        mitauth = TRUE;
                }
        }

        /* Manufacturer ID */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_manufacturer)) {
                g_warning (_("%s: Could not read Manufacturer ID"),
                           "gdm_xdmcp_handle_request");
                XdmcpDisposeARRAY8 (&clnt_authname);
                XdmcpDisposeARRAY8 (&clnt_authdata);
                XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
                XdmcpDisposeARRAYofARRAY8 (&clnt_authorization_names);
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                goto out;
        }

        /* Crude checksumming */
        explen = 2;                 /* Display Number */
        explen += 1 + 2 * clnt_conntyp.length; /* Connection Type */
        explen += 1;                /* Connection Address */
        for (i = 0 ; i < clnt_addr.length ; i++) {
                explen += 2 + clnt_addr.data[i].length;
        }
        explen += 2 + clnt_authname.length; /* Authentication Name */
        explen += 2 + clnt_authdata.length; /* Authentication Data */
        explen += 1;                /* Authorization Names */
        for (i = 0 ; i < clnt_authorization_names.length ; i++) {
                explen += 2 + clnt_authorization_names.data[i].length;
        }

        explen += 2 + clnt_manufacturer.length;

        if G_UNLIKELY (explen != len) {
                g_warning (_("%s: Failed checksum from %s"),
                           "gdm_xdmcp_handle_request",
                           hostname);

                XdmcpDisposeARRAY8 (&clnt_authname);
                XdmcpDisposeARRAY8 (&clnt_authdata);
                XdmcpDisposeARRAY8 (&clnt_manufacturer);
                XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
                XdmcpDisposeARRAYofARRAY8 (&clnt_authorization_names);
                XdmcpDisposeARRAY16 (&clnt_conntyp);
                goto out;
        }

        {
                char *s = g_strndup ((char *) clnt_manufacturer.data, clnt_manufacturer.length);
                g_debug ("gdm_xdmcp_handle_request: xdmcp_pending=%d, MaxPending=%d, xdmcp_sessions=%d, MaxSessions=%d, ManufacturerID=%s",
                         factory->priv->num_pending_sessions,
                         factory->priv->max_pending_displays,
                         factory->priv->num_sessions,
                         factory->priv->max_displays,
                         ve_sure_string (s));
                g_free (s);
        }

        /* Check if ok to manage display */
        if (mitauth &&
            factory->priv->num_sessions < factory->priv->max_displays &&
            (gdm_address_is_local (address) ||
             gdm_xdmcp_num_displays_from_host (factory, address) < factory->priv->max_displays_per_host)) {
                entered = TRUE;
        }

        if (entered) {

                /* Check if we are already talking to this host */
                display_dispose_check (factory, hostname, clnt_dspnum);

                if (factory->priv->num_pending_sessions >= factory->priv->max_pending_displays) {
                        g_debug ("gdm_xdmcp_handle_request: maximum pending");
                        /* Don't translate, this goes over the wire to servers where we
                         * don't know the charset or language, so it must be ascii */
                        gdm_xdmcp_send_decline (factory, address, "Maximum pending servers");
                } else {
                        GdmDisplay *display;

                        display = gdm_xdmcp_display_alloc (factory,
                                                           hostname,
                                                           address,
                                                           clnt_dspnum);

                        if (display != NULL) {
                                ARRAY8 authentication_name;
                                ARRAY8 authentication_data;
                                ARRAY8 authorization_name;
                                ARRAY8 authorization_data;
                                gint32 session_number;
                                char    *x11_cookie;
                                GString *cookie;
                                GString *binary_cookie;
                                GString *test_cookie;

                                gdm_display_get_x11_cookie (display, &x11_cookie, NULL);
                                cookie = g_string_new (x11_cookie);
                                g_free (x11_cookie);

                                binary_cookie = g_string_new (NULL);

                                if (! gdm_string_hex_decode (cookie,
                                                             0,
                                                             NULL,
                                                             binary_cookie,
                                                             0)) {
                                        g_warning ("Unable to decode hex cookie");
                                        /* FIXME: handle error */
                                }

                                test_cookie = g_string_new (NULL);
                                if (! gdm_string_hex_encode (binary_cookie,
                                                             0,
                                                             test_cookie,
                                                             0)) {
                                        g_warning ("Unable to encode hex cookie");
                                        /* FIXME: handle error */
                                }

                                /* sanity check cookie */
                                g_debug ("Reencoded cookie len:%d '%s'", test_cookie->len, test_cookie->str);
                                g_assert (test_cookie->len == cookie->len);
                                g_assert (strcmp (test_cookie->str, cookie->str) == 0);
                                g_string_free (test_cookie, TRUE);

                                g_debug ("Sending authorization key for display %s", cookie->str);
                                g_debug ("Decoded cookie len %d", binary_cookie->len);

                                session_number = gdm_xdmcp_display_get_session_number (GDM_XDMCP_DISPLAY (display));

                                /* the send accept will fail if cookie is null */
                                g_assert (binary_cookie != NULL);

                                authentication_name.data   = NULL;
                                authentication_name.length = 0;
                                authentication_data.data   = NULL;
                                authentication_data.length = 0;

                                authorization_name.data     = (CARD8 *) "MIT-MAGIC-COOKIE-1";
                                authorization_name.length   = strlen ((char *) authorization_name.data);

                                authorization_data.data     = (CARD8 *) binary_cookie->str;
                                authorization_data.length   = binary_cookie->len;

                                /* the addrs are NOT copied */
                                gdm_xdmcp_send_accept (factory,
                                                       address,
                                                       session_number,
                                                       &authentication_name,
                                                       &authentication_data,
                                                       &authorization_name,
                                                       &authorization_data);

                                g_string_free (binary_cookie, TRUE);
                                g_string_free (cookie, TRUE);
                        }
                }
        } else {
                /* Don't translate, this goes over the wire to servers where we
                 * don't know the charset or language, so it must be ascii */
                if ( ! mitauth) {
                        gdm_xdmcp_send_decline (factory,
                                                address,
                                                "Only MIT-MAGIC-COOKIE-1 supported");
                } else if (factory->priv->num_sessions >= factory->priv->max_displays) {
                        g_warning ("Maximum number of open XDMCP sessions reached");
                        gdm_xdmcp_send_decline (factory,
                                                address,
                                                "Maximum number of open sessions reached");
                } else {
                        g_debug ("Maximum number of open XDMCP sessions from host %s reached",
                                 hostname);
                        gdm_xdmcp_send_decline (factory,
                                                address,
                                                "Maximum number of open sessions from your host reached");
                }
        }

        XdmcpDisposeARRAY8 (&clnt_authname);
        XdmcpDisposeARRAY8 (&clnt_authdata);
        XdmcpDisposeARRAY8 (&clnt_manufacturer);
        XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
        XdmcpDisposeARRAYofARRAY8 (&clnt_authorization_names);
        XdmcpDisposeARRAY16 (&clnt_conntyp);
 out:
        g_free (hostname);
}

static gboolean
lookup_by_session_id (const char *id,
                      GdmDisplay *display,
                      gpointer    data)
{
        CARD32 sessid;
        CARD32 session_id;

        sessid = GPOINTER_TO_INT (data);

        if (! GDM_IS_XDMCP_DISPLAY (display)) {
                return FALSE;
        }

        session_id = gdm_xdmcp_display_get_session_number (GDM_XDMCP_DISPLAY (display));

        if (session_id == sessid) {
                return TRUE;
        }

        return FALSE;
}

static GdmDisplay *
gdm_xdmcp_display_lookup (GdmXdmcpDisplayFactory *factory,
                          CARD32           sessid)
{
        GdmDisplay      *display;
        GdmDisplayStore *store;

        if (sessid == 0) {
                return NULL;
        }

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        display = gdm_display_store_find (store,
                                          (GdmDisplayStoreFunc)lookup_by_session_id,
                                          GINT_TO_POINTER (sessid));

        return display;
}

static void
gdm_xdmcp_send_failed (GdmXdmcpDisplayFactory *factory,
                       GdmAddress      *address,
                       CARD32           sessid)
{
        XdmcpHeader header;
        ARRAY8      status;

        g_debug ("XDMCP: Sending FAILED to %ld", (long)sessid);

        /*
         * Don't translate, this goes over the wire to servers where we
         * don't know the charset or language, so it must be ascii
         */
        status.data    = (CARD8 *) "Failed to start session";
        status.length  = strlen ((char *) status.data);

        header.version = XDM_PROTOCOL_VERSION;
        header.opcode  = (CARD16) FAILED;
        header.length  = 6 + status.length;

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteCARD32 (&factory->priv->buf, sessid);
        XdmcpWriteARRAY8 (&factory->priv->buf, &status);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));
}

static void
gdm_xdmcp_send_refuse (GdmXdmcpDisplayFactory *factory,
                       GdmAddress      *address,
                       CARD32           sessid)
{
        XdmcpHeader      header;
        GdmForwardQuery *fq;

        g_debug ("XDMCP: Sending REFUSE to %ld",
                 (long)sessid);

        header.version = XDM_PROTOCOL_VERSION;
        header.opcode  = (CARD16) REFUSE;
        header.length  = 4;

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteCARD32 (&factory->priv->buf, sessid);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));

        /*
         * This was from a forwarded query quite apparently so
         * send MANAGED_FORWARD
         */
        fq = gdm_forward_query_lookup (factory, address);
        if (fq != NULL) {
                gdm_xdmcp_send_managed_forward (factory, fq->from_address, address);
                gdm_forward_query_dispose (factory, fq);
        }
}

static void
gdm_xdmcp_handle_manage (GdmXdmcpDisplayFactory *factory,
                         GdmAddress      *address,
                         int              len)
{
        CARD32              clnt_sessid;
        CARD16              clnt_dspnum;
        ARRAY8              clnt_dspclass;
        GdmDisplay         *display;
        GdmForwardQuery    *fq;
        char               *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("gdm_xdmcp_handle_manage: Got MANAGE from %s", host);

        /* Check with tcp_wrappers if client is allowed to access */
        if (! gdm_xdmcp_host_allow (address)) {
                g_warning (_("%s: Got Manage from banned host %s"),
                           "gdm_xdmcp_handle_manage",
                           host);
                g_free (host);
                return;
        }

        /* SessionID */
        if G_UNLIKELY (! XdmcpReadCARD32 (&factory->priv->buf, &clnt_sessid)) {
                g_warning (_("%s: Could not read Session ID"),
                           "gdm_xdmcp_handle_manage");
                goto out;
        }

        /* Remote display number */
        if G_UNLIKELY (! XdmcpReadCARD16 (&factory->priv->buf, &clnt_dspnum)) {
                g_warning (_("%s: Could not read Display Number"),
                           "gdm_xdmcp_handle_manage");
                goto out;
        }

        /* Display Class */
        if G_UNLIKELY (! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_dspclass)) {
                g_warning (_("%s: Could not read Display Class"),
                           "gdm_xdmcp_handle_manage");
                goto out;
        }

        {
                char *s = g_strndup ((char *) clnt_dspclass.data, clnt_dspclass.length);
                g_debug ("gdm_xdmcp-handle_manage: Got display=%d, SessionID=%ld Class=%s from %s",
                         (int)clnt_dspnum,
                         (long)clnt_sessid,
                         ve_sure_string (s),
                         host);

                g_free (s);
        }

        display = gdm_xdmcp_display_lookup (factory, clnt_sessid);
        if (display != NULL &&
            gdm_display_get_status (display) == GDM_DISPLAY_UNMANAGED) {
                char *name;

                name = NULL;
                gdm_display_get_x11_display_name (display, &name, NULL);
                g_debug ("gdm_xdmcp_handle_manage: Looked up %s", name);
                g_free (name);

#if 0 /* FIXME: */
                if (factory->priv->honor_indirect) {
                        GdmIndirectDisplay *id;

                        id = gdm_choose_indirect_lookup (address);

                        /* This was an indirect thingie and nothing was yet chosen,
                         * use a chooser */
                        if (id != NULL &&
                            id->chosen_host == NULL) {
                                d->use_chooser = TRUE;
                                d->indirect_id = id->id;
                        } else {
                                d->indirect_id = 0;
                                d->use_chooser = FALSE;
                                if (id != NULL) {
                                        gdm_choose_indirect_dispose (id);
                                }
                        }
                } else {

                }
#endif
                /* this was from a forwarded query quite apparently so
                 * send MANAGED_FORWARD */
                fq = gdm_forward_query_lookup (factory, address);
                if (fq != NULL) {
                        gdm_xdmcp_send_managed_forward (factory, fq->from_address, address);
                        gdm_forward_query_dispose (factory, fq);
                }

                factory->priv->num_sessions++;
                factory->priv->num_pending_sessions--;

                /* Start greeter/session */
                if (! gdm_display_manage (display)) {
                        gdm_xdmcp_send_failed (factory, address, clnt_sessid);
                        g_debug ("Failed to manage display");
                }
        } else if (display != NULL &&
                   gdm_display_get_status (display) == GDM_DISPLAY_MANAGED) {
                g_debug ("gdm_xdmcp_handle_manage: Session id %ld already managed",
                         (long)clnt_sessid);
        } else {
                g_warning ("gdm_xdmcp_handle_manage: Failed to look up session id %ld",
                           (long)clnt_sessid);
                gdm_xdmcp_send_refuse (factory, address, clnt_sessid);
        }

 out:
        XdmcpDisposeARRAY8 (&clnt_dspclass);
        g_free (host);
}

static void
gdm_xdmcp_handle_managed_forward (GdmXdmcpDisplayFactory *factory,
                                  GdmAddress      *address,
                                  int              len)
{
        ARRAY8              clnt_address;
        GdmIndirectDisplay *id;
        char               *host;
        GdmAddress         *disp_address;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("gdm_xdmcp_handle_managed_forward: Got MANAGED_FORWARD from %s",
                   host);

        /* Check with tcp_wrappers if client is allowed to access */
        if (! gdm_xdmcp_host_allow (address)) {
                g_warning ("%s: Got MANAGED_FORWARD from banned host %s",
                           "gdm_xdmcp_handle_request", host);
                g_free (host);
                return;
        }
        g_free (host);

        /* Hostname */
        if G_UNLIKELY ( ! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_address)) {
                g_warning (_("%s: Could not read address"),
                           "gdm_xdmcp_handle_managed_forward");
                return;
        }

        disp_address = NULL;
        if (! create_address_from_request (&clnt_address, NULL, gdm_address_get_family_type (address), &disp_address)) {
                g_warning ("Unable to parse address for request");
                XdmcpDisposeARRAY8 (&clnt_address);
                return;
        }

        id = gdm_choose_indirect_lookup_by_chosen (address, disp_address);
        if (id != NULL) {
                gdm_choose_indirect_dispose (id);
        }

        /* Note: we send GOT even on not found, just in case our previous
         * didn't get through and this was a second managed forward */
        gdm_xdmcp_send_got_managed_forward (factory, address, disp_address);

        gdm_address_free (disp_address);

        XdmcpDisposeARRAY8 (&clnt_address);
}

static void
gdm_xdmcp_handle_got_managed_forward (GdmXdmcpDisplayFactory *factory,
                                      GdmAddress      *address,
                                      int              len)
{
        GdmAddress *disp_address;
        ARRAY8      clnt_address;
        char       *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("gdm_xdmcp_handle_got_managed_forward: Got MANAGED_FORWARD from %s",
                   host);

        if (! gdm_xdmcp_host_allow (address)) {
                g_warning ("%s: Got GOT_MANAGED_FORWARD from banned host %s",
                           "gdm_xdmcp_handle_request", host);
                g_free (host);
                return;
        }
        g_free (host);

        /* Hostname */
        if G_UNLIKELY ( ! XdmcpReadARRAY8 (&factory->priv->buf, &clnt_address)) {
                g_warning (_("%s: Could not read address"),
                           "gdm_xdmcp_handle_got_managed_forward");
                return;
        }

        if (! create_address_from_request (&clnt_address, NULL, gdm_address_get_family_type (address), &disp_address)) {
                g_warning (_("%s: Could not read address"),
                           "gdm_xdmcp_handle_got_managed_forward");
                XdmcpDisposeARRAY8 (&clnt_address);
                return;
        }

        gdm_xdmcp_whack_queued_managed_forwards (factory, address, disp_address);

        gdm_address_free (disp_address);

        XdmcpDisposeARRAY8 (&clnt_address);
}

static void
gdm_xdmcp_send_alive (GdmXdmcpDisplayFactory *factory,
                      GdmAddress      *address,
                      CARD16           dspnum,
                      CARD32           sessid)
{
        XdmcpHeader header;
        GdmDisplay *display;
        int         send_running = 0;
        CARD32      send_sessid = 0;

        display = gdm_xdmcp_display_lookup (factory, sessid);
        if (display == NULL) {
                display = gdm_xdmcp_display_lookup_by_host (factory, address, dspnum);
        }

        if (display != NULL) {
                int status;

                send_sessid = gdm_xdmcp_display_get_session_number (GDM_XDMCP_DISPLAY (display));
                status = gdm_display_get_status (display);

                if (status == GDM_DISPLAY_MANAGED) {
                        send_running = 1;
                }
        }

        g_debug ("XDMCP: Sending ALIVE to %ld (running %d, sessid %ld)",
                 (long)sessid,
                 send_running,
                 (long)send_sessid);

        header.version = XDM_PROTOCOL_VERSION;
        header.opcode = (CARD16) ALIVE;
        header.length = 5;

        XdmcpWriteHeader (&factory->priv->buf, &header);
        XdmcpWriteCARD8 (&factory->priv->buf, send_running);
        XdmcpWriteCARD32 (&factory->priv->buf, send_sessid);

        XdmcpFlush (factory->priv->socket_fd,
                    &factory->priv->buf,
                    (XdmcpNetaddr)gdm_address_peek_sockaddr_storage (address),
                    (int)sizeof (struct sockaddr_storage));
}

static void
gdm_xdmcp_handle_keepalive (GdmXdmcpDisplayFactory *factory,
                            GdmAddress      *address,
                            int              len)
{
        CARD16 clnt_dspnum;
        CARD32 clnt_sessid;
        char *host;

        host = NULL;
        gdm_address_get_numeric_info (address, &host, NULL);
        g_debug ("XDMCP: Got KEEPALIVE from %s", host);

        /* Check with tcp_wrappers if client is allowed to access */
        if (! gdm_xdmcp_host_allow (address)) {
                g_warning (_("%s: Got KEEPALIVE from banned host %s"),
                           "gdm_xdmcp_handle_keepalive",
                           host);
                g_free (host);
                return;
        }
        g_free (host);

        /* Remote display number */
        if G_UNLIKELY (! XdmcpReadCARD16 (&factory->priv->buf, &clnt_dspnum)) {
                g_warning (_("%s: Could not read Display Number"),
                           "gdm_xdmcp_handle_keepalive");
                return;
        }

        /* SessionID */
        if G_UNLIKELY (! XdmcpReadCARD32 (&factory->priv->buf, &clnt_sessid)) {
                g_warning (_("%s: Could not read Session ID"),
                           "gdm_xdmcp_handle_keepalive");
                return;
        }

        gdm_xdmcp_send_alive (factory, address, clnt_dspnum, clnt_sessid);
}

static const char *
opcode_string (int opcode)
{
        static const char * const opcode_names[] = {
                NULL,
                "BROADCAST_QUERY",
                "QUERY",
                "INDIRECT_QUERY",
                "FORWARD_QUERY",
                "WILLING",
                "UNWILLING",
                "REQUEST",
                "ACCEPT",
                "DECLINE",
                "MANAGE",
                "REFUSE",
                "FAILED",
                "KEEPALIVE",
                "ALIVE"
        };
        static const char * const gdm_opcode_names[] = {
                "MANAGED_FORWARD",
                "GOT_MANAGED_FORWARD"
        };


        if (opcode < G_N_ELEMENTS (opcode_names)) {
                return opcode_names [opcode];
        } else if (opcode >= GDM_XDMCP_FIRST_OPCODE &&
                   opcode < GDM_XDMCP_LAST_OPCODE) {
                return gdm_opcode_names [opcode - GDM_XDMCP_FIRST_OPCODE];
        } else {
                return "UNKNOWN";
        }
}

static gboolean
decode_packet (GIOChannel             *source,
               GIOCondition            cond,
               GdmXdmcpDisplayFactory *factory)
{
        struct sockaddr_storage clnt_ss;
        GdmAddress             *address;
        gint                    ss_len;
        XdmcpHeader             header;
        char                   *host;
        char                   *port;
        int                     res;

        g_debug ("decode_packet: GIOCondition %d", (int)cond);

        if ( ! (cond & G_IO_IN)) {
                return TRUE;
        }

        ss_len = sizeof (clnt_ss);
        res = XdmcpFill (factory->priv->socket_fd, &factory->priv->buf, (XdmcpNetaddr)&clnt_ss, &ss_len);
        if G_UNLIKELY (! res) {
                g_debug (_("XMCP: Could not create XDMCP buffer!"));
                return TRUE;
        }

        res = XdmcpReadHeader (&factory->priv->buf, &header);
        if G_UNLIKELY (! res) {
                g_warning (_("XDMCP: Could not read XDMCP header!"));
                return TRUE;
        }

        if G_UNLIKELY (header.version != XDM_PROTOCOL_VERSION &&
                       header.version != GDM_XDMCP_PROTOCOL_VERSION) {
                g_warning (_("XMDCP: Incorrect XDMCP version!"));
                return TRUE;
        }

        address = gdm_address_new_from_sockaddr_storage (&clnt_ss);
        if (address == NULL) {
                g_warning (_("XMDCP: Unable to parse address"));
                return TRUE;
        }

        gdm_address_debug (address);

        host = NULL;
        port = NULL;
        gdm_address_get_numeric_info (address, &host, &port);

        g_debug ("XDMCP: Received opcode %s from client %s : %s",
                 opcode_string (header.opcode),
                 host,
                 port);

        switch (header.opcode) {
        case BROADCAST_QUERY:
                gdm_xdmcp_handle_broadcast_query (factory, address, header.length);
                break;

        case QUERY:
                gdm_xdmcp_handle_query (factory, address, header.length);
                break;

        case INDIRECT_QUERY:
                gdm_xdmcp_handle_indirect_query (factory, address, header.length);
                break;

        case FORWARD_QUERY:
                gdm_xdmcp_handle_forward_query (factory, address, header.length);
                break;

        case REQUEST:
                gdm_xdmcp_handle_request (factory, address, header.length);
                break;

        case MANAGE:
                gdm_xdmcp_handle_manage (factory, address, header.length);
                break;

        case KEEPALIVE:
                gdm_xdmcp_handle_keepalive (factory, address, header.length);
                break;

        case GDM_XDMCP_MANAGED_FORWARD:
                gdm_xdmcp_handle_managed_forward (factory, address, header.length);
                break;

        case GDM_XDMCP_GOT_MANAGED_FORWARD:
                gdm_xdmcp_handle_got_managed_forward (factory, address, header.length);
                break;

        default:
                g_debug ("XDMCP: Unknown opcode from client %s : %s",
                         host,
                         port);

                break;
        }

        g_free (host);
        g_free (port);

        gdm_address_free (address);

        return TRUE;
}

static gboolean
gdm_xdmcp_display_factory_start (GdmDisplayFactory *base_factory)
{
        gboolean                ret;
        GIOChannel             *ioc;
        GdmXdmcpDisplayFactory *factory = GDM_XDMCP_DISPLAY_FACTORY (base_factory);

        g_return_val_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory), FALSE);
        g_return_val_if_fail (factory->priv->socket_fd == -1, FALSE);

        ret = open_port (factory);
        if (! ret) {
                return ret;
        }

        g_debug ("XDMCP: Starting to listen on XDMCP port");

        ioc = g_io_channel_unix_new (factory->priv->socket_fd);

        g_io_channel_set_encoding (ioc, NULL, NULL);
        g_io_channel_set_buffered (ioc, FALSE);

        factory->priv->socket_watch_id = g_io_add_watch_full (ioc,
                                                              G_PRIORITY_DEFAULT,
                                                              G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
                                                              (GIOFunc)decode_packet,
                                                              factory,
                                                              NULL);
        g_io_channel_unref (ioc);

        return ret;
}

static gboolean
gdm_xdmcp_display_factory_stop (GdmDisplayFactory *base_factory)
{
        GdmXdmcpDisplayFactory *factory = GDM_XDMCP_DISPLAY_FACTORY (base_factory);

        g_return_val_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory), FALSE);
        g_return_val_if_fail (factory->priv->socket_fd != -1, FALSE);

        if (factory->priv->socket_watch_id > 0) {
                g_source_remove (factory->priv->socket_watch_id);
                factory->priv->socket_watch_id = 0;
        }

        if (factory->priv->socket_fd > 0) {
                VE_IGNORE_EINTR (close (factory->priv->socket_fd));
                factory->priv->socket_fd = -1;
        }

        return TRUE;
}

void
gdm_xdmcp_display_factory_set_port (GdmXdmcpDisplayFactory *factory,
                                    guint                   port)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->port = port;
}

static void
gdm_xdmcp_display_factory_set_use_multicast (GdmXdmcpDisplayFactory *factory,
                                             gboolean                use_multicast)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->use_multicast = use_multicast;
}

static void
gdm_xdmcp_display_factory_set_multicast_address (GdmXdmcpDisplayFactory *factory,
                                                 const char             *address)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        g_free (factory->priv->multicast_address);
        factory->priv->multicast_address = g_strdup (address);
}

static void
gdm_xdmcp_display_factory_set_honor_indirect (GdmXdmcpDisplayFactory *factory,
                                              gboolean                honor_indirect)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->honor_indirect = honor_indirect;
}

static void
gdm_xdmcp_display_factory_set_max_displays_per_host (GdmXdmcpDisplayFactory *factory,
                                                     guint                   num)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->max_displays_per_host = num;
}

static void
gdm_xdmcp_display_factory_set_max_displays (GdmXdmcpDisplayFactory *factory,
                                            guint                   num)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->max_displays = num;
}

static void
gdm_xdmcp_display_factory_set_max_pending_displays (GdmXdmcpDisplayFactory *factory,
                                                    guint                   num)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->max_pending_displays = num;
}

static void
gdm_xdmcp_display_factory_set_max_wait (GdmXdmcpDisplayFactory *factory,
                                        guint                   num)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        factory->priv->max_wait = num;
}

static void
gdm_xdmcp_display_factory_set_willing_script (GdmXdmcpDisplayFactory *factory,
                                              const char             *script)
{
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (factory));

        g_free (factory->priv->willing_script);
        factory->priv->willing_script = g_strdup (script);
}

static void
gdm_xdmcp_display_factory_set_property (GObject       *object,
                                        guint          prop_id,
                                        const GValue  *value,
                                        GParamSpec    *pspec)
{
        GdmXdmcpDisplayFactory *self;

        self = GDM_XDMCP_DISPLAY_FACTORY (object);

        switch (prop_id) {
        case PROP_PORT:
                gdm_xdmcp_display_factory_set_port (self, g_value_get_uint (value));
                break;
        case PROP_USE_MULTICAST:
                gdm_xdmcp_display_factory_set_use_multicast (self, g_value_get_boolean (value));
                break;
        case PROP_MULTICAST_ADDRESS:
                gdm_xdmcp_display_factory_set_multicast_address (self, g_value_get_string (value));
                break;
        case PROP_HONOR_INDIRECT:
                gdm_xdmcp_display_factory_set_honor_indirect (self, g_value_get_boolean (value));
                break;
        case PROP_MAX_DISPLAYS_PER_HOST:
                gdm_xdmcp_display_factory_set_max_displays_per_host (self, g_value_get_uint (value));
                break;
        case PROP_MAX_DISPLAYS:
                gdm_xdmcp_display_factory_set_max_displays (self, g_value_get_uint (value));
                break;
        case PROP_MAX_PENDING_DISPLAYS:
                gdm_xdmcp_display_factory_set_max_pending_displays (self, g_value_get_uint (value));
                break;
        case PROP_MAX_WAIT:
                gdm_xdmcp_display_factory_set_max_wait (self, g_value_get_uint (value));
                break;
        case PROP_WILLING_SCRIPT:
                gdm_xdmcp_display_factory_set_willing_script (self, g_value_get_string (value));
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
gdm_xdmcp_display_factory_get_property (GObject    *object,
                                        guint       prop_id,
                                        GValue     *value,
                                        GParamSpec *pspec)
{
        GdmXdmcpDisplayFactory *self;

        self = GDM_XDMCP_DISPLAY_FACTORY (object);

        switch (prop_id) {
        case PROP_PORT:
                g_value_set_uint (value, self->priv->port);
                break;
        case PROP_USE_MULTICAST:
                g_value_set_boolean (value, self->priv->use_multicast);
                break;
        case PROP_MULTICAST_ADDRESS:
                g_value_set_string (value, self->priv->multicast_address);
                break;
        case PROP_HONOR_INDIRECT:
                g_value_set_boolean (value, self->priv->honor_indirect);
                break;
        case PROP_MAX_DISPLAYS_PER_HOST:
                g_value_set_uint (value, self->priv->max_displays_per_host);
                break;
        case PROP_MAX_DISPLAYS:
                g_value_set_uint (value, self->priv->max_displays);
                break;
        case PROP_MAX_PENDING_DISPLAYS:
                g_value_set_uint (value, self->priv->max_pending_displays);
                break;
        case PROP_MAX_WAIT:
                g_value_set_uint (value, self->priv->max_wait);
                break;
        case PROP_WILLING_SCRIPT:
                g_value_set_string (value, self->priv->willing_script);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
gdm_xdmcp_display_factory_class_init (GdmXdmcpDisplayFactoryClass *klass)
{
        GObjectClass           *object_class = G_OBJECT_CLASS (klass);
        GdmDisplayFactoryClass *factory_class = GDM_DISPLAY_FACTORY_CLASS (klass);

        object_class->get_property = gdm_xdmcp_display_factory_get_property;
        object_class->set_property = gdm_xdmcp_display_factory_set_property;
        object_class->finalize = gdm_xdmcp_display_factory_finalize;

        factory_class->start = gdm_xdmcp_display_factory_start;
        factory_class->stop = gdm_xdmcp_display_factory_stop;

        g_object_class_install_property (object_class,
                                         PROP_PORT,
                                         g_param_spec_uint ("port",
                                                            "UDP port",
                                                            "UDP port",
                                                            0,
                                                            G_MAXINT,
                                                            DEFAULT_PORT,
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_USE_MULTICAST,
                                         g_param_spec_boolean ("use-multicast",
                                                               NULL,
                                                               NULL,
                                                               DEFAULT_USE_MULTICAST,
                                                               G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_MULTICAST_ADDRESS,
                                         g_param_spec_string ("multicast-address",
                                                              "multicast-address",
                                                              "multicast-address",
                                                              DEFAULT_MULTICAST_ADDRESS,
                                                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_HONOR_INDIRECT,
                                         g_param_spec_boolean ("honor-indirect",
                                                               NULL,
                                                               NULL,
                                                               DEFAULT_HONOR_INDIRECT,
                                                               G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_WILLING_SCRIPT,
                                         g_param_spec_string ("willing-script",
                                                              "willing-script",
                                                              "willing-script",
                                                              NULL,
                                                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_MAX_DISPLAYS_PER_HOST,
                                         g_param_spec_uint ("max-displays-per-host",
                                                            "max-displays-per-host",
                                                            "max-displays-per-host",
                                                            0,
                                                            G_MAXINT,
                                                            DEFAULT_MAX_DISPLAYS_PER_HOST,
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_MAX_DISPLAYS,
                                         g_param_spec_uint ("max-displays",
                                                            "max-displays",
                                                            "max-displays",
                                                            0,
                                                            G_MAXINT,
                                                            DEFAULT_MAX_DISPLAYS,
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_MAX_PENDING_DISPLAYS,
                                         g_param_spec_uint ("max-pending-displays",
                                                            "max-pending-displays",
                                                            "max-pending-displays",
                                                            0,
                                                            G_MAXINT,
                                                            DEFAULT_MAX_PENDING_DISPLAYS,
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
        g_object_class_install_property (object_class,
                                         PROP_MAX_WAIT,
                                         g_param_spec_uint ("max-wait",
                                                            "max-wait",
                                                            "max-wait",
                                                            0,
                                                            G_MAXINT,
                                                            DEFAULT_MAX_WAIT,
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

        g_type_class_add_private (klass, sizeof (GdmXdmcpDisplayFactoryPrivate));
}

static void
gdm_xdmcp_display_factory_init (GdmXdmcpDisplayFactory *factory)
{
        char           hostbuf[1024];
        struct utsname name;

        factory->priv = GDM_XDMCP_DISPLAY_FACTORY_GET_PRIVATE (factory);

        factory->priv->socket_fd = -1;

        factory->priv->session_serial = g_random_int ();

        /* Fetch and store local hostname in XDMCP friendly format */
        hostbuf[1023] = '\0';
        if G_UNLIKELY (gethostname (hostbuf, 1023) != 0) {
                g_warning (_("Could not get server hostname: %s!"), g_strerror (errno));
                strcpy (hostbuf, "localhost.localdomain");
        }

        uname (&name);
        factory->priv->sysid = g_strconcat (name.sysname,
                                            " ",
                                            name.release,
                                            NULL);

        factory->priv->hostname = g_strdup (hostbuf);

        factory->priv->servhost.data   = (CARD8 *) g_strdup (hostbuf);
        factory->priv->servhost.length = strlen ((char *) factory->priv->servhost.data);
}

static void
gdm_xdmcp_display_factory_finalize (GObject *object)
{
        GdmXdmcpDisplayFactory *factory;

        g_return_if_fail (object != NULL);
        g_return_if_fail (GDM_IS_XDMCP_DISPLAY_FACTORY (object));

        factory = GDM_XDMCP_DISPLAY_FACTORY (object);

        g_return_if_fail (factory->priv != NULL);

        if (factory->priv->socket_watch_id > 0) {
                g_source_remove (factory->priv->socket_watch_id);
        }

        g_slist_free (factory->priv->forward_queries);
        g_slist_free (factory->priv->managed_forwards);

        g_free (factory->priv->sysid);
        g_free (factory->priv->hostname);
        g_free (factory->priv->multicast_address);
        g_free (factory->priv->willing_script);

        /* FIXME: Free servhost */

        G_OBJECT_CLASS (gdm_xdmcp_display_factory_parent_class)->finalize (object);
}

GdmXdmcpDisplayFactory *
gdm_xdmcp_display_factory_new (GdmDisplayStore *store)
{
        if (xdmcp_display_factory_object != NULL) {
                g_object_ref (xdmcp_display_factory_object);
        } else {
                xdmcp_display_factory_object = g_object_new (GDM_TYPE_XDMCP_DISPLAY_FACTORY,
                                                             "display-store", store,
                                                             NULL);
                g_object_add_weak_pointer (xdmcp_display_factory_object,
                                           (gpointer *) &xdmcp_display_factory_object);
        }

        return GDM_XDMCP_DISPLAY_FACTORY (xdmcp_display_factory_object);
}