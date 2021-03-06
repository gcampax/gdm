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

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#ifdef WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "gdm-display-factory.h"
#include "gdm-local-display-factory.h"
#include "gdm-local-display-factory-glue.h"

#include "gdm-display-store.h"
#include "gdm-static-display.h"
#include "gdm-transient-display.h"
#include "gdm-product-display.h"

#define GDM_LOCAL_DISPLAY_FACTORY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GDM_TYPE_LOCAL_DISPLAY_FACTORY, GdmLocalDisplayFactoryPrivate))

#define CK_SEAT1_PATH                       "/org/freedesktop/ConsoleKit/Seat1"
#define SYSTEMD_SEAT0_PATH                  "seat0"

#define GDM_DBUS_PATH                       "/org/gnome/DisplayManager"
#define GDM_LOCAL_DISPLAY_FACTORY_DBUS_PATH GDM_DBUS_PATH "/LocalDisplayFactory"
#define GDM_MANAGER_DBUS_NAME               "org.gnome.DisplayManager.LocalDisplayFactory"

#define MAX_DISPLAY_FAILURES 5

struct GdmLocalDisplayFactoryPrivate
{
        DBusGConnection *connection;
        DBusGProxy      *proxy;
        GHashTable      *displays;

        /* FIXME: this needs to be per seat? */
        guint            num_failures;
};

enum {
        PROP_0,
};

static void     gdm_local_display_factory_class_init    (GdmLocalDisplayFactoryClass *klass);
static void     gdm_local_display_factory_init          (GdmLocalDisplayFactory      *factory);
static void     gdm_local_display_factory_finalize      (GObject                     *object);

static GdmDisplay *create_display                       (GdmLocalDisplayFactory      *factory,
                                                         const char                  *seat_id);

static gpointer local_display_factory_object = NULL;

G_DEFINE_TYPE (GdmLocalDisplayFactory, gdm_local_display_factory, GDM_TYPE_DISPLAY_FACTORY)

GQuark
gdm_local_display_factory_error_quark (void)
{
        static GQuark ret = 0;
        if (ret == 0) {
                ret = g_quark_from_static_string ("gdm_local_display_factory_error");
        }

        return ret;
}

static void
listify_hash (gpointer    key,
              GdmDisplay *display,
              GList     **list)
{
        *list = g_list_prepend (*list, key);
}

static int
sort_nums (gpointer a,
           gpointer b)
{
        guint32 num_a;
        guint32 num_b;

        num_a = GPOINTER_TO_UINT (a);
        num_b = GPOINTER_TO_UINT (b);

        if (num_a > num_b) {
                return 1;
        } else if (num_a < num_b) {
                return -1;
        } else {
                return 0;
        }
}

static guint32
take_next_display_number (GdmLocalDisplayFactory *factory)
{
        GList  *list;
        GList  *l;
        guint32 ret;

        ret = 0;
        list = NULL;

        g_hash_table_foreach (factory->priv->displays, (GHFunc)listify_hash, &list);
        if (list == NULL) {
                goto out;
        }

        /* sort low to high */
        list = g_list_sort (list, (GCompareFunc)sort_nums);

        g_debug ("GdmLocalDisplayFactory: Found the following X displays:");
        for (l = list; l != NULL; l = l->next) {
                g_debug ("GdmLocalDisplayFactory: %u", GPOINTER_TO_UINT (l->data));
        }

        for (l = list; l != NULL; l = l->next) {
                guint32 num;
                num = GPOINTER_TO_UINT (l->data);

                /* always fill zero */
                if (l->prev == NULL && num != 0) {
                        ret = 0;
                        break;
                }
                /* now find the first hole */
                if (l->next == NULL || GPOINTER_TO_UINT (l->next->data) != (num + 1)) {
                        ret = num + 1;
                        break;
                }
        }
 out:

        /* now reserve this number */
        g_debug ("GdmLocalDisplayFactory: Reserving X display: %u", ret);
        g_hash_table_insert (factory->priv->displays, GUINT_TO_POINTER (ret), NULL);

        return ret;
}

static void
on_display_disposed (GdmLocalDisplayFactory *factory,
                     GdmDisplay             *display)
{
        g_debug ("GdmLocalDisplayFactory: Display %p disposed", display);
}

static void
store_display (GdmLocalDisplayFactory *factory,
               guint32                 num,
               GdmDisplay             *display)
{
        GdmDisplayStore *store;

        g_object_weak_ref (G_OBJECT (display), (GWeakNotify)on_display_disposed, factory);

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        gdm_display_store_add (store, display);

        /* now fill our reserved spot */
        g_hash_table_insert (factory->priv->displays, GUINT_TO_POINTER (num), NULL);
}

static const char *
get_seat_of_transient_display (GdmLocalDisplayFactory *factory)
{
        const char *seat_id;

        /* FIXME: don't hardcode seat */
#ifdef WITH_SYSTEMD
        seat_id = SYSTEMD_SEAT0_PATH;
#else
        seat_id = CK_SEAT1_PATH;
#endif

        return seat_id;
}

/*
  Example:
  dbus-send --system --dest=org.gnome.DisplayManager \
  --type=method_call --print-reply --reply-timeout=2000 \
  /org/gnome/DisplayManager/Manager \
  org.gnome.DisplayManager.Manager.GetDisplays
*/
gboolean
gdm_local_display_factory_create_transient_display (GdmLocalDisplayFactory *factory,
                                                    char                  **id,
                                                    GError                **error)
{
        gboolean         ret;
        GdmDisplay      *display;
        guint32          num;
        const char      *seat_id;

        g_return_val_if_fail (GDM_IS_LOCAL_DISPLAY_FACTORY (factory), FALSE);

        ret = FALSE;

        num = take_next_display_number (factory);

        g_debug ("GdmLocalDisplayFactory: Creating transient display %d", num);

        display = gdm_transient_display_new (num);

        seat_id = get_seat_of_transient_display (factory);
        g_object_set (display, "seat-id", seat_id, NULL);

        store_display (factory, num, display);

        if (! gdm_display_manage (display)) {
                display = NULL;
                goto out;
        }

        if (! gdm_display_get_id (display, id, NULL)) {
                display = NULL;
                goto out;
        }

        ret = TRUE;
 out:
        /* ref either held by store or not at all */
        g_object_unref (display);

        return ret;
}

gboolean
gdm_local_display_factory_create_product_display (GdmLocalDisplayFactory *factory,
                                                  const char             *parent_display_id,
                                                  const char             *relay_address,
                                                  char                  **id,
                                                  GError                **error)
{
        gboolean    ret;
        GdmDisplay *display;
        guint32     num;
        const char *seat_id;

        g_return_val_if_fail (GDM_IS_LOCAL_DISPLAY_FACTORY (factory), FALSE);

        ret = FALSE;

        g_debug ("GdmLocalDisplayFactory: Creating product display parent %s address:%s",
                 parent_display_id, relay_address);

        num = take_next_display_number (factory);

        g_debug ("GdmLocalDisplayFactory: got display num %u", num);

        display = gdm_product_display_new (num, relay_address);

        seat_id = get_seat_of_transient_display (factory);
        g_object_set (display, "seat-id", seat_id, NULL);

        store_display (factory, num, display);

        if (! gdm_display_manage (display)) {
                display = NULL;
                goto out;
        }

        if (! gdm_display_get_id (display, id, NULL)) {
                display = NULL;
                goto out;
        }

        ret = TRUE;
 out:
        /* ref either held by store or not at all */
        g_object_unref (display);

        return ret;
}

static void
on_static_display_status_changed (GdmDisplay             *display,
                                  GParamSpec             *arg1,
                                  GdmLocalDisplayFactory *factory)
{
        int              status;
        GdmDisplayStore *store;
        int              num;
        char            *seat_id = NULL;

        num = -1;
        gdm_display_get_x11_display_number (display, &num, NULL);
        g_assert (num != -1);

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));

        g_object_get (display, "seat-id", &seat_id, NULL);

        status = gdm_display_get_status (display);

        g_debug ("GdmLocalDisplayFactory: static display status changed: %d", status);
        switch (status) {
        case GDM_DISPLAY_FINISHED:
                /* remove the display number from factory->priv->displays
                   so that it may be reused */
                g_hash_table_remove (factory->priv->displays, GUINT_TO_POINTER (num));
                gdm_display_store_remove (store, display);
                /* reset num failures */
                factory->priv->num_failures = 0;
                create_display (factory, seat_id);
                break;
        case GDM_DISPLAY_FAILED:
                /* leave the display number in factory->priv->displays
                   so that it doesn't get reused */
                gdm_display_store_remove (store, display);
                factory->priv->num_failures++;
                if (factory->priv->num_failures > MAX_DISPLAY_FAILURES) {
                        /* oh shit */
                        g_warning ("GdmLocalDisplayFactory: maximum number of X display failures reached: check X server log for errors");
                        /* FIXME: should monitor hardware changes to
                           try again when seats change */
                } else {
                        create_display (factory, seat_id);
                }
                break;
        case GDM_DISPLAY_UNMANAGED:
                break;
        case GDM_DISPLAY_PREPARED:
                break;
        case GDM_DISPLAY_MANAGED:
                break;
        default:
                g_assert_not_reached ();
                break;
        }

        g_free (seat_id);
}

static gboolean
lookup_by_seat_id (const char *id,
                   GdmDisplay *display,
                   gpointer    user_data)
{
        const char *looking_for = user_data;
        char *current;
        gboolean res;

        g_object_get (G_OBJECT (display), "seat-id", &current, NULL);

        res = g_strcmp0 (current, looking_for) == 0;

        g_free(current);

        return res;
}

static GdmDisplay *
create_display (GdmLocalDisplayFactory *factory,
                const char             *seat_id)
{
        GdmDisplayStore *store;
        GdmDisplay      *display;
        guint32          num;

        /* Ensure we don't create the same display more than once */
        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        display = gdm_display_store_find (store, lookup_by_seat_id, (gpointer) seat_id);
        if (display != NULL) {
                return NULL;
        }

        g_debug ("GdmLocalDisplayFactory: Adding display on seat %s", seat_id);

        num = take_next_display_number (factory);

#if 0
        display = gdm_static_factory_display_new (num);
#else
        display = gdm_static_display_new (num);
#endif

        g_object_set (display, "seat-id", seat_id, NULL);

        g_signal_connect (display,
                          "notify::status",
                          G_CALLBACK (on_static_display_status_changed),
                          factory);

        store_display (factory, num, display);

        /* let store own the ref */
        g_object_unref (display);

        if (! gdm_display_manage (display)) {
                gdm_display_unmanage (display);
        }

        return display;
}

#ifdef WITH_SYSTEMD

static void
delete_display (GdmLocalDisplayFactory *factory,
                const char             *seat_id) {

        GdmDisplayStore *store;

        g_debug ("GdmLocalDisplayFactory: Removing displays on seat %s", seat_id);

        store = gdm_display_factory_get_display_store (GDM_DISPLAY_FACTORY (factory));
        gdm_display_store_foreach_remove (store, lookup_by_seat_id, (gpointer) seat_id);
}

static gboolean gdm_local_display_factory_sync_seats (GdmLocalDisplayFactory *factory)
{
        DBusError error;
        DBusMessage *message, *reply;
        DBusMessageIter iter, sub, sub2;

        dbus_error_init (&error);

        message = dbus_message_new_method_call (
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListSeats");
        if (message == NULL) {
                g_warning ("GdmLocalDisplayFactory: Failed to allocate message");
                return FALSE;
        }

        reply = dbus_connection_send_with_reply_and_block (dbus_g_connection_get_connection (factory->priv->connection), message, -1, &error);
        dbus_message_unref (message);

        if (reply == NULL) {
                g_warning ("GdmLocalDisplayFactory: Failed to issue method call: %s", error.message);
                dbus_error_free (&error);
                return FALSE;
        }

        if (!dbus_message_iter_init (reply, &iter) ||
            dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type (&iter) != DBUS_TYPE_STRUCT)  {
                g_warning ("GdmLocalDisplayFactory: Failed to parse reply.");
                dbus_message_unref (reply);
                return FALSE;
        }

        dbus_message_iter_recurse (&iter, &sub);

        while (dbus_message_iter_get_arg_type (&sub) != DBUS_TYPE_INVALID) {
                const char *seat;

                if (dbus_message_iter_get_arg_type (&sub) != DBUS_TYPE_STRUCT) {
                        g_warning ("GdmLocalDisplayFactory: Failed to parse reply.");
                        dbus_message_unref (reply);
                        return FALSE;
                }

                dbus_message_iter_recurse (&sub, &sub2);

                if (dbus_message_iter_get_arg_type (&sub2) != DBUS_TYPE_STRING) {
                        g_warning ("GdmLocalDisplayFactory: Failed to parse reply.");
                        dbus_message_unref (reply);
                        return FALSE;
                }

                dbus_message_iter_get_basic (&sub2, &seat);
                create_display (factory, seat);

                dbus_message_iter_next (&sub);
        }

        dbus_message_unref (reply);
        return TRUE;
}

static DBusHandlerResult
on_seat_signal (DBusConnection *connection,
                DBusMessage    *message,
                void           *user_data)
{
        GdmLocalDisplayFactory *factory = user_data;
        DBusError error;

        dbus_error_init (&error);

        if (dbus_message_is_signal (message, "org.freedesktop.login1.Manager", "SeatNew") ||
            dbus_message_is_signal (message, "org.freedesktop.login1.Manager", "SeatRemoved")) {
                const char *seat;

                dbus_message_get_args (message,
                                       &error,
                                       DBUS_TYPE_STRING, &seat,
                                       DBUS_TYPE_INVALID);

                if (dbus_error_is_set (&error)) {
                        g_warning ("GdmLocalDisplayFactory: Failed to decode seat message: %s", error.message);
                        dbus_error_free (&error);
                } else {

                        if (strcmp (dbus_message_get_member (message), "SeatNew") == 0) {
                                create_display (factory, seat);
                        } else {
                                delete_display (factory, seat);
                        }
                }
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
gdm_local_display_factory_start_monitor (GdmLocalDisplayFactory *factory)
{
        DBusError error;

        dbus_error_init (&error);

        dbus_bus_add_match (dbus_g_connection_get_connection (factory->priv->connection),
                            "type='signal',"
                            "sender='org.freedesktop.login1',"
                            "path='/org/freedesktop/login1',"
                            "interface='org.freedesktop.login1.Manager',"
                            "member='SeatNew'",
                            &error);

        if (dbus_error_is_set (&error)) {
                g_warning ("GdmLocalDisplayFactory: Failed to add match for SeatNew: %s", error.message);
                dbus_error_free (&error);
        }

        dbus_bus_add_match (dbus_g_connection_get_connection (factory->priv->connection),
                            "type='signal',"
                            "sender='org.freedesktop.login1',"
                            "path='/org/freedesktop/login1',"
                            "interface='org.freedesktop.login1.Manager',"
                            "member='SeatRemoved'",
                            &error);

        if (dbus_error_is_set (&error)) {
                g_warning ("GdmLocalDisplayFactory: Failed to add match for SeatNew: %s", error.message);
                dbus_error_free (&error);
        }

        dbus_connection_add_filter (dbus_g_connection_get_connection (factory->priv->connection), on_seat_signal, factory, NULL);
}

static void
gdm_local_display_factory_stop_monitor (GdmLocalDisplayFactory *factory)
{
        dbus_connection_remove_filter (dbus_g_connection_get_connection (factory->priv->connection), on_seat_signal, factory);
}

#endif

static gboolean
gdm_local_display_factory_start (GdmDisplayFactory *base_factory)
{
        GdmLocalDisplayFactory *factory = GDM_LOCAL_DISPLAY_FACTORY (base_factory);
        GdmDisplay             *display;

        g_return_val_if_fail (GDM_IS_LOCAL_DISPLAY_FACTORY (factory), FALSE);

#ifdef WITH_SYSTEMD
        if (sd_booted () > 0) {
                gdm_local_display_factory_start_monitor (factory);
                return gdm_local_display_factory_sync_seats (factory);
        }
#endif

        /* On ConsoleKit just create Seat1, and that's it. */
        display = create_display (factory, CK_SEAT1_PATH);

        return display != NULL;
}

static gboolean
gdm_local_display_factory_stop (GdmDisplayFactory *base_factory)
{
        GdmLocalDisplayFactory *factory = GDM_LOCAL_DISPLAY_FACTORY (base_factory);

        g_return_val_if_fail (GDM_IS_LOCAL_DISPLAY_FACTORY (factory), FALSE);

#ifdef WITH_SYSTEMD
        gdm_local_display_factory_stop_monitor (factory);
#endif

        return TRUE;
}

static void
gdm_local_display_factory_set_property (GObject       *object,
                                        guint          prop_id,
                                        const GValue  *value,
                                        GParamSpec    *pspec)
{
        switch (prop_id) {
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
gdm_local_display_factory_get_property (GObject    *object,
                                        guint       prop_id,
                                        GValue     *value,
                                        GParamSpec *pspec)
{
        switch (prop_id) {
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static gboolean
register_factory (GdmLocalDisplayFactory *factory)
{
        GError *error = NULL;

        error = NULL;
        factory->priv->connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (factory->priv->connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                exit (1);
        }

        dbus_g_connection_register_g_object (factory->priv->connection, GDM_LOCAL_DISPLAY_FACTORY_DBUS_PATH, G_OBJECT (factory));

        return TRUE;
}

static GObject *
gdm_local_display_factory_constructor (GType                  type,
                                       guint                  n_construct_properties,
                                       GObjectConstructParam *construct_properties)
{
        GdmLocalDisplayFactory      *factory;
        gboolean                     res;

        factory = GDM_LOCAL_DISPLAY_FACTORY (G_OBJECT_CLASS (gdm_local_display_factory_parent_class)->constructor (type,
                                                                                                                   n_construct_properties,
                                                                                                                   construct_properties));

        res = register_factory (factory);
        if (! res) {
                g_warning ("Unable to register local display factory with system bus");
        }

        return G_OBJECT (factory);
}

static void
gdm_local_display_factory_class_init (GdmLocalDisplayFactoryClass *klass)
{
        GObjectClass           *object_class = G_OBJECT_CLASS (klass);
        GdmDisplayFactoryClass *factory_class = GDM_DISPLAY_FACTORY_CLASS (klass);

        object_class->get_property = gdm_local_display_factory_get_property;
        object_class->set_property = gdm_local_display_factory_set_property;
        object_class->finalize = gdm_local_display_factory_finalize;
        object_class->constructor = gdm_local_display_factory_constructor;

        factory_class->start = gdm_local_display_factory_start;
        factory_class->stop = gdm_local_display_factory_stop;

        g_type_class_add_private (klass, sizeof (GdmLocalDisplayFactoryPrivate));

        dbus_g_object_type_install_info (GDM_TYPE_LOCAL_DISPLAY_FACTORY, &dbus_glib_gdm_local_display_factory_object_info);
}

static void
gdm_local_display_factory_init (GdmLocalDisplayFactory *factory)
{
        factory->priv = GDM_LOCAL_DISPLAY_FACTORY_GET_PRIVATE (factory);

        factory->priv->displays = g_hash_table_new (NULL, NULL);
}

static void
gdm_local_display_factory_finalize (GObject *object)
{
        GdmLocalDisplayFactory *factory;

        g_return_if_fail (object != NULL);
        g_return_if_fail (GDM_IS_LOCAL_DISPLAY_FACTORY (object));

        factory = GDM_LOCAL_DISPLAY_FACTORY (object);

        g_return_if_fail (factory->priv != NULL);

        g_hash_table_destroy (factory->priv->displays);

#ifdef WITH_SYSTEMD
        gdm_local_display_factory_stop_monitor (factory);
#endif

        G_OBJECT_CLASS (gdm_local_display_factory_parent_class)->finalize (object);
}

GdmLocalDisplayFactory *
gdm_local_display_factory_new (GdmDisplayStore *store)
{
        if (local_display_factory_object != NULL) {
                g_object_ref (local_display_factory_object);
        } else {
                local_display_factory_object = g_object_new (GDM_TYPE_LOCAL_DISPLAY_FACTORY,
                                                             "display-store", store,
                                                             NULL);
                g_object_add_weak_pointer (local_display_factory_object,
                                           (gpointer *) &local_display_factory_object);
        }

        return GDM_LOCAL_DISPLAY_FACTORY (local_display_factory_object);
}
