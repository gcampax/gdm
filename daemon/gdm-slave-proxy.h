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


#ifndef __GDM_SLAVE_PROXY_H
#define __GDM_SLAVE_PROXY_H

#include <glib-object.h>

G_BEGIN_DECLS

#define GDM_TYPE_SLAVE               (gdm_slave_proxy_get_type ())
#define GDM_SLAVE_PROXY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), GDM_TYPE_SLAVE, GdmSlaveProxy))
#define GDM_SLAVE_PROXY_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), GDM_TYPE_SLAVE, GdmSlaveProxyClass))
#define GDM_IS_SLAVE(o)              (G_TYPE_CHECK_INSTANCE_TYPE ((o), GDM_TYPE_SLAVE))
#define GDM_IS_SLAVE_CLASS(k)        (G_TYPE_CHECK_CLASS_TYPE ((k), GDM_TYPE_SLAVE))
#define GDM_SLAVE_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GDM_TYPE_SLAVE, GdmSlaveProxyClass))

typedef struct GdmSlaveProxyPrivate GdmSlaveProxyPrivate;

typedef struct
{
	GObject	              parent;
	GdmSlaveProxyPrivate *priv;
} GdmSlaveProxy;

typedef struct
{
	GObjectClass   parent_class;

} GdmSlaveProxyClass;

GType		    gdm_slave_proxy_get_type	 (void);
GdmSlaveProxy *	    gdm_slave_proxy_new	         (const char *display_id);
gboolean            gdm_slave_proxy_start        (GdmSlaveProxy *slave);
gboolean            gdm_slave_proxy_stop         (GdmSlaveProxy *slave);

G_END_DECLS

#endif /* __GDM_SLAVE_PROXY_H */