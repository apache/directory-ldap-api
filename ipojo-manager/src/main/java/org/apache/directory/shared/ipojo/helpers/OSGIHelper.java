/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.shared.ipojo.helpers;


import java.util.ArrayList;
import java.util.List;

import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;


/**
 * Provides some OSGI helpers related to Service publication and access.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OSGIHelper
{
    /** BundleContext reference which will be assigned through BundleActivator */
    public static BundleContext bundleCtx;


    /**
     * Determines if Shared is launched in OSGI container.
     *
     * @return {@link Boolean}
     */
    public static boolean isAPIInOSGIContainer()
    {
        if ( bundleCtx == null )
        {
            return false;
        }

        return true;
    }


    /**
     * Gets OSGI Services by given specification and filter.
     *
     * @param serviceClassName Name of published service class name.
     * @param filter Filter to match against services.
     * @return List of matching services as List<Object>
     */
    public static List<?> getServices( String serviceClassName, String filter )
    {
        if ( !isAPIInOSGIContainer() )
        {
            return null;
        }

        try
        {
            ServiceReference[] serviceReferences = bundleCtx.getServiceReferences( serviceClassName, filter );
            List<Object> services = new ArrayList<Object>();
            for ( ServiceReference ref : serviceReferences )
            {
                services.add( bundleCtx.getService( ref ) );
            }

            return services;
        }
        catch ( InvalidSyntaxException e )
        {
            e.printStackTrace();
            return null;
        }
        catch ( IllegalStateException e )
        {
            e.printStackTrace();
            return null;
        }
    }


    /**
     * Gets the first service of given specification.
     *
     * @param serviceClassName Published OSGI Service class name.
     * @return The first matched service in service registry.
     */
    public static Object getService( String serviceClassName )
    {
        if ( !isAPIInOSGIContainer() )
        {
            return null;
        }

        ServiceReference ref = bundleCtx.getServiceReference( serviceClassName );
        if ( ref == null )
        {
            return null;
        }

        try
        {
            return bundleCtx.getService( ref );
        }
        catch ( IllegalStateException e )
        {
            e.printStackTrace();
            return null;
        }
    }
}
