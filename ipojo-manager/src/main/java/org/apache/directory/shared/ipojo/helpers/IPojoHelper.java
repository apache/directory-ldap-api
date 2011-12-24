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


import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

import org.apache.felix.ipojo.ComponentFactory;
import org.apache.felix.ipojo.ComponentInstance;
import org.apache.felix.ipojo.ConfigurationException;
import org.apache.felix.ipojo.Factory;
import org.apache.felix.ipojo.InstanceManager;
import org.apache.felix.ipojo.MissingHandlerException;
import org.apache.felix.ipojo.UnacceptableConfiguration;


public class IPojoHelper
{
    public static ComponentFactory getFactory( String factoryName )
    {
        try
        {
            String filter = "(factory.name=" + factoryName + ")";
            List<ComponentFactory> factories = ( List<ComponentFactory> ) OSGIHelper.getServices( Factory.class.getName(), filter );
            if ( factories == null )
            {
                return null;
            }
            return factories.get( 0 );
        }
        catch ( ClassCastException e )
        {
            return null;
        }
    }


    public static Object createIPojoComponent( String factoryName, String instanceName, Dictionary props )
    {
        ComponentFactory factory = IPojoHelper.getFactory( factoryName );
        if ( factory == null )
        {
            return null;
        }

        if ( instanceName != null )
        {
            if ( props == null )
            {
                props = new Hashtable<String, String>();
            }
            props.put( "instance.name", instanceName );
        }

        try
        {
            ComponentInstance comp = factory.createComponentInstance( props );
            Object instance = ( ( InstanceManager ) comp ).getPojoObject();

            return instance;
        }
        catch ( UnacceptableConfiguration e )
        {
            e.printStackTrace();
            return null;
        }
        catch ( MissingHandlerException e )
        {
            e.printStackTrace();
            return null;
        }
        catch ( ConfigurationException e )
        {
            e.printStackTrace();
            return null;
        }

    }
}
