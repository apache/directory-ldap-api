/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.schema.registries;

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.util.Strings;

/**
 * a map implementation which converts the keys to lower case before inserting
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LowerCaseKeyMap extends HashMap<String, Schema>
{
    private static final long serialVersionUID = 1L;

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Schema get( Object key )
    {
        return super.get( Strings.toLowerCaseAscii( ( String ) key ) );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Schema remove( Object key )
    {
        return super.remove( Strings.toLowerCaseAscii( ( String ) key ) );
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsKey( Object key )
    {
        return super.containsKey( Strings.toLowerCaseAscii( ( String ) key ) );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Schema put( String key, Schema value )
    {
        return super.put( Strings.toLowerCaseAscii( key ), value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void putAll( Map<? extends String, ? extends Schema> map )
    {
        for ( Map.Entry<? extends String, ? extends Schema> e : map.entrySet() )
        {
            super.put( Strings.toLowerCaseAscii( e.getKey() ), e.getValue() );
        }
    }
}
