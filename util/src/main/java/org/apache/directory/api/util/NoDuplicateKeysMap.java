/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */

package org.apache.directory.api.util;


import java.util.HashMap;

import org.apache.directory.api.i18n.I18n;


/**
 * A Map implementation derived from HashMap that only overrides a single method
 * put() in order to prevent duplicate keyed entries to be added.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("rawtypes")
public class NoDuplicateKeysMap extends HashMap
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 5107433500719957457L;
    
    /**
     * A public constructor
     */
    public NoDuplicateKeysMap()
    {
        super();
    }

    /**
     * Overrides java.util.Map.put(java.lang.Object, java.lang.Object) to
     * prevent duplicate keys.
     * 
     * @see java.util.Map#put(java.lang.Object, java.lang.Object)
     */
    @SuppressWarnings("unchecked")
    @Override
    public Object put( Object key, Object value )
    {
        if ( containsKey( key ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_17034_ADDING_DUP_KEYS_NOT_ALLOWED ) );
        }
        else
        {
            return super.put( key, value );
        }
    }
}
