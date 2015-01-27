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
package org.apache.directory.ldap.client.api.search;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.util.Strings;


/**
 * A class used to manage Substring Filters.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class SubstringFilter extends AbstractFilter
{
    /** The AttributeType for this filter */
    private String attribute;

    /** The initial substring string. It may be null */
    private String initial;

    /** The array of any substring strings. It may be null */
    private String[] any;

    /** The final substring string. It may be null */
    private String end;


    /**
     * A private constructor that builds a SubstringFilter 
     */
    private SubstringFilter( String attribute, String initial, String[] any, String end )
    {
        this.attribute = attribute;
        this.initial = initial;

        // We have to filter the 'any' and remove every empty strings
        if ( ( any != null ) && ( any.length != 0 ) )
        {
            List<String> anyList = new ArrayList<String>();

            for ( String string : any )
            {
                if ( !Strings.isEmpty( string ) )
                {
                    anyList.add( string );
                }
            }

            if ( anyList.size() > 0 )
            {
                this.any = anyList.toArray( new String[]
                    {} );
            }
        }

        this.end = end;
    }


    /**
     * Create a SubstringFilter based on the filter elements. Such a filter
     * has a form like Attribute=[initial]*([any]*)*[final].
     *
     * @param attribute The AttributeType for this filter
     * @param initial The first part of the substring
     * @param any The inner strings
     * @param end The final part of the substring.
     * @return An instance of a SubstringFilter
     */
    public static SubstringFilter substring( String attribute, String initial, String[] any, String end )
    {
        return new SubstringFilter( attribute, initial, any, end );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build( StringBuilder builder )
    {
        builder.append( "(" ).append( attribute ).append( '=' );

        if ( !Strings.isEmpty( initial ) )
        {
            builder.append( initial );
        }

        if ( any != null )
        {
            for ( String string : any )
            {
                builder.append( '*' ).append( string );
            }
        }

        builder.append( '*' );

        if ( !Strings.isEmpty( end ) )
        {
            builder.append( end );
        }

        builder.append( ")" );

        return builder;
    }
}