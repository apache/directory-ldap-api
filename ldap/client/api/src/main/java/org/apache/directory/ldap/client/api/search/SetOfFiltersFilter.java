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


class SetOfFiltersFilter extends AbstractFilter
{
    private Operator operator;
    private List<Filter> filters;


    private SetOfFiltersFilter( Operator operator )
    {
        this.operator = operator;
        this.filters = new ArrayList<Filter>();
    }


    public SetOfFiltersFilter add( Filter filter )
    {
        filters.add( filter );
        return this;
    }


    public SetOfFiltersFilter addAll( Filter... filters )
    {
        for ( Filter filter : filters )
        {
            this.filters.add( filter );
        }

        return this;
    }


    public SetOfFiltersFilter addAll( List<Filter> filters )
    {
        this.filters.addAll( filters );
        return this;
    }


    public static SetOfFiltersFilter and( Filter... filters )
    {
        return new SetOfFiltersFilter( Operator.AND ).addAll( filters );
    }


    public static SetOfFiltersFilter or( Filter... filters )
    {
        return new SetOfFiltersFilter( Operator.OR ).addAll( filters );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        if ( filters.isEmpty() )
        {
            throw new IllegalStateException( "at least one filter required" );
        }

        builder.append( "(" ).append( operator.operator() );

        for ( Filter filter : filters )
        {
            filter.build( builder );
        }

        return builder.append( ")" );
    }

    public static enum Operator
    {
        AND("&"),
        OR("|");

        private String operator;


        private Operator( String operator )
        {
            this.operator = operator;
        }


        public String operator()
        {
            return operator;
        }
    }
}