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


/**
 * 
 * TODO AttributeFilter.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AttributeFilter extends AbstractFilter
{
    private String attribute;
    private Operator operator;


    private AttributeFilter( String attribute, Operator operator )
    {
        this.attribute = attribute;
        this.operator = operator;
    }


    public static AttributeFilter present( String attribute )
    {
        return new AttributeFilter( attribute, Operator.PRESENT );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute )
            .append( operator.operator() ).append( ")" );
    }

    public static enum Operator
    {
        PRESENT("=*");

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