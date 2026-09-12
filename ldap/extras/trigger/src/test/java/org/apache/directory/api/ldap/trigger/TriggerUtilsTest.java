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

package org.apache.directory.api.ldap.trigger;


import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import javax.naming.ldap.LdapContext;

import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Unit tests for {@link org.apache.directory.api.ldap.trigger.TriggerUtils}.
 * Verifies that CN values are escaped per RFC 4514 before being embedded
 * in DN syntax, so a value containing DN metacharacters cannot retarget
 * the JNDI operation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class TriggerUtilsTest
{
    /**
     * Creates an LdapContext proxy that records the name argument of every
     * createSubcontext/modifyAttributes call.
     */
    private LdapContext capturingContext( final List<String> names )
    {
        return ( LdapContext ) Proxy.newProxyInstance(
            LdapContext.class.getClassLoader(),
            new Class<?>[]
                { LdapContext.class },
            new InvocationHandler()
            {
                @Override
                public Object invoke( Object proxy, Method method, Object[] args )
                {
                    if ( ( "createSubcontext".equals( method.getName() )
                        || "modifyAttributes".equals( method.getName() ) )
                        && ( args != null ) && ( args.length > 0 ) && ( args[0] instanceof String ) )
                    {
                        names.add( ( String ) args[0] );
                    }

                    return null;
                }
            } );
    }


    @Test
    public void testCreateTriggerExecutionSubentryEscapesCN() throws Exception
    {
        List<String> names = new ArrayList<>();
        LdapContext apCtx = capturingContext( names );

        TriggerUtils.createTriggerExecutionSubentry( apCtx, "evil,cn=other", "{}", "spec" );

        assertEquals( 1, names.size() );

        // The name must parse as a single RDN : the ',' must have been escaped
        Dn dn = new Dn( names.get( 0 ) );
        assertEquals( 1, dn.size() );
        assertEquals( "evil,cn=other", dn.getRdn().getValue() );
    }


    @Test
    public void testLoadPrescriptiveTriggerSpecificationEscapesCN() throws Exception
    {
        List<String> names = new ArrayList<>();
        LdapContext apCtx = capturingContext( names );

        TriggerUtils.loadPrescriptiveTriggerSpecification( apCtx, "evil,cn=other", "spec" );

        assertEquals( 1, names.size() );

        // The name must parse as a single RDN : the ',' must have been escaped
        Dn dn = new Dn( names.get( 0 ) );
        assertEquals( 1, dn.size() );
        assertEquals( "evil,cn=other", dn.getRdn().getValue() );
    }
}
