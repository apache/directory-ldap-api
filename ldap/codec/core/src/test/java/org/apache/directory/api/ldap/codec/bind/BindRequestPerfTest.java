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
package org.apache.directory.api.ldap.codec.bind;


import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
//@Ignore("Ignore performance tests: should not be with integration tests")
public class BindRequestPerfTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a BindRequest with Simple authentication and no
     * controls
     */
    @Test
    @Ignore
    public void testEncodeBindRequestPerf() throws Exception
    {
        Dn dn = new Dn( "uid=akarasulu,dc=example,dc=com" );
        int nbLoops = 100_000_000;

        // Check the decoded BindRequest
        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setMessageId( 1 );

        bindRequest.setSimple( true );
        bindRequest.setDn( dn );
        bindRequest.setCredentials( Strings.getBytesUtf8( "password" ) );
        //Control control = new ManageDsaITImpl();

        //bindRequest.addControl( control );
/*
        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < nbLoops; i++ )
        {
            // Check the encoding
            LdapEncoder.encodeMessage( codec, bindRequest );
        }

        long t1 = System.currentTimeMillis();
        System.out.println( "BindRequest testEncodeBindRequestPerf, " + nbLoops + " loops, Delta = " + ( t1 - t0 ) );
*/
        long sum = 0L;
        long max = 0L;
        long min = Long.MAX_VALUE;

        for ( int j = 0; j < 12; j++ )
        {
            Asn1Buffer buffer = new Asn1Buffer();

            long t2 = System.currentTimeMillis();

            for ( int i = 0; i < nbLoops; i++ )
            {
                // Check the encoding
                LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );
                buffer.clear();
            }

            long delta = System.currentTimeMillis() - t2;
            System.out.println( "delta: " + delta );

            sum += delta;
            min = delta < min ? delta: min;
            max = delta > max ? delta: max;
        }

        sum -= min + max;
        System.out.println( "BindRequest testEncodeBindRequestPerf reverse, " + nbLoops + " loops, Delta = "
        + ( sum/10 ) + ", min = " + min + ", max = " + max );
    }
}
