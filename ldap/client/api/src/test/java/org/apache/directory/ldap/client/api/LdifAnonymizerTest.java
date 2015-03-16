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

package org.apache.directory.ldap.client.api;


import org.junit.Test;


/**
 * A class used to test the LDIFAnonymizer
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifAnonymizerTest
{
    @Test
    public void testLdifAnonymizer() throws Exception, Exception
    {
        String ldif =
            "dn:: Y249RW1tYW51ZWwgTMOpY2hhcm55LCBkYz1leG1hcGxlLCBkYz1jb20=\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn:: RW1tYW51ZWwgTMOpY2hhcm55\n" +
                "sn: elecharny\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer();
        String result = anonymizer.anonymize( ldif );
    }


    @Test
    public void testLdifAnonymizer2() throws Exception, Exception
    {
        String ldif =
            "dn: cn=cn2 + sn=elecharny, dc=example, dc=com\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn: cn1\n" +
                "cn: cn2\n" +
                "cn: cn3\n" +
                "sn: elecharny\n" +
                "givenname: test\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer();
        String result = anonymizer.anonymize( ldif );
    }


    @Test
    public void testLdifAnonymizer3() throws Exception, Exception
    {
        String ldif =
            "dn: cn=cn2 + sn=elecharny, dc=example, dc=com\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn: cn1\n" +
                "cn: cn2\n" +
                "cn: cn3\n" +
                "userPassword: test\n" +
                "sn: elecharny\n" +
                "givenname: test\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer();
        String result = anonymizer.anonymize( ldif );
    }
}
