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
package org.apache.directory.api.ldap.model.constants;


/**
 * An enum defining a list of dedicated loggers, used for debugging
 * purpose :
 * <ul>
 * <li>ACI_LOG : Logs on teh ACI processing</li>
 * <li>CONSUMER_LOG : Logs on the replication consummer</li>
 * <li>CURSOR_LOG : Logs on search cursors</li>
 * <li>PROVIDER_LOG : Logs on the replication provider</li>
 * <li>OPERATION_STAT : Logs on the operations statistics</li>
 * <li>OPERATION_TIME : Logs on the time it takes to process an operation</li>
 * <li>KERBEROS_LOG : Logs on Kerberos</li>
 * <li>CODEC_LOG : Logs on encoder/decoder</li>
 * <li>OPERATIONS_LOG: Logs on LDAP operations</li>
 * </ul>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum Loggers
{
    /** The dedicated logger for ACIs */
    ACI_LOG("org.apache.directory.server.ACI_LOG"),

    /** The dedicated logs for the replication consumer */
    CONSUMER_LOG("org.apache.directory.server.CONSUMER_LOG"),

    /** The dedicated logs for the cursors */
    CURSOR_LOG("org.apache.directory.CURSOR_LOG"),

    /** The dedicated logs for the replication provider */
    PROVIDER_LOG("org.apache.directory.server.PROVIDER_LOG"),

    /** The dedicated logs for operation statistics */
    OPERATION_STAT("org.apache.directory.server.OPERATION_STAT"),

    /** The dedicated logs for operation execution time */
    OPERATION_TIME("org.apache.directory.server.OPERATION_TIME"),

    /** The dedicated logger for KERBEROS */
    KERBEROS_LOG("org.apache.directory.server.KERBEROS_LOG"),

    /** The dedicated logger for LDAP operations */
    OPERATION_LOG("org.apache.directory.server.OPERATION_LOG"),

    /** The dedicated logger for CODEC */
    CODEC_LOG("org.apache.directory.api.CODEC_LOG");

    /** The associated name */
    private String name;


    /**
     * Creates a new instance of LdapSecurityConstants.
     * @param name the associated name
     */
    Loggers( String name )
    {
        this.name = name;
    }


    /**
     * @return the name associated with the constant.
     */
    public String getName()
    {
        return name;
    }
}
