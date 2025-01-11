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
package org.apache.directory.api.asn1.ber.tlv;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Parse and decode a Boolean value.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class BooleanDecoder
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( BooleanDecoder.class );

    /**
     * A private constructor
     */
    private BooleanDecoder()
    {
    }

    /**
     * Parse a Value containing a byte[] and send back a boolean.
     *
     * @param value The Value to parse
     * @return A boolean.
     * @throws BooleanDecoderException Thrown if the Value does not contains a boolean
     */
    public static boolean parse( BerValue value ) throws BooleanDecoderException
    {
        byte[] bytes = value.getData();

        if ( Strings.isEmpty( bytes ) )
        {
            throw new BooleanDecoderException( I18n.err( I18n.ERR_01302_0_BYTES_LONG_BOOLEAN ) );
        }

        if ( bytes.length != 1 )
        {
            throw new BooleanDecoderException( I18n.err( I18n.ERR_01303_N_BYTES_LONG_BOOLEAN ) );
        }

        if ( ( bytes[0] != 0 ) && ( bytes[0] != ( byte ) 0xFF ) )
        {
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( I18n.msg( I18n.MSG_01300_BOOLEAN_0X00_0XFF ) );
            }
        }

        return bytes[0] != 0;
    }
}
