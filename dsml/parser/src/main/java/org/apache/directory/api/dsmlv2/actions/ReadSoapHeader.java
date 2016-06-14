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
package org.apache.directory.api.dsmlv2.actions;


import java.io.IOException;

import org.apache.directory.api.dsmlv2.Dsmlv2Container;
import org.apache.directory.api.dsmlv2.Dsmlv2StatesEnum;
import org.apache.directory.api.dsmlv2.GrammarAction;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;


/**
 * The action used to read the SOAP Header
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ReadSoapHeader extends GrammarAction
{
    /**
     * Instantiates the action.
     */
    public ReadSoapHeader()
    {
        super( "Reads SOAP header" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( Dsmlv2Container container ) throws XmlPullParserException
    {
        try
        {
            XmlPullParser xpp = container.getParser();
            StringBuilder sb = new StringBuilder();

            String startTag = xpp.getText();
            sb.append( startTag );

            // string '<' and '>'
            startTag = startTag.substring( 1, startTag.length() - 1 );

            int tagType = -1;
            String endTag = "";

            // continue parsing till we get to the end tag of SOAP header
            // and match the tag values including the namespace
            while ( !startTag.equals( endTag ) )
            {
                tagType = xpp.next();
                endTag = xpp.getText();
                sb.append( endTag );

                if ( tagType == XmlPullParser.END_TAG )
                {
                    // strip '<', '/' and '>'
                    endTag = endTag.substring( 2, endTag.length() - 1 );
                }
            }

            // change the state to header end
            container.setState( Dsmlv2StatesEnum.SOAP_HEADER_END_TAG );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
    }
}
