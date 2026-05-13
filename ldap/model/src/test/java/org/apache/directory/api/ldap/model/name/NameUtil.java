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
package org.apache.directory.api.ldap.model.name;

import java.util.List;

import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.util.Strings;

/**
 * Utility class used to dump the DN/RDN/AVA/Value elements
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NameUtil 
{
    private static String dumpValue( String tabs, Value value )
    {
        StringBuilder sb = new StringBuilder();
        
        if ( value  == null )
        {
            return tabs + "No value" + "\n";
        }
        else
        {
            sb.append( tabs ).append( "Value:\n" );
            tabs = tabs + "    ";
        }
        
        // The upValue
        sb.append( tabs ).append( "UpValue: '" ).append( value.getUpValue() ).append( "'\n" );
        
        // The normValue
        sb.append( tabs ).append( "NormValue: '" ).append( value.getNormalized() ).append( "'\n" );
        
        // The bytes
        sb.append( tabs ).append( "Bytes: '" ).append( Strings.dumpBytes( value.getBytes() ) ).append( "'\n" );
        
        // The attributeType
        if ( value.getAttributeType() == null )
        {
            sb.append( tabs ).append( "No attributeType" ).append( '\n' ); 
        }
        else
        {
            sb.append( tabs ).append( "AttributeType" ).append( value.getAttributeType() ).append( '\n' );  
        }
        
        // The HR flag
        if ( value.isHumanReadable() )
        {
            sb.append( tabs ).append( "HR: true\n" );
        }
        else
        {
            sb.append( tabs ).append( "HR: false\n" );
        }
        
        // The hashcode
        sb.append( tabs ).append( "H: " ).append( value.hashCode() ).append( '\n' );
        
        return sb.toString();
    }
    
 
    public static void dumpValue( Value value )
    {
        System.out.println( dumpValue( "    ", value ));
    }
    
    
    private static String dumpAva( String tabs, Ava ava )
    {
        if ( ava == null )
        {
            return tabs + "null";
        }
        
        StringBuilder sb = new StringBuilder();
        
        // The upName
        sb.append( tabs ).append( "upName: '" ).append( ava.upName ).append( "'\n" );
        
        // The attributeType
        sb.append( tabs ).append( "attributeType: '" ).append( ava.attributeType ).append( "'\n" );

        // The upType
        sb.append( tabs ).append( "upType: '" ).append( ava.upType ).append( "'\n" );

        // The normType
        sb.append( tabs ).append( "normType: '" ).append( ava.normType ).append( "'\n" );

        // The schemaManager
        if ( ava.isSchemaAware() )
        {
            sb.append( tabs ).append( "Schema aware\n" );
        }
        else
        {
            sb.append( tabs ).append( "No schema\n" );
        }
        
        // The value
        sb.append( dumpValue( tabs, ava.value ) ).appendCodePoint( '\n' );
        
        return sb.toString();
    }

    public static void dumpAva( Ava ava )
    {
        System.out.println( dumpAva( "    ", ava ) );
    }

    private static String dumpRdn( String tabs, Rdn rdn )
    {
        StringBuilder sb = new StringBuilder();

        if ( rdn == null )
        {
            sb.append( tabs ).append( "RDN: null\n" );
        }
        
        if ( rdn.nbAvas == 0 )
        {
            sb.append( tabs ).append( "RDN: no AVAs\n" );
        }
        else
        {
            sb.append( tabs ).append( "RDN:\n" );
        }
        
        tabs = tabs + "    ";
        
        // The schema
        if ( rdn.isSchemaAware() )
        {
            sb.append( tabs ).append( "Schema aware\n" );
        }
        else
        {
            sb.append( tabs ).append( "No schema\n" );
        }
        
        // The upName
        if ( Strings.isEmpty( rdn.upName ) )
        {
            sb.append( tabs ).append( "UpName is empty\n" );
        }
        else
        {
            sb.append( tabs ).append( "UpName: '" ).append( rdn.upName ).append( "'\n" );
        }
  
        // The normName
        if ( Strings.isEmpty( rdn.normName ) )
        {
            sb.append( tabs ).append( "NormName is empty\n" );
        }
        else
        {
            sb.append( tabs ).append( "NormName: '" ).append( rdn.normName ).append( "'\n" );
        }
        
        // The hash code
        sb.append( tabs ).append( "h:" ).append( rdn.hashCode() ).append( '\n' );

        // The AVAs
        sb.append( tabs ).append( "Nb AVAs: " ).append( rdn.nbAvas ).append( '\n' );
        
        switch ( rdn.nbAvas )
        {
            case 0:
                sb.append( tabs ).append( "No AVAs\n" );
                break;
                
            case 1:
                sb.append( tabs + "    " ).append( "AVA:\n" );
                sb.append( dumpAva( tabs + "        ", rdn.ava ) );
                break;
                
            default:
                List<Ava> avas = rdn.avas;
                
                for ( int i = 0; i < rdn.nbAvas; i++ )
                {
                    sb.append( tabs + "    " ).append( "AVA[" ).append( i ).append( "]:\n" );
                    sb.append( dumpAva( tabs + "        ", avas.get( i ) ) );
                }
        }
        
        return sb.toString();
    }

    public static void dumpRdn( Rdn rdn )
    {
        String tabs = "    ";
        
        System.out.println( dumpRdn( tabs, rdn ) );
    }

    public static void dumpDn( Dn dn )
    {
        String tabs = "    ";
        
        if ( dn == null )
        {
            System.out.println( "DN: null" );
        }
        
        if ( dn.isEmpty() )
        {
            System.out.println( "DN: empty" );
        }
        
        StringBuilder sb = new StringBuilder();
        
        // The schema
        if ( dn.isSchemaAware() )
        {
            sb.append( tabs ).append( "Schema aware\n" );
        }
        else
        {
            sb.append( tabs ).append( "No schema\n" );
        }
        
        // The upname
        if ( Strings.isEmpty( dn.getName() ) )
        {
            sb.append( tabs ).append( "UpName is empty\n" );
        }
        else
        {
            sb.append( tabs ).append( "UpName: '" ).append( dn.getName() ).append( "'\n" );
        }
        
        // The normname
        if ( Strings.isEmpty( dn.getNormName() ) )
        {
            sb.append( tabs ).append( "NormName is empty\n" );
        }
        else
        {
            sb.append( tabs ).append( "NormName: '" ).append( dn.getNormName() ).append( "'\n" );
        }
        
        // The RDNs
        List<Rdn> rdns = dn.getRdns();
        
        sb.append( tabs ).append( "RDNs:\n" );
        
        tabs = tabs + "    ";
        
        if ( rdns.isEmpty() )
        {
            sb.append( tabs ).append( "null\n" );
        }
        else
        {
            int i = 0;
            
            for ( Rdn rdn : rdns )
            {
                sb.append( tabs ).append( "rdn[" + i + "]:\n" );
                
                sb.append( dumpRdn( tabs + "    ", rdn ) );
                
                i++;
            }
        }
        
        System.out.println( "DN: ");
        System.out.println( sb.toString() );
    }
}
