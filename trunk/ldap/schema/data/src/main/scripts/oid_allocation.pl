#!/usr/bin/env perl
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

use strict;
use warnings;

use File::Basename;
use File::Find;
use File::Spec;
use Getopt::Long;
use Net::LDAP::LDIF;
use Sort::Versions;

my $json;
GetOptions(
    "json" => \$json
);

# Find path to /src/main using relative to this script
my @dir_parts = File::Spec->splitdir((fileparse($0))[1]);
splice(@dir_parts, -2);
my $dir = File::Spec->catdir(@dir_parts);

my %oid_to_metadata = ();
find(sub {
        return unless (-f $_ && /^.*\.ldif$/);

        my ($entry, $oid, $name, $description);
        my $ldif = Net::LDAP::LDIF->new($_, 'r', onerror => 'undef');
        while (!$ldif->eof()) {
            $entry = $ldif->read_entry();
            $oid = $entry->get_value('m-oid');
            if ($oid) {
                $name = $entry->get_value('m-name');
                $description = $entry->get_value('m-description');

                my $value = $oid_to_metadata{$oid};
                if (!$value) {
                    $value = [];
                    $oid_to_metadata{$oid} = $value;
                }
                push(@$value, {
                        file => $File::Find::name, 
                        name => $name,
                        description => $description 
                    });
            }
        }
    }, $dir);

my %header = (
    '0' => '### `ou=syntaxes` and `ou=syntaxCheckers`',
    '1' => '### `ou=comparators` and `ou=matchingRules` and `ou=normalizers`',
    '2' => '### `ou=attributeTypes`',
    '2.0' => '#### Base Bean',
    '2.100' => '#### Directory Service',
    '2.300' => '#### LDAP Server',
    '2.400' => '#### Kerberos Server',
    '2.500' => '#### DNS Server',
    '2.600' => '#### DHCP Server',
    '2.700' => '#### NTP Server',
    '2.800' => '#### ChangePassword Server',
    '2.900' => '#### Password Policy',
    '3' => '### `ou=objectClasses`',
    '3.0' => '#### Base Bean',
    '3.100' => '#### Directory Service',
    '3.300' => '#### LDAP Server',
    '3.400' => '#### Kerberos Server',
    '3.500' => '#### DNS Server',
    '3.600' => '#### DHCP Server',
    '3.700' => '#### NTP Server',
    '3.800' => '#### ChangePassword Server',
    '3.900' => '#### Password Policy',
);

if($json) {
    # JSON format
    require JSON;
    my $json = JSON->new()
        ->utf8()->indent()->space_after()
        ->sort_by(sub{no warnings 'once';versioncmp($JSON::PP::a, $JSON::PP::b)})
        ->encode(\%oid_to_metadata);
    print($json);
}
else {
    # Default markdown format
    require POSIX;
    print("#\n");
    print("#  Licensed to the Apache Software Foundation (ASF) under one\n");
    print("#  or more contributor license agreements.  See the NOTICE file\n");
    print("#  distributed with this work for additional information\n");
    print("#  regarding copyright ownership.  The ASF licenses this file\n");
    print("#  to you under the Apache License, Version 2.0 (the\n");
    print("#  \"License\"); you may not use this file except in compliance\n");
    print("#  with the License.  You may obtain a copy of the License at\n");
    print("#\n");
    print("#    http://www.apache.org/licenses/LICENSE-2.0\n");
    print("#\n");
    print("#  Unless required by applicable law or agreed to in writing,\n");
    print("#  software distributed under the License is distributed on an\n");
    print("#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n");
    print("#  KIND, either express or implied.  See the License for the\n");
    print("#  specific language governing permissions and limitations\n");
    print("#  under the License.\n");

    foreach my $oid (sort {versioncmp($a, $b)} keys(%oid_to_metadata)) {
        next unless ($oid =~ /^1\.3\.6\.1\.4\.1\.18060\.0\.4\.1\.(\d+)\.(\d+).*$/);
        my $section = "$1";
        my $section_and_sub = "$section." . POSIX::floor($2/100)*100;
    
        if (defined($header{$section})) {
            print("\n", delete($header{$section}), "\n\n");
        }
        if (defined($header{$section_and_sub})) {
            print("\n", delete($header{$section_and_sub}), "\n\n");
        }
    
        if ($section == 0) {
            # no name, so use description
            print("- $oid: ", join(',', (map {defined($_->{description}) ? $_->{description} : ()} @{$oid_to_metadata{$oid}})), "\n");
        }
        else {
            print("- $oid: ", join(',', (map {defined($_->{name}) ? $_->{name} : ()} @{$oid_to_metadata{$oid}})), "\n");
        }
    }
}
