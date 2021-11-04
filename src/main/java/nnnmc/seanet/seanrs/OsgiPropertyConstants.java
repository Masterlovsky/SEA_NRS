/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nnnmc.seanet.seanrs;

public final class OsgiPropertyConstants {

    private OsgiPropertyConstants() {

    }

    public static final String SEANRS_TABLEID_IPV6 = "seanrs_tableid_ipv6";
    public static final int NRS_TABLE_BASE_ID_DEFAULT = 1;

    public static final String MOBILITY_TABLEID_FOR_IPV6 = "mobility_tableid_for_ipv6";
    public static final int MOBILITY_TABLE_BASE_ID_DEFAULT = 2;

    public static final String TABLESIZE = "tableSize";
    public static final int SIZE_DEFAULT = 1024 * 64;

    public static final String IRS_NA_NAME = "irsNa";
    public static final String IRS_NA_DEFAULT = "2400:dd01:1037:201:192:168:47:191";

    public static final String IRS_PORT_NAME = "irsPort";
    public static final int IRS_PORT_DEFAULT = 10061;

    public static final String BGP_NUM_NAME = "bgpNum";
    public static final int BGP_NUM_DEFAULT = 1;

    public static final String BGP_NA_NAME = "bgpNaStr";
    public static final String BGP_NA = "2400:dd01:1037:10:20::20"; // BGP_NA is comma-separated
}
