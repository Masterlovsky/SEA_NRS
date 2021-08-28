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

    static final String NRS_TABLE_BASE_ID = "nrsTableBaseId";
    static final int NRS_TABLE_BASE_ID_DEFAULT = 1;

    static final String MOBILITY_TABLE_BASE_ID = "mobilityTableBaseId";
    static final int MOBILITY_TABLE_BASE_ID_DEFAULT = 2;

    static final String TABLESIZE = "tableSize";
    static final int SIZE_DEFAULT = 1024 * 64;

    static final String IRS_NA_NAME = "irsNa";
    static final String IRS_NA_DEFAULT = "2400:dd01:1037:201:192:168:47:191";

    static final String IRS_PORT_NAME = "irsPort";
    static final int IRS_PORT_DEFAULT = 10061;

    static final String BGP_NUM_NAME = "bgpNum";
    static final int BGP_NUM_DEFAULT = 1;

    static final String BGP_NA_NAME = "bgpNa";
    static final String BGP_NA = "2400:dd01:1037:201:192:168:47:198,2400:dd01:1037:201:192:168:47:191";
}
