package nnnmc.seanet.seanrs.util;

public interface Message {
    int TYPE_LEN = 1;
    int REQUESTID_LEN = 4;
    int PADDING_LEN = 1;
    int EID_LEN = 20;
    int ID_LEN = 4;
    int NA_LEN = 16;
    int TTL_LEN = 1;
    int NUM_LEN = 1;
    int REAL_LEN = 1;
    int INT_LEN = 4;
    int BYTE_LEN = 1;    
    int TLV_LEN = 2;
    int REMOTE_LEN = 1;
    int LEVEL_LEN = 1;
    int IS_GLOBAL_VISABLE_LEN = 1;
    int DELAY_LEN = 1;
    int STATUS_LEN = 1;
    int FLAG_LEN = 1;
    int TIMESTAMP_LEN = 4;
    int LEVEL_DELAY_LEN = 2;
    int ID_NA_LEN = 20;
    int EID_NA_NUM_LEN = 2;
    int LEVEL_ID_NA_LEN = 21;
    int ID_NA_LEVEL_LEN = 21;
    int ID_NA_LEVEL_REAL_LEN = 22;
    int ID_NA_REAL_LEN = 21;
    int MAPPING_LEN = 43;
    int UDP_LEN = 512;
    int TCP_LEN = 5400;
    int CARRIER_LEN = 20;
    int LOCATION_LEN = 16;
    int FORMAT_LEN = 1;

    int GEO_LOCATION_LEN = 40;
    int DESC_LEN = 40;
    // client
    byte RNL_REQ = 13;                      // 0d
    byte RNL_RESP = 14;                     // 0e
    byte LATENCY_NEIGHBOR_REQ = 80;
    byte LATENCY_NEIGHBOR_RESP = 81;
    byte INDEX_NEIGHBOR_REQ = 82;
    byte INDEX_NEIGHBOR_RESP = 83;
    
    byte MEASURE_UN = 3;                   // 03
    byte MEASURE_UN_RESP = 4;              // 04
    byte ROOT_QUERY = 5;                   // 05
    byte ROOT_QUERY_RESP = 6;              // 06
    byte MEASURE_NU = 7;                   // 07
    byte MEASURE_NU_RESP = 8;              // 08
    byte UPLOAD_LAST_NODE = 9;             // 09
    byte UPLOAD_LAST_NODE_RESP = 10;       // 0a
    byte REGISTER = 111;                   // 6f
    byte REGISTER_RESP = 112;              // 70
    byte RESOLVE = 113;                    // 71
    byte RESOLVE_RESP = 114;               // 72
    byte DEREGISTER = 115;                 // 73
    byte DEREGISTER_RESP = 116;            // 74
    byte BATCH_REGISTER = 117;             // 75
    byte BATCH_REGISTER_RESP = 118;        // 76
    byte BATCH_DEREGISTER = 119;           // 77
    byte BATCH_DEREGISTER_RESP = 120;      // 78
    byte TRANSFER_REQ = 121;               // 79
    byte TRANSFER_RESP = 122;              // 7a

    // need to merge to common register, resolve and deregister
    byte REGISTER_TLV = 111;               // 6f
    byte REGISTER_RESP_TLV = 112;          // 70
    byte RESOLVE_TLV = 113;                // 71
    byte RESOLVE_RESP_TLV = 114;           // 72
    byte DEREGISTER_TLV = 115;             // 73
    byte DEREGISTER_RESP_TLV = 116;        // 74

    // manager
    byte REPORT_PARENT_NMRVS = 10;
    byte REPORT_OFFLINE_NMRVS = 11;
    byte REPORT_ONLINE = 21;               // 15
    byte REPORT_ONLINE_RESP = 22;          // 16
    byte REPORT_OFFLINE = 23;              // 17
    byte REPORT_OFFLINE_RESP = 24;         // 18
    byte VIRTUAL_ROOTS_REQ = 25;           // 19
    byte VIRTUAL_ROOTS_RESP = 26;          // 1a
    byte ROOTS_REQ = 27;                   // 1b
    byte ROOTS_RESP = 28;                  // 1c

    // node
    byte MEASURE_NN = 40;                  // 28
    byte MEASURE_NN_RESP = 41;             // 29
    byte ROOT_REPLACE = 42;                // 2a
    byte ROOT_REPLACE_RESP = 43;           // 2b
    byte CHILD_REQ = 44;                   // 2c
    byte CHILD_RESP = 45;                  // 2d
    byte VIRTUAL_SIBLING_REQ = 46;         // 2e
    byte VIRTUAL_SIBLING_RESP = 47;        // 2f
    byte ADOPT_NOTIFY = 48;                // 30
    byte ADOPT_NOTIFY_RESP = 49;           // 31
    byte ADOPT_QUIT_NOTIFY = 50;           // 32
    byte ADOPT_QUIT_NOTIFY_RESP = 51;      // 33
    byte JOIN_NOTIFY = 52;                 // 34
    byte JOIN_NOTIFY_RESP = 53;            // 35
    byte HEARTBEAT = 54;                   // 36
    byte HEARTBEAT_RESP = 55;              // 37
    byte DELAY_NEIGHBOR_REQ = 56;          // 38
    byte DELAY_NEIGHBOR_RESP = 57;         // 39
    byte QUIT_NOTIFY = 58;                 // 3a
    byte QUIT_NOTIFY_RESP = 59;            // 3b
    byte MEASURE_LOC = 85;                 // 55
    byte MEASURE_LOC_RESP = 86;            // 56

    //others
    byte STRUCTURE_NOTIFY = 39;            // 27
    byte STRUCTURE_NOTIFY_RESP = 40;       // 28
    byte STRUCTURE_REQ = 47;               // 2f
    byte STRUCTURE_RESP = 48;              // 30
    byte MAPPING_REQ = 63;                 // 3f
    byte MAPPING_RESP = 64;                // 40
    byte SEND_MAPPING = 65;                // 41
    byte SEND_MAPPING_RESP = 66;           // 42
    byte DEL_CHILD = 67;                   // 43
    byte DEL_CHILD_RESP = 68;              // 44
    byte RNL_NOTIFY = 69;                  // 45
    byte RNL_NOTIFY_RESP = 70;             // 46
    byte ADD_GEO_NEIGHBOR = 73;            // 49
    byte ADD_GEO_NEIGHBOR_RESP = 74;       // 4a
    byte GEO_NEIGHBOR_REQ = 75;            // 4b
    byte GEO_NEIGHBOR_RESP = 76;           // 4c
    byte SHUTDOWN = 89;                    // 59
    byte SHUTDOWN_RESP = 90;               // 5a

    // test
    byte PRINT_NODE = 101;                 // 65
    byte TRIGGER_DAEMON = 102;             // 66
    byte QUERY_DELAY = 103;                // 67
    byte QUERY_DELAY_RESP = 104;           // 68
    byte RELOAD_DELAY_FILE = 106;          // 6a
    byte DEL_GEO_NEIGHBOR = 109;           // 6d

    // reserve
    byte REPORT_STATUS = 0;  
    
    

    // device
    byte DEREGISTER_NA=117;                 //75
    byte RESOLVE_EID_NA=119;                //77
    byte RESOLVE_RESP_EID_NA=120;           //78

    // global resolution
    byte GLOBAL_REGISTER_TLV = 11;          //7b  123->11
    byte GLOBAL_REGISTER_RESP_TLV = 12;     //7c  124->12
    byte INDEX_NEIGHBOR_REQUEST = 125;      //7d
    byte INDEX_NEIGHBOR_RESPONSE = 126;     //7e

    // snmp management

    byte INFO = 60;                         //3c
    byte MAPPING_ITEM_NUM = 61;             //3d
    byte DELAY_LEVEL = 62;                  //3e
    byte REGISTER_REQUEST_PER_HOUR = 63;    //3f
    byte DEREGISTER_REQUEST_PER_HOUR = 64;  //40
    byte RESOLVE_REQUEST_PER_HOUR = 65;     //41
    byte DESCENDENTS_NUM = 66;              //42
    byte ONELINE_TIMESTAMP = 67;            //43
    byte GEO_LOCATION = 68;                 //44
    byte OPERT = 69;                        //45
    byte LAL = 70;                          //46
    byte SNMP_RESULT = 71;                  //47
    

    byte[] pack();

    Message unpack(byte[] data);

}
