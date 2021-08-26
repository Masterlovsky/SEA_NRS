package nnnmc.seanet.sea_nrs;

import nnnmc.seanet.controller.api.FlowRuleCache;
import nnnmc.seanet.sea_nrs.protocol.IDP;
import nnnmc.seanet.sea_nrs.protocol.NRS;
import nnnmc.seanet.sea_nrs.util.HexUtil;
import nnnmc.seanet.sea_nrs.util.SendAndRecv;
import nnnmc.seanet.sea_nrs.util.SocketUtil;
import nnnmc.seanet.sea_nrs.util.Util;
import org.onlab.packet.Data;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv6;
import org.onlab.packet.IpAddress;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.floodlightpof.protocol.OFMatch20;
import org.onosproject.floodlightpof.protocol.instruction.*;
import org.onosproject.floodlightpof.protocol.table.OFTableType;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.*;
import org.onosproject.pof.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static nnnmc.seanet.sea_nrs.OsgiPropertyConstants.*;
import static org.onlab.util.Tools.groupedThreads;


@Component(immediate = true,
        property = {
                NRS_TABLE_BASE_ID + ":Integer=" + NRS_TABLE_BASE_ID_DEFAULT,
                MOBILITY_TABLE_BASE_ID + ":Integer=" + MOBILITY_TABLE_BASE_ID_DEFAULT,
                "tableSize" + ":Integer=" + SIZE_DEFAULT,
                "irs_na" + ":String=" + IRS_NA_DEFAULT,
                "irs_port" + ":Integer=" + IRS_PORT_DEFAULT,
                "bgp_num" + ":Integer=" + BGP_NUM_DEFAULT,
                "bgp_na" + ":String=" + BGP_NA
        }
)
public class SeanrsApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterService clusterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService componentConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleStore store;

    private static final int SEANRS_TABLEID_IPV6 = NRS_TABLE_BASE_ID_DEFAULT;
    private static final int SEANRS_TABLEID_Vlan = NRS_TABLE_BASE_ID_DEFAULT + 10;
    private static final int SEANRS_TABLEID_Qinq = NRS_TABLE_BASE_ID_DEFAULT + 20;
    private static final int MobilityTableID_for_Ipv6 = MOBILITY_TABLE_BASE_ID_DEFAULT;
    private static final int MobilityTableID_for_Vlan = MOBILITY_TABLE_BASE_ID_DEFAULT + 10;
    private static final int MobilityTableID_for_Qinq = MOBILITY_TABLE_BASE_ID_DEFAULT + 20;
    private static final int DEFAULT_PRIORITY = 1000;
    private static final int PKTIN_PRIORITY = 2000;
    private static final int FORWARD_PRIORITY = 5000;
    private static final int ETH_HEADER_LEN = 14 * 8;
    private static final String NA_ZEROS = HexUtil.zeros(32);
    private static int DEFAULT_TABLE_SIZE = SIZE_DEFAULT;
    private static String IRS_NA = IRS_NA_DEFAULT;
    private static int IRS_port = IRS_PORT_DEFAULT;
    private static final List<String> bgp_Na_List = new ArrayList<>();
    private static int BGP_NUM = BGP_NUM_DEFAULT;
    private static String BGP_NA_String = BGP_NA;

    private final FlowRuleCache instructionBlockSentCache = new FlowRuleCache();
    private final FlowRuleCache instructionBlockInstalledCache = new FlowRuleCache();
    private final FlowRuleCache flowEntrySentCache = new FlowRuleCache();
    private final FlowRuleCache tableSentCache = new FlowRuleCache();
    private final FlowRuleCache tableInstalledCache = new FlowRuleCache();

    private final SeaNRSFlowRuleListener flowRuleListener = new SeaNRSFlowRuleListener();
    private final SeaNRSPacketProcessor processor = new SeaNRSPacketProcessor();

    private ExecutorService executor;

    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        IRS_NA = Tools.get(properties, "irs_na");
        BGP_NUM = Tools.getIntegerProperty(properties, "bgp_num", BGP_NUM_DEFAULT);
        IRS_port = Tools.getIntegerProperty(properties, "irs_port", IRS_PORT_DEFAULT);
        DEFAULT_TABLE_SIZE = Tools.getIntegerProperty(properties, "tableSize", SIZE_DEFAULT);
        BGP_NA_String = Tools.get(properties, "bgp_na");
    }


    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
    }

    protected ApplicationId appId;
    private NodeId local;

    @Activate
    public void activate(ComponentContext context) {
//        for test: ---------------------
        bgp_Na_List.addAll(Arrays.asList(BGP_NA_String.split(",")));
//        -------------------------
        appId = coreService.registerApplication("org.onosproject.sea_nrs");
        local = clusterService.getLocalNode().id();

        executor = Executors.newSingleThreadExecutor(groupedThreads("onos/seanet/sea_nrs", "main", log));
        flowRuleService.addListener(flowRuleListener);

        instructionBlockSentCache.clear();
        instructionBlockInstalledCache.clear();
        flowEntrySentCache.clear();
        tableSentCache.clear();
        tableInstalledCache.clear();

        componentConfigService.registerProperties(getClass());
        modified(context);
        //Send flow tables to the switches that have been connected
        for (Device device : deviceService.getAvailableDevices()) {
            if (device.id().toString().startsWith("pof")) {
                DeviceId deviceId = device.id();
                NodeId master = mastershipService.getMasterFor(deviceId);
                if (Objects.equals(local, master)) {
                    buildNRSTables(deviceId);
                    log.info("activate: {} add FlowTable for NRS App. allNRSTablesStored(deviceId)={}, " + "instructionBlockSentCache.size(deviceId)={}",
                            deviceId, allNRSTablesStored(deviceId), instructionBlockSentCache.size(deviceId));
                }
            }
        }
        packetService.addProcessor(processor, PacketProcessor.director(100)); // todo: 看一下其他业务的priority
        log.info("============== Sea_NRS app activate! ==============");
    }


    @Deactivate
    public void deactivate(ComponentContext context) {
        //Before stopping the application, we first need to delete the entry delivered by the application on the switch
        for (Device device : deviceService.getAvailableDevices()) {
            DeviceId deviceId = device.id();
            NodeId master = mastershipService.getMasterFor(deviceId);
            if (Objects.equals(local, master)) {
                removeOldFlowRules(deviceId);
            }
        }

        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        flowRuleService.removeListener(flowRuleListener);

        componentConfigService.unregisterProperties(getClass(), false);
        executor.shutdown();

        log.info("================= Sea_NRS app deactivate =================");
    }

    private void removeOldFlowRules(DeviceId deviceId) {
        try {
            Set<FlowRule> entryRemoveSet = flowEntrySentCache.remove(deviceId);
            if ((entryRemoveSet != null) && (!entryRemoveSet.isEmpty())) {
                for (FlowRule flowRule : entryRemoveSet) {
                    flowRuleService.removeFlowRules(flowRule);
                    log.debug("removeOldFlowRules in {}, removeFlowRules {}!", deviceId, flowRule);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    // =================== Flow Tables =======================

    private void buildNRSTables(DeviceId deviceId) {
        log.debug("========== build NRS Table begin for device {} ==========", deviceId);
        {
            FlowRule table1 = createNRSTable(deviceId, SEANRS_TABLEID_IPV6, 0);//ipv6
            flowRuleService.applyFlowRules(table1);
            tableSentCache.add(table1);
        }
        {
            FlowRule table11 = createNRSTable(deviceId, SEANRS_TABLEID_Vlan, 4);//vlan
            flowRuleService.applyFlowRules(table11);
            tableSentCache.add(table11);
        }
        {
            FlowRule table21 = createNRSTable(deviceId, SEANRS_TABLEID_Qinq, 8);//qinq
            flowRuleService.applyFlowRules(table21);
            tableSentCache.add(table21);
        }
        log.debug("{} : NRS buildTable end", deviceId);
    }

    private FlowRule createNRSTable(DeviceId deviceId, int tableId, int offset) {
        log.info("---------- createNRSTable{}, in {} begin ----------", tableId, deviceId);

        OFMatch20Selector selector = new OFMatch20Selector();
        selector.addOFMatch20(FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 24 * 8, 16 * 8); // DEST_IPV6_ADDR
        selector.addOFMatch20(FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 40 * 8, 8); // IDP_NextHeader
        selector.addOFMatch20(FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8); // DEST_EID (1-16Byte)
        selector.addOFMatch20(FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8); // DEST_EID (16-20Byte)

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(new TableModTreatment(OFTableType.OF_MM_TABLE, DEFAULT_TABLE_SIZE, "NRSTable"), deviceId);
        PofFlowRuleBuilder builder = new PofFlowRuleBuilder();
        FlowRule flowRule = builder
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return flowRule;
    }

    private boolean allNRSTablesStored(DeviceId deviceId) {
        log.debug("allNRSTablesStored, tableSentCache.size({})={}.", deviceId, tableSentCache.size(deviceId));
//		tableSentCache.size(deviceId) == 3

        boolean tableStored = false;
        int count = 0;

        try {
            if (tableSentCache.size(deviceId) == 0) {
                log.error("getNRSTableStoreByDeviceId({}).isEmpty()!", deviceId);
                return false;
            }
            for (FlowRule table : tableSentCache.getFlowRuleSet()) {
                if (store.getFlowEntry(new DefaultFlowEntry(table)) == null) {
                    count++;
                }
            }
            if (count == 0) {
                tableStored = true;
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        return tableStored;
    }

    private boolean allNRSTablesInstalled(DeviceId deviceId) {
        boolean tableInstalled;
        if (tableSentCache.size(deviceId) == 0) {
            return false;
        }
        tableInstalled = tableSentCache.contrains(tableInstalledCache, deviceId);
        if (tableInstalled) log.info("------- NRS tables installed -------");
        return tableInstalled;
    }

    // ================= Instruction Block =================

    private FlowRule buildPacketInInstructionBlock(DeviceId deviceId) {
        log.debug("---------- build packetIn instruction block for {} ----------", deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();

        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildSetAddrAndGotoTableInstructionBlock(DeviceId deviceId, int offset, String ipAddress, int gotoTableId) {
        log.debug("---------- build SetAddr&GotoTable instruction block for {} ----------", deviceId);
        OFMatch20 ofMatch20 = new OFMatch20(FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 24 * 8, 16 * 8); // IPv6 dstAddr
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionSetField(ofMatch20, ipAddress));
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildGotoTableInstructionBlock(DeviceId deviceId, int gotoTableId) {
        log.debug("---------- build GotoTable{} instruction block for {} ----------", gotoTableId, deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildOutputInstructionBlock(DeviceId deviceId) {
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        try {
            // 从交换机port 1转出
            instructionBlockModTreatment.addInstruction(new OFInstructionOutput(OutPutType.OUTP, 0, 1));
            trafficTreatmentBuilder.extension(instructionBlockModTreatment, deviceId);
        } catch (Exception e) {
            log.info("BuildOutputInstructionBlock Faild");
        }

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .makeStored(false)
                .build();

        return blockFlowRule;
    }

    private void addDefaultInstructionBlock(DeviceId deviceId) {
        log.debug("========== add default instruction block for {} ==========", deviceId);
        {
            FlowRule blockFlowRule = buildPacketInInstructionBlock(deviceId);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildGotoTableInstructionBlock(deviceId, MobilityTableID_for_Ipv6);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildGotoTableInstructionBlock(deviceId, MobilityTableID_for_Vlan);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildGotoTableInstructionBlock(deviceId, MobilityTableID_for_Qinq);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
    }

    private boolean allInstructionBlocksInstalled(DeviceId deviceId) {
        boolean instructionBlockInstalled;
        if (instructionBlockSentCache.size(deviceId) == 0) {
            return false;
        }
        instructionBlockInstalled = instructionBlockSentCache.contrains(instructionBlockInstalledCache, deviceId);
        if (instructionBlockInstalled) log.info("------- NRS instruction blocks installed -------");
        return instructionBlockInstalled;
    }

    // =================== Flow Entries ======================

    private void addPacketInFlowEntry(DeviceId deviceId, int tableId) {
        log.debug("---------- add PacketIn flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        switch (tableId) {
            case SEANRS_TABLEID_Vlan:
                offset = 4;
                break;
            case SEANRS_TABLEID_Qinq:
                offset = 8;
                break;
            default:
                break;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        FlowModTreatment flowModTreatment = new FlowModTreatment(buildPacketInInstructionBlock(deviceId).id().value());

        //construct treatment
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);


        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(PKTIN_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addSetIPDstAddrAndGoToTableFlowEntry(DeviceId deviceId, String eid, String na, int tableId, int gotoTableId) {
        log.debug("---------- add Set IPDstAddr And GoToTable flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        switch (tableId) {
            case SEANRS_TABLEID_Vlan:
                offset = 4;
                break;
            case SEANRS_TABLEID_Qinq:
                offset = 8;
                break;
            default:
                break;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), 16 * 8, NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), 8, "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, eid.substring(0, 32), HexUtil.duplicates('F', 32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, eid.substring(32, 40), HexUtil.duplicates('F', 8)); // DEST_EID (16-20Byte)

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        // construct treatment
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetAddrAndGotoTableInstructionBlock(deviceId, offset, na, gotoTableId).id().value());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);

        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(FORWARD_PRIORITY)
                .makePermanent() // TODO: 2021/8/20 这个地方后面要改成软超时，暂时先用永久表项
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addDefaultGoToTableFlowEntry(DeviceId deviceId, int tableId, int goToTableId) {
        log.debug("---------- add default GoToTable flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        switch (tableId) {
            case SEANRS_TABLEID_Vlan:
                offset = 4;
                break;
            case SEANRS_TABLEID_Qinq:
                offset = 8;
                break;
            default:
                break;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.zeros(32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "00");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildGotoTableInstructionBlock(deviceId, goToTableId).id().value());

        //construct treatment
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);


        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addDefaultFlowEntry(DeviceId deviceId) {
        log.debug("========== add default flow entry for device:{} ==========", deviceId);
        try {
            addPacketInFlowEntry(deviceId, SEANRS_TABLEID_IPV6);
            addPacketInFlowEntry(deviceId, SEANRS_TABLEID_Vlan);
            addPacketInFlowEntry(deviceId, SEANRS_TABLEID_Qinq);
            addDefaultGoToTableFlowEntry(deviceId, SEANRS_TABLEID_IPV6, MobilityTableID_for_Ipv6);
            addDefaultGoToTableFlowEntry(deviceId, SEANRS_TABLEID_Vlan, MobilityTableID_for_Vlan);
            addDefaultGoToTableFlowEntry(deviceId, SEANRS_TABLEID_Qinq, MobilityTableID_for_Qinq);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }


    // ====================== process =========================
    /**
     * 对于设备标识为DeviceId的某设备，用函数getProcessStatusByDeviceId判断fibApp是否下发过表项，
     * 下发过则调用processedSetAdd函数将其记录在processedDeviceIdSet中；
     * 当设备下线后，调用resetStatusByDeviceId函数，将该设备的DeviceId从processedDeviceIdSet中移出。以此来避免重复下发表项
     */
    private final CopyOnWriteArraySet<DeviceId> processedDeviceIdSet = new CopyOnWriteArraySet<>();

    public synchronized void processedSetAdd(DeviceId deviceId) {
        processedDeviceIdSet.add(deviceId);
    }

    public synchronized void resetStatusByDeviceId(DeviceId deviceId) {
        if (!processedDeviceIdSet.isEmpty()) {
            processedDeviceIdSet.remove(deviceId);
        }
    }

    public synchronized boolean getProcessStatusByDeviceId(DeviceId deviceId) {
        boolean processed = !processedDeviceIdSet.isEmpty() && processedDeviceIdSet.contains(deviceId);
        return processed;
    }


    /**
     * listener 监听所有flowRule相关事件，包括流表的添加和删除、指令块儿的添加和删除、表项的添加和删除都会触发这个listener
     */
    private class SeaNRSFlowRuleListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule rule = event.subject();
            switch (event.type()) {
                //case RULE_ADDED:
                //case RULE_UPDATED:
                case RULE_ADD_REQUESTED: {
                    DeviceId deviceId = rule.deviceId();
                    if (deviceId.toString().startsWith("pof")) {
                        NodeId master = mastershipService.getMasterFor(deviceId);
                        if (Objects.equals(local, master)) {
                            switch (rule.type()) {
                                case FlowRuleType.TABLE_MOD: //flow table add
                                {
                                    if (tableSentCache.contains(rule)) {
                                        tableInstalledCache.add(rule);
                                        if (allNRSTablesInstalled(deviceId) && (instructionBlockSentCache.size(deviceId) == 0)) {
                                            executor.execute(() -> addDefaultInstructionBlock(deviceId));
                                        }
                                    }
                                }
                                break;
                                case FlowRuleType.INSTRUCTION_BLOCK_MOD: //instruction block add
                                {
                                    executor.execute(() -> {
                                        if (instructionBlockSentCache.contains(rule)) {
                                            //log.debug("INSTRUCTION_BLOCK_MOD instructionBlockSentCache.contains\n");
                                            instructionBlockInstalledCache.add(rule);
                                            //需要的默认指令块全部添加完毕，则下发表项; 如果该设备上的表项已经下发完成则不再下发
                                            if (allInstructionBlocksInstalled(deviceId) && !getProcessStatusByDeviceId(deviceId)) {
                                                //log.debug("INSTRUCTION_BLOCK_MOD call onDefaultBlocksAddedByDevice,add default entries\n");
                                                executor.execute(() -> {
                                                    addDefaultFlowEntry(deviceId);
                                                    processedSetAdd(deviceId);
                                                });
                                            }
                                        }
                                    });
                                    break;
                                }
                                default:
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }


    // TODO: 2021/7/24 这里是重点，根据packetEID改ip，然后goto Mobility表, 进行后续业务逻辑
    private class SeaNRSPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            nrsPacketInProcess(context);
        }

        private void nrsPacketInProcess(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            ConnectPoint ingressPort = pkt.receivedFrom();
            Interface anInterface = interfaceService.getInterfacesByPort(ingressPort).stream().findFirst().orElse(null);
            IpAddress ipAddress = Objects.requireNonNull(anInterface).ipAddressesList().get(0).ipAddress();
            String fromSwitchIP = ipAddress.toInetAddress().getHostAddress();
            String fromSwitchIP_hex = HexUtil.ip2HexString(fromSwitchIP, 32);
            DeviceId deviceId = ingressPort.deviceId();
            Ethernet ethPkt = pkt.parsed();
            // TODO: 2021/8/22 Vlan 和 Qinq 先不处理
            short pkt_type = ethPkt.getEtherType();
            if (pkt_type == Ethernet.TYPE_VLAN) {
                return;
            }
            if (pkt_type == Ethernet.TYPE_QINQ) {
                return;
            }
            IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
            int nextHdr = HexUtil.byteToUnsignedInt(ipv6Pkt.getNextHeader());
            if (nextHdr == 0x11) {
                // TODO: 2021/7/27 UDP 实际上并不会执行
                log.info("receive UDP packet, content: {}", SocketUtil.bytesToHexString(ipv6Pkt.serialize()));
            } else if (nextHdr == 0x99) {
                // TODO: 2021/7/27 IDP 暂定使用扩展包头的方式
                /*
                byte[] ipv6PktByte = ipv6Pkt.serialize();
                byte idpNextHeader = ipv6PktByte[40]; // 网内解析匹配字段，0x10
                byte[] idpReserved = {ipv6PktByte[42], ipv6PktByte[43]}; //
                byte[] srcEidByte = new byte[20];
                System.arraycopy(ipv6PktByte, 44, srcEidByte, 0, 20);
                byte[] dstEidByte = new byte[20];
                System.arraycopy(ipv6PktByte, 64, dstEidByte, 0, 20);
                */
                IDP idpPkt = (IDP) ipv6Pkt.getPayload();
                String nextHeader = HexUtil.byte2HexString(idpPkt.getNextHeader());
                String dstEid = SocketUtil.bytesToHexString(idpPkt.getDestEID());
                // 处理网内解析请求 0x10
                if (nextHeader.equals("10")) {
                    NRS nrsPkt = (NRS) idpPkt.getPayload();
                    String queryType = HexUtil.byte2HexString(nrsPkt.getQueryType());

                    // TODO: 2021/8/22 register or deregister
                    if (queryType.equals("01") || queryType.equals("02")) {
                        boolean flag = true; // 标记在控制器上是否注册成功
                        byte[] payload = nrsPkt.getPayload().serialize();
                        if (payload != null) {
                            // 转发注册或注销请求给解析单点, 获取响应之后返回
                            String sendToIRSMsg = Util.msgFormat1ToIRSFormat(SocketUtil.bytesToHexString(payload));
                            byte[] receive = SendAndRecv.throughUDP(IRS_NA, IRS_port, SocketUtil.hexStringToBytes(sendToIRSMsg));
                            if (receive != null) {
                                if (Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).startsWith("01", 2)) {
                                    // 注册或注销成功，改payload为格式2，转发给BGP, 控制器不返回注册注销响应报文
                                    int total_len = 1 + 20 + 16 + 16 + 4 + BGP_NUM * 16;
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream(total_len);
                                    try {
                                        baos.write(Arrays.copyOfRange(payload, 0, 37));
                                        baos.write(SocketUtil.hexStringToBytes(fromSwitchIP_hex));
                                        baos.write(SocketUtil.int2Bytes(BGP_NUM));
                                        for (int i = 0; i < BGP_NUM; i++) {
                                            String BGP_NA = bgp_Na_List.get(i);
                                            baos.write(SocketUtil.hexStringToBytes(HexUtil.ip2HexString(BGP_NA, 32)));
                                        }
                                    } catch (Exception e) {
                                        log.error(e.getMessage());
                                        e.printStackTrace();
                                        return;
                                    }
                                    byte[] byteToBGP = baos.toByteArray();
                                    nrsPkt.setPayload(new Data(byteToBGP));
                                    nrsPkt.setSource((byte) 0x01);
                                    idpPkt.setPayload(nrsPkt);
                                    ipv6Pkt.setPayload(idpPkt);
                                    String BGP_NA = bgp_Na_List.get(0); // TODO: 2021/8/23 暂时从BGP列表中选取选取第一个发送
                                    ipv6Pkt.setDestinationAddress(SocketUtil.hexStringToBytes(HexUtil.ip2HexString(BGP_NA, 32)));
                                    ethPkt.setPayload(ipv6Pkt);
                                } else {
                                    flag = false;
                                    log.error("Receive IRS register/deregister response status is not success");
                                }
                            } else {
                                flag = false;
                                log.error("Receive packets from IRS is null!");
                            }
                        } else {
                            flag = false;
                            log.error("Register message format is wrong, nrs payload is null!");
                        }
                        // 如果注册/注销不成功，向用户发送注册/注销失败响应格式1
                        if (!flag) {
                            byte[] payload_format1 = new byte[38];
                            if (payload != null) {
                                String type = Objects.requireNonNull(SocketUtil.bytesToHexString(payload)).startsWith("6f") ? "70" : "74";
                                System.arraycopy(SocketUtil.hexStringToBytes(type), 0, payload_format1, 0, 1);
                                System.arraycopy(SocketUtil.hexStringToBytes("00"), 0, payload_format1, 1, 1); // TODO: 2021/8/25 假设"00"表示失败
                                System.arraycopy(payload, 1, payload_format1, 2, 36);
                            }
                            nrsPkt.setPayload(new Data(payload_format1));
                            nrsPkt.setQueryType(SocketUtil.hexStringToBytes(queryType.equals("01") ? "03" : "04")[0]);
                            idpPkt.setPayload(nrsPkt);
                            ipv6Pkt.setPayload(idpPkt);
                            ipv6Pkt.setDestinationAddress(ipv6Pkt.getSourceAddress());
                            ipv6Pkt.setSourceAddress(SocketUtil.hexStringToBytes(fromSwitchIP_hex));
                            ethPkt.setPayload(ipv6Pkt);
                        }
                    }
                    // TODO: 2021/8/25 register response or deregister response
                    else if (queryType.equals("03") || queryType.equals("04")) {
                        byte[] payload = nrsPkt.getPayload().serialize();
                        if (payload != null && nrsPkt.getSource() == 0x01) {
                            // 收到BGP发来的注册/注销失败响应报文，反操作注册注销
                            String sendToIRSMsg = Util.msgFormat2ToIRSFormat(SocketUtil.bytesToHexString(payload));
                            byte[] receive = SendAndRecv.throughUDP(IRS_NA, IRS_port, SocketUtil.hexStringToBytes(sendToIRSMsg));
                            if (receive != null && Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).startsWith("01", 2)) {
                                // 转发给用户注册/注销失败响应报文，响应报文格式1
                                byte[] payload_format1 = new byte[38];
                                System.arraycopy(payload, 0, payload_format1, 0, payload_format1.length);
                                nrsPkt.setPayload(new Data(payload_format1));
                                nrsPkt.setSource((byte) 0x00);
                                idpPkt.setPayload(nrsPkt);
                                ipv6Pkt.setDestinationAddress(Arrays.copyOfRange(payload, 22, 38));
                                ipv6Pkt.setPayload(idpPkt);
                                ethPkt.setPayload(ipv6Pkt);
                            } else {
                                log.error("IRS don't response correctly");
                            }
                        }
                    }
                    // TODO: 2021/8/22 resolve
                    else if (queryType.equals("05")) {
//                        byte[] payload = nrsPkt.getPayload().serialize();
                        // 发送给解析单点解析请求 TODO: 暂时未考虑tag解析
                        String resolveMsg = "71" + "000000" + Util.getRandomRequestID() + dstEid + Util.getTimestamp();
                        byte[] receive = SendAndRecv.throughUDP(IRS_NA, IRS_port, SocketUtil.hexStringToBytes(resolveMsg));
                        String na = HexUtil.zeros(32);
                        if (receive[1] == 1) {
                            int na_num = SocketUtil.bytes2Int(Arrays.copyOfRange(receive, 12, 14), 0);
                            if (na_num > 0) {
                                // 解析成功!，将返回的NA的第一个填入ipv6的dstIP字段 TODO：是否有选ip的策略？
                                na = SocketUtil.bytesToHexString(Arrays.copyOfRange(receive, 34, 50));
//                                eid_na_map.put(dstEid, na);
                            } else {
                                // 解析不到
                                String source = HexUtil.byte2HexString(nrsPkt.getSource());
                                if (source.equals("00")) {
                                    // 包是从客户端发来的
                                    String BGP_NA = bgp_Na_List.get(0);
                                    na = HexUtil.ip2HexString(BGP_NA, 32);
                                } else if (source.equals("01")) {
                                    // 包是从BGP发来的
                                    nrsPkt.setQueryType(SocketUtil.hexStringToBytes("06")[0]);
                                    nrsPkt.setNA(SocketUtil.hexStringToBytes(fromSwitchIP_hex));
                                    na = bgp_Na_List.get(0); // TODO: 2021/8/24 这里我怎么知道哪个BGP给我发的请求？
                                    idpPkt.setPayload(nrsPkt);
                                    ipv6Pkt.setPayload(idpPkt);
                                } else {
                                    log.error("packet source is unknown!");
                                }
                            }
                        } else {
                            // 解析失败会怎么处理？
                            log.error("resolve in irs failed, maybe IRS cannot connect successfully");
                        }
                        ipv6Pkt.setDestinationAddress(SocketUtil.hexStringToBytes(na));
                        ethPkt.setPayload(ipv6Pkt);
                        // TODO: 2021/8/16 是否下发流表项，下发策略？
                        if (dstEid != null) {
                            {
                                FlowRule blockFlowRule = buildSetAddrAndGotoTableInstructionBlock(deviceId, 0, na, MobilityTableID_for_Ipv6);
                                flowRuleService.applyFlowRules(blockFlowRule);
                                instructionBlockSentCache.add(blockFlowRule);
                            }
                            {
                                FlowRule blockFlowRule = buildSetAddrAndGotoTableInstructionBlock(deviceId, 4, na, MobilityTableID_for_Vlan);
                                flowRuleService.applyFlowRules(blockFlowRule);
                                instructionBlockSentCache.add(blockFlowRule);
                            }
                            {
                                FlowRule blockFlowRule = buildSetAddrAndGotoTableInstructionBlock(deviceId, 8, na, MobilityTableID_for_Qinq);
                                flowRuleService.applyFlowRules(blockFlowRule);
                                instructionBlockSentCache.add(blockFlowRule);
                            }
                            if (allInstructionBlocksInstalled(deviceId)) {
                                addSetIPDstAddrAndGoToTableFlowEntry(deviceId, dstEid, na, SEANRS_TABLEID_IPV6, MobilityTableID_for_Ipv6);
                                addSetIPDstAddrAndGoToTableFlowEntry(deviceId, dstEid, na, SEANRS_TABLEID_Vlan, MobilityTableID_for_Vlan);
                                addSetIPDstAddrAndGoToTableFlowEntry(deviceId, dstEid, na, SEANRS_TABLEID_Qinq, MobilityTableID_for_Qinq);
                            }
                        }
                    }
                    FlowModTreatment flowModTreatment = new FlowModTreatment(buildGotoTableInstructionBlock(deviceId, MobilityTableID_for_Ipv6).id().value());
                    TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                    builder.extension(flowModTreatment, deviceId);
                    byte[] outPutBytes = ethPkt.serialize();
                    ByteBuffer bf = ByteBuffer.allocate(outPutBytes.length);
                    bf.put(outPutBytes).flip();
                    packetService.emit(new DefaultOutboundPacket(deviceId, builder.build(), bf));
                }
                // 不是网内解析请求则不处理
                else {
                    log.info("receive a SeaDP packet without nrs header, go to next processor");
                }
            }
        }
    }


}