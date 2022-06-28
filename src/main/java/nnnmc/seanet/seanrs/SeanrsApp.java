package nnnmc.seanet.seanrs;

import nnnmc.seanet.controller.api.FlowRuleCache;
import nnnmc.seanet.seanrs.protocol.IDP;
import nnnmc.seanet.seanrs.protocol.NRS;
import nnnmc.seanet.seanrs.util.HexUtil;
import nnnmc.seanet.seanrs.util.SendAndRecv;
import nnnmc.seanet.seanrs.util.SocketUtil;
import nnnmc.seanet.seanrs.util.Util;
import org.onlab.packet.*;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.floodlightpof.protocol.OFMatch20;
import org.onosproject.floodlightpof.protocol.instruction.*;
import org.onosproject.floodlightpof.protocol.table.OFTableType;
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.*;
import org.onosproject.pof.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static nnnmc.seanet.seanrs.OsgiPropertyConstants.*;
import static org.onlab.util.Tools.groupedThreads;


@SuppressWarnings("UnnecessaryLocalVariable")
@Component(
        immediate = true,
        property = {
                SEANRS_TABLEID_IPV6 + ":Integer=" + NRS_TABLE_BASE_ID_DEFAULT,
                SEANRS_NEXT_TABLEID + ":Integer=" + SEANRS_NEXT_TABLEID_DEFAULT,
                TABLESIZE + ":Integer=" + SIZE_DEFAULT,
                IRS_PORT_NAME + ":Integer=" + IRS_PORT_DEFAULT,
                BGP_NUM_NAME + ":Integer=" + BGP_NUM_DEFAULT,
                BGP_NA_NAME + ":String=" + BGP_NA,
                IRS_NA_NAME + ":String=" + IRS_NA_DEFAULT,
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

    protected int seanrs_tableid_ipv6 = NRS_TABLE_BASE_ID_DEFAULT;
    protected int seanrs_tableid_vlan = NRS_TABLE_BASE_ID_DEFAULT + 10;
    protected int seanrs_tableid_qinq = NRS_TABLE_BASE_ID_DEFAULT + 20;
    protected int seanrs_next_tableid = SEANRS_NEXT_TABLEID_DEFAULT;
    protected int seanrs_next_tableid_for_vlan = SEANRS_NEXT_TABLEID_DEFAULT + 10;
    protected int seanrs_next_tableid_for_qinq = SEANRS_NEXT_TABLEID_DEFAULT + 20;

    private static final int LOCAL_PKTIN_PRIORITY = 5000;
    private static final int FORWARD_PRIORITY = 4000;
    private static final int REGISTER_PRIORITY = 3000;
    private static final int RESOLVE_PRIORITY = 2500;
    private static final int TOAE_PRIORITY = 2000;
    private static final int PKTIN_PRIORITY = 1500;
    private static final int DEFAULT_PRIORITY = 1000;
    private static final int ETH_HEADER_LEN = 14 * 8;
    private static final int FIRST_TABLE = 0;
    private static final int FIB_TABLE = 2;
    private static final String NA_ZEROS = HexUtil.zeros(32);
    private static int tableSize = SIZE_DEFAULT;
    private static String irsNa = IRS_NA_DEFAULT;
    private static int irsPort = IRS_PORT_DEFAULT;
    private static final List<String> bgp_Na_List = new ArrayList<>();
    private static int bgpNum = BGP_NUM_DEFAULT;
    private static String bgpNaStr = BGP_NA;

    private final FlowRuleCache instructionBlockSentCache = new FlowRuleCache();
    private final FlowRuleCache instructionBlockInstalledCache = new FlowRuleCache();
    private final FlowRuleCache flowEntrySentCache = new FlowRuleCache();
    private final FlowRuleCache tableSentCache = new FlowRuleCache();
    private final FlowRuleCache tableInstalledCache = new FlowRuleCache();

    private final SeaNRSFlowRuleListener flowRuleListener = new SeaNRSFlowRuleListener();
    private final InternalDeviceListener deviceListener = new InternalDeviceListener();
    private final InternalMastershipListener mastershipListener = new InternalMastershipListener();
    private final SeaNRSPacketProcessor processor = new SeaNRSPacketProcessor();
    private final HashMap<DeviceId, ArrayList<String>> deviceInterfacesMap = new HashMap<>();

    private ExecutorService executor;

    protected ApplicationId appId;
    private NodeId local;

    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        irsNa = Tools.get(properties, IRS_NA_NAME);
        bgpNum = Tools.getIntegerProperty(properties, BGP_NUM_NAME, BGP_NUM_DEFAULT);
        irsPort = Tools.getIntegerProperty(properties, IRS_PORT_NAME, IRS_PORT_DEFAULT);
        tableSize = Tools.getIntegerProperty(properties, TABLESIZE, SIZE_DEFAULT);
        bgpNaStr = Tools.get(properties, BGP_NA_NAME);
        seanrs_tableid_ipv6 = Tools.getIntegerProperty(properties, SEANRS_TABLEID_IPV6, NRS_TABLE_BASE_ID_DEFAULT);
        seanrs_tableid_vlan = seanrs_tableid_ipv6 + 10;
        seanrs_tableid_qinq = seanrs_tableid_ipv6 + 20;
        seanrs_next_tableid = Tools.getIntegerProperty(properties, SEANRS_NEXT_TABLEID, SEANRS_NEXT_TABLEID_DEFAULT);
        seanrs_next_tableid_for_vlan = seanrs_next_tableid + 10;
        seanrs_next_tableid_for_qinq = seanrs_next_tableid + 20;
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
    }

    @Activate
    public void activate(ComponentContext context) {

        appId = coreService.registerApplication("org.onosproject.sea_nrs");
        local = clusterService.getLocalNode().id();
        for (Device device : deviceService.getAvailableDevices()) {
            ArrayList<String> interfaceList = new ArrayList<>();
            for (Interface anInterface : interfaceService.getInterfacesByDeviceId(device.id())) {
                for (InterfaceIpAddress interfaceIpAddress : anInterface.ipAddressesList()) {
                    Ip6Address ip6Address = interfaceIpAddress.ipAddress().getIp6Address();
                    if (ip6Address != null) {
                        interfaceList.add(HexUtil.ip2HexString(ip6Address.toString(), 32));
                    }
                }
            }
            deviceInterfacesMap.put(device.id(), interfaceList);
        }
        log.debug("device: [interfaces]: {}", deviceInterfacesMap);

        instructionBlockSentCache.clear();
        instructionBlockInstalledCache.clear();
        flowEntrySentCache.clear();
        tableSentCache.clear();
        tableInstalledCache.clear();

        executor = Executors.newSingleThreadExecutor(groupedThreads("onos/seanet/sea_nrs", "main", log));
        flowRuleService.addListener(flowRuleListener);
        deviceService.addListener(deviceListener);
        mastershipService.addListener(mastershipListener);

        componentConfigService.registerProperties(getClass());
        modified(context);

        bgp_Na_List.addAll(Arrays.asList(bgpNaStr.split(",")));
        //Send flow tables to the switches that have been connected
        for (Device device : deviceService.getAvailableDevices()) {
            if (device.id().toString().startsWith("pof")) {
                DeviceId deviceId = device.id();
                NodeId master = mastershipService.getMasterFor(deviceId);
                if (Objects.equals(local, master)) {
                    addDefaultInstructionBlock(deviceId);
                    log.debug("activate: {} add Default Instruction Block for NRS App. allInstructionBlocksInstalled(deviceId)={}, ",
                            deviceId, allInstructionBlocksInstalled(deviceId));
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
        deviceService.removeListener(deviceListener);
        mastershipService.removeListener(mastershipListener);

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
        log.info("========== build Table 0 for device {} ==========", deviceId);
        {
            FlowRule table0 = createFirstTable(deviceId, FIRST_TABLE); //table0
            flowRuleService.applyFlowRules(table0);
            tableSentCache.add(table0);
        }

        log.info("========== build NRS Table begin for device {} ==========", deviceId);
        {
            FlowRule table1 = createNRSTable(deviceId, seanrs_tableid_ipv6, seanrs_next_tableid); //ipv6
            flowRuleService.applyFlowRules(table1);
            tableSentCache.add(table1);
        }

        log.info("========== build Table 2 for device {} ==========", deviceId);
        {
            FlowRule table2 = createFibTable(deviceId, FIB_TABLE); //table0
            flowRuleService.applyFlowRules(table2);
            tableSentCache.add(table2);
        }
    }

    private FlowRule createNRSTable(DeviceId deviceId, int tableId, int gotoTableID) {
        log.debug("---------- createNRSTable{}, in {} begin ----------", tableId, deviceId);

        OFMatch20Selector selector = new OFMatch20Selector();
        selector.addOFMatch20(FieldId.PACKET, 24 * 8, 16 * 8); // DEST_IPV6_ADDR
        selector.addOFMatch20(FieldId.PACKET, 40 * 8, 8); // IDP_NextHeader
        selector.addOFMatch20(FieldId.PACKET, 64 * 8, 16 * 8); // DEST_EID (1-16Byte)
        selector.addOFMatch20(FieldId.PACKET, 80 * 8, 4 * 8); // DEST_EID (16-20Byte)

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(new TableModTreatment(OFTableType.OF_EM_TABLE, tableSize, "NRSTable",
                buildSuperDefaultInstructionBlock(deviceId, gotoTableID).id().value()), deviceId);
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

    private FlowRule createFirstTable(DeviceId deviceId, int tableId) {
        log.debug("-- createFirstTable{}, in {} begin --", tableId, deviceId);

        OFMatch20Selector selector = new OFMatch20Selector();
        selector.addOFMatch20(FieldId.PACKET, 12 * 8, 2 * 8); // ETH_TYPE
        selector.addOFMatch20(FieldId.PACKET, ETH_HEADER_LEN + 40 * 8, 8); // IDP_NextHeader

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(new TableModTreatment(OFTableType.OF_MM_TABLE, tableSize, "FirstTable"), deviceId);
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

    private FlowRule createFibTable(DeviceId deviceId, int tableId) {
        log.debug("-- createFibTable{}, in {} begin --", tableId, deviceId);

        OFMatch20Selector selector = new OFMatch20Selector();
        selector.addOFMatch20(FieldId.PACKET, 24 * 8, 16 * 8); // DEST_IPV6_ADDR

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(new TableModTreatment(OFTableType.OF_MM_TABLE, tableSize, "FibTable"), deviceId);
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
        if (tableInstalled) log.debug("------- NRS tables installed -------");
        return tableInstalled;
    }

    // ================= Instruction Block =================

    private void addDefaultInstructionBlock(DeviceId deviceId) {
        log.info("========== add default instruction block for {} ==========", deviceId);
        {
            FlowRule blockFlowRule = buildPacketInInstructionBlock(deviceId);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildSetOffsetAndGotoTableInstructionBlock(deviceId, seanrs_tableid_ipv6);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildSetOffsetAndGotoTableInstructionBlock(deviceId, seanrs_next_tableid);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildDropInstructionBlock(deviceId);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildOutpInstructionBlock(deviceId, 0);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildOutpInstructionBlock(deviceId, 1);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
        {
            FlowRule blockFlowRule = buildSuperDefaultInstructionBlock(deviceId, seanrs_next_tableid);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
    }

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

    private FlowRule buildDropInstructionBlock(DeviceId deviceId) {
        log.debug("---------- build Drop instruction block for {} ----------", deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();

        instructionBlockModTreatment.addInstruction(new OFInstructionDrop());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildOutpInstructionBlock(DeviceId deviceId, int portid) {
        log.debug("---------- build Output instruction block for {} ----------", deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();

        instructionBlockModTreatment.addInstruction(new OFInstructionOutput(OutPutType.OUTP, portid));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildToAEInstructionBlock(DeviceId deviceId) {
        log.debug("---------- build To AE instruction block for {} ----------", deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();

        instructionBlockModTreatment.addInstruction(new OFInstructionOutput(OutPutType.OUTAE, 0xffff));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildSetAddrAndGotoTableInstructionBlock(DeviceId deviceId, String ipAddress, int gotoTableId) {
        log.debug("---------- build SetAddr&GotoTable instruction block for {} ----------", deviceId);
        OFMatch20 ofMatch20 = new OFMatch20(FieldId.PACKET, 24 * 8, 16 * 8); // IPv6 dstAddr
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

    private FlowRule buildSetOffsetAndGotoTableInstructionBlock(DeviceId deviceId, int gotoTableId) {
        log.debug("---------- build GotoTable{} instruction block for {} ----------", gotoTableId, deviceId);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionSetPacketOffset(14));
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildSuperDefaultInstructionBlock(DeviceId deviceId, int gotoTableId) {
        log.debug("---------- build super-default{} instruction block for {} ----------", gotoTableId, deviceId);
        OFMatch20 idpNhField = new OFMatch20(FieldId.PACKET, 40 * 8, 8);
        OFMatch20 dstIpField = new OFMatch20(FieldId.PACKET, 24 * 8, 16 * 8);
        OFMatch20 queryTypeField = new OFMatch20(FieldId.PACKET, 85 * 8, 8); // NRS_QueryType
        OFMatch20 sourceField = new OFMatch20(FieldId.PACKET, 87 * 8, 8); // NRS_Source
        OFMatch20 inportField = new OFMatch20(FieldId.INPORT, 0, 2 * 8); // In port
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(16, idpNhField, "10"));
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, queryTypeField, "03"));
        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, queryTypeField, "04"));
        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, sourceField, "02"));
        instructionBlockModTreatment.addInstruction(new OFInstructionOutput(OutPutType.OUTAE, 0xffff));
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(9, dstIpField, HexUtil.zeros(32)));
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, queryTypeField, "01"));
        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, queryTypeField, "02"));
        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(5, queryTypeField, "05"));
        instructionBlockModTreatment.addInstruction(new OFInstructionBranch(2, inportField, "ffff"));
        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        instructionBlockModTreatment.addInstruction(new OFInstructionOutput(OutPutType.OUTAE, 0xffff));
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        instructionBlockModTreatment.addInstruction(new OFInstructionDrop());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private boolean allInstructionBlocksInstalled(DeviceId deviceId) {
        boolean instructionBlockInstalled;
        if (instructionBlockSentCache.size(deviceId) == 0) {
            return false;
        }
        instructionBlockInstalled = instructionBlockSentCache.contrains(instructionBlockInstalledCache, deviceId);
        if (instructionBlockInstalled) log.debug("------- NRS instruction blocks installed -------");
        return instructionBlockInstalled;
    }

    // =================== Flow Entries ======================

    private void addDefaultFlowEntry(DeviceId deviceId) {
        log.info("========== add default flow entry for device:{} ==========", deviceId);
        try {
//          add drop entry and goto nrs_table entry for first table
            addDropFlowEntry(deviceId, FIRST_TABLE);
            addFirstGoToTableFlowEntry(deviceId, FIRST_TABLE, seanrs_next_tableid, "00", PKTIN_PRIORITY);
            addFirstGoToTableFlowEntry(deviceId, FIRST_TABLE, seanrs_tableid_ipv6, "FF", FORWARD_PRIORITY);

//          add fib match ipv6_address action: output port entry for fib table
            addMatchIPv6dstAndOutPFlowEntry(deviceId, FIB_TABLE, "2400dd01103700090009000000000009", "FFFFFFFFFFFFFFFF0000000000000000", 0);
            addMatchIPv6dstAndOutPFlowEntry(deviceId, FIB_TABLE, "2400dd01103700100020000000000020", "FFFFFFFFFFFFFFFF0000000000000000", 1);

//          add packet_in entry for nrs_table
            addPacketInFlowEntry(deviceId, seanrs_tableid_ipv6);

////          add super default entry for nrs_table
//            addSuperDefaultFlowEntry(deviceId, seanrs_tableid_ipv6, seanrs_next_tableid);
//            addSuperDefaultFlowEntry(deviceId, seanrs_tableid_vlan, seanrs_next_tableid_for_vlan);
//            addSuperDefaultFlowEntry(deviceId, seanrs_tableid_qinq, seanrs_next_tableid_for_qinq);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private void addPacketInFlowEntry(DeviceId deviceId, int tableId) {
        log.debug("---------- add PacketIn flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, (24 * 8), (16 * 8), NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, 64 * 8, 16 * 8, HexUtil.duplicates('F', 32), HexUtil.duplicates('F', 32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, 80 * 8, 4 * 8, HexUtil.duplicates('F', 8), HexUtil.duplicates('F', 8)); // DEST_EID (16-20Byte)
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

    private void addRegisterPacketInFlowEntry(DeviceId deviceId, int tableId, String nrs_qt) {
        log.debug("---------- add Register and Deregister PacketIn flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        if (tableId == seanrs_tableid_vlan) {
            offset = 4;
        } else if (tableId == seanrs_tableid_qinq) {
            offset = 8;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        selector.addOFMatchX("NRSQueryType", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 85 * 8, 8, nrs_qt, "FF"); // NRS QueryType
        selector.addOFMatchX("Inport", FieldId.INPORT, 0, 16, "FFFF", "0000"); // In port = from AE
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
                .withPriority(REGISTER_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addResolveCachePacketInFlowEntry(DeviceId deviceId, int tableId, String IPMask) {
        log.debug("---------- add Resolve Cache Miss PacketIn flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        if (tableId == seanrs_tableid_vlan) {
            offset = 4;
        } else if (tableId == seanrs_tableid_qinq) {
            offset = 8;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, IPMask);
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        selector.addOFMatchX("NRSQueryType", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 85 * 8, 8, "05", "FF"); // NRS QueryType
        selector.addOFMatchX("Inport", FieldId.INPORT, 0, 16, "FFFF", "FFFF"); // In port = from AE
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
                .withPriority(RESOLVE_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addDropFlowEntry(DeviceId deviceId, int tableId) {
        log.debug("---------- add DROP flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("ETH_TYPE", FieldId.PACKET, 12 * 8, 2 * 8, "86dd", "0000"); // ETH_TYPE
        selector.addOFMatchX("IDP_NH", FieldId.PACKET, ETH_HEADER_LEN + 40 * 8, 8, "10", "00");
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        FlowModTreatment flowModTreatment = new FlowModTreatment(buildDropInstructionBlock(deviceId).id().value());

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

    private void addMatchIPv6dstAndOutPFlowEntry(DeviceId deviceId, int tableId, String ipv6DstAddr, String mask, int outPort) {
        log.debug("---------- add DROP flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPv6_DST", FieldId.PACKET, 24 * 8, 16 * 8, ipv6DstAddr, mask); // DEST_IPV6_ADDR
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        FlowModTreatment flowModTreatment = new FlowModTreatment(buildOutpInstructionBlock(deviceId, outPort).id().value());

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

    private void addOutAEFlowEntry(DeviceId deviceId, int tableId) {
        log.debug("---------- add Output to AE flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        if (tableId == seanrs_tableid_vlan) {
            offset = 4;
        } else if (tableId == seanrs_tableid_qinq) {
            offset = 8;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        selector.addOFMatchX("NRSQueryType", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 85 * 8, 8, "05", "FF"); // NRS QueryType
        selector.addOFMatchX("Inport", FieldId.INPORT, 0, 16, "FFFF", "0000"); // In port = from AE        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        FlowModTreatment flowModTreatment = new FlowModTreatment(buildToAEInstructionBlock(deviceId).id().value());

        //construct treatment
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);


        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(TOAE_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addMatchLocalIPAndPacketInFlowEntry(DeviceId deviceId, int tableId, String localIp) {
        log.debug("---------- add Match Local IP And PacketIn flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        if (tableId == seanrs_tableid_vlan) {
            offset = 4;
        } else if (tableId == seanrs_tableid_qinq) {
            offset = 8;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), localIp, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        selector.addOFMatchX("NRSQueryType", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 85 * 8, 8, "05", "00"); // NRS QueryType
        selector.addOFMatchX("Inport", FieldId.INPORT, 0, 16, "FFFF", "0000"); // In port = from AE
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
                .withPriority(LOCAL_PKTIN_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addSetIPDstAddrAndGoToTableFlowEntry(DeviceId deviceId, String eid, String na, int tableId, int gotoTableId) {
        log.debug("---------- add Set IPDstAddr And GoToTable flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, (24 * 8), 16 * 8, NA_ZEROS, HexUtil.duplicates('F', 32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, (40 * 8), 8, "10", "FF");
        selector.addOFMatchX("destEID16", FieldId.PACKET, 64 * 8, 16 * 8, eid.substring(0, 32), HexUtil.duplicates('F', 32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, 80 * 8, 4 * 8, eid.substring(32, 40), HexUtil.duplicates('F', 8)); // DEST_EID (16-20Byte)
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        // construct treatment
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetAddrAndGotoTableInstructionBlock(deviceId, na, gotoTableId).id().value());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);

        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(FORWARD_PRIORITY)
                .makeTemporary(10)  // 10s之后超时删除，需要数据包触发
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addDefaultGoToTableFlowEntry(DeviceId deviceId, int tableId, int goToTableId) {
        log.debug("---------- add default GoToTable flow entry for table{}, device:{} ----------", tableId, deviceId);
        // packet offset
        int offset = 0;
        if (tableId == seanrs_tableid_vlan) {
            offset = 4;
        } else if (tableId == seanrs_tableid_qinq) {
            offset = 8;
        }
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.zeros(32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + (40 * 8), (8), "10", "00");
        selector.addOFMatchX("destEID16", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, offset * 8 + ETH_HEADER_LEN + 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetOffsetAndGotoTableInstructionBlock(deviceId, goToTableId).id().value());

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

    private void addSuperDefaultFlowEntry(DeviceId deviceId, int tableId, int goToTableId) {
        log.debug("---------- add default flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, (24 * 8), (16 * 8), NA_ZEROS, HexUtil.zeros(32));
        selector.addOFMatchX("NRS_NextHeader", FieldId.PACKET, (40 * 8), (8), "10", "00");
        selector.addOFMatchX("destEID16", FieldId.PACKET, 64 * 8, 16 * 8, HexUtil.zeros(32), HexUtil.zeros(32)); // DEST_EID (1-16Byte)
        selector.addOFMatchX("destEID4", FieldId.PACKET, 80 * 8, 4 * 8, HexUtil.zeros(8), HexUtil.zeros(8)); // DEST_EID (16-20Byte)
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSuperDefaultInstructionBlock(deviceId, goToTableId).id().value());

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

    private void addFirstGoToTableFlowEntry(DeviceId deviceId, int tableId, int goToTableId, String mask, int priority) {
        log.debug("---------- add First GoToTable flow entry for table{}, device:{} ----------", tableId, deviceId);
        // construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("ETH_TYPE", FieldId.PACKET, 12 * 8, 2 * 8, "86dd", "FFFF"); // ETH_TYPE-ipv6
        selector.addOFMatchX("IDP_NH", FieldId.PACKET, ETH_HEADER_LEN + 40 * 8, 8, "10", mask);
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetOffsetAndGotoTableInstructionBlock(deviceId, goToTableId).id().value());
        //construct treatment
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);


        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(priority)
                .makePermanent()
                .makeStored(false)
                .build();
        flowEntrySentCache.add(flowRule);
        flowRuleService.applyFlowRules(flowRule);
    }

    // ====================== listener =========================

    /**
     * listener 监听所有flowRule相关事件，包括流表的添加和删除、指令块儿的添加和删除、表项的添加和删除都会触发这个listener
     */
    private class SeaNRSFlowRuleListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule rule = event.subject();
            //noinspection SwitchStatementWithTooFewBranches
            switch (event.type()) {
                // case RULE_ADDED:
                case RULE_ADD_REQUESTED: {
                    DeviceId deviceId = rule.deviceId();
                    if (deviceId.toString().startsWith("pof")) {
                        NodeId master = mastershipService.getMasterFor(deviceId);
                        if (Objects.equals(local, master)) {
                            switch (rule.type()) {
                                case FlowRuleType.INSTRUCTION_BLOCK_MOD: //instruction block add
                                {
                                    executor.execute(() -> {
                                        if (instructionBlockSentCache.contains(rule)) {
//                                            log.debug("INSTRUCTION_BLOCK_MOD instructionBlockSentCache.contains {}\n", rule);
                                            instructionBlockInstalledCache.add(rule);
                                            //需要的默认指令块全部添加完毕，则下发流表;
                                            if (allInstructionBlocksInstalled(deviceId) && !getProcessStatusByDeviceId(deviceId)) {
                                                //log.debug("INSTRUCTION_BLOCK_MOD call onDefaultBlocksAddedByDevice,add default entries\n");
                                                executor.execute(() -> {
                                                    buildNRSTables(deviceId);
                                                    processedSetAdd(deviceId);
                                                });
                                            }
                                        }
                                    });
                                    break;
                                }
                                case FlowRuleType.TABLE_MOD: //flow table add
                                {
                                    if (tableSentCache.contains(rule)) {
                                        tableInstalledCache.add(rule);
                                        // 如果该设备上的流表已经下发完成则开始下发表项
                                        if (allNRSTablesInstalled(deviceId)) {
                                            executor.execute(() -> addDefaultFlowEntry(deviceId));
                                        }
                                    }
                                }
                                break;
                                default:
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            //noinspection SwitchStatementWithTooFewBranches
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED: {
                    executor.execute(() -> {
                        DeviceId deviceId = event.subject().id();
                        log.debug("seanet switch deviceId={}, deviceService.isAvailable(deviceId)={}, tableInstalledCache.size(deviceId)={}",
                                deviceId, deviceService.isAvailable(deviceId), tableInstalledCache.size(deviceId));
                        if (!deviceService.isAvailable(deviceId)) {
                            removeOldFlowRules(deviceId);
                            flowEntrySentCache.remove(deviceId);
                            instructionBlockSentCache.remove(deviceId);
                            tableSentCache.remove(deviceId);
                            instructionBlockInstalledCache.remove(deviceId);
                            tableInstalledCache.remove(deviceId);
                            resetStatusByDeviceId(deviceId);
                            log.debug("init DeviceEvent : deviceId={}, event.type()={}, event.subject()={}, tableInstalledCache.size(deviceId)={}.",
                                    deviceId, event.type(), event.subject(), tableInstalledCache.size(deviceId));
                        }
                    });
                }
                break;
                default:
                    break;
            }
        }
    }

    private class InternalMastershipListener implements MastershipListener {
        @Override
        public void event(MastershipEvent event) {
            DeviceId deviceId = event.subject();
            //noinspection SwitchStatementWithTooFewBranches
            switch (event.type()) {
                case MASTER_CHANGED: {
                    NodeId master = mastershipService.getMasterFor(deviceId);
                    if (deviceId.toString().startsWith("pof")) {
                        if (Objects.equals(local, master) && (tableSentCache.size(deviceId) == 0)) {
                            addDefaultInstructionBlock(deviceId);
                        } else {
                            executor.execute(() -> {
                                removeOldFlowRules(deviceId);
                                instructionBlockSentCache.remove(deviceId);
                                instructionBlockInstalledCache.remove(deviceId);
                                flowEntrySentCache.remove(deviceId);
                                tableSentCache.remove(deviceId);
                                tableInstalledCache.remove(deviceId);
                            });
                        }
                    }
                }
                break;
                default:
                    break;
            }
        }
    }

    // ====================== processor =========================

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

    // TODO: 2021/7/24 这里是重点，根据packetEID改ip，然后goto Mobility表, 进行后续业务逻辑
    private class SeaNRSPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            nrsPacketInProcess(context);
//            onlyPktOut(context);
        }

        /**
         * 用于测试，直接把收上来的包从收包端口发回去
         *
         * @param context 数据包
         */
        private void onlyPktOut(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            ConnectPoint ingressPort = pkt.receivedFrom();
            DeviceId deviceId = ingressPort.deviceId();
            TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
            builder.setOutput(ingressPort.port());
            packetService.emit(new DefaultOutboundPacket(deviceId, builder.build(), pkt.unparsed()));
        }

        private void nrsPacketInProcess(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            ConnectPoint ingressPort = pkt.receivedFrom();
            Interface anInterface = interfaceService.getInterfacesByPort(ingressPort).stream().findFirst().orElse(null);
            if (anInterface == null) {
                //log.info(">>>> packet ingress port: " + ingressPort.toString() + " interface is fromAE <<<<");
                anInterface = interfaceService.getInterfacesByDeviceId(ingressPort.deviceId()).stream().findFirst().orElse(null);
            }
            IpAddress ipAddress = Objects.requireNonNull(anInterface).ipAddressesList().get(1).ipAddress();
            String fromSwitchIP = ipAddress.toInetAddress().getHostAddress();
            String fromSwitchIP_hex = HexUtil.ip2HexString(fromSwitchIP, 32);
            //log.info(">>>> receive pkt from switch, ip: " + fromSwitchIP + ", port: " + ingressPort.port().toLong() + " <<<<");
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
                log.debug("receive UDP packet, content: {}", SocketUtil.bytesToHexString(ipv6Pkt.serialize()));
            } else if (nextHdr == 0x99) {
                // TODO: 2021/7/27 IDP 暂定使用扩展包头的方式
                IDP idpPkt = new IDP().unpack(ipv6Pkt.getPayload().serialize());
                String nextHeader = HexUtil.byte2HexString(idpPkt.getNextHeader());
                String dstEid = idpPkt.getDestEID();
                // 处理网内解析请求 0x10
                if (nextHeader.equals("10")) {
                    NRS nrsPkt = new NRS().unpack(idpPkt.getPayload());
                    String queryType = HexUtil.byte2HexString(nrsPkt.getQueryType());
                    // TODO: 2021/8/22 register or deregister
                    //noinspection IfCanBeSwitch
                    if (queryType.equals("01") || queryType.equals("02")) {
                        boolean flag = true; // 标记在控制器上是否注册成功
                        byte[] payload = nrsPkt.getPayload();
                        if (payload != null) {
                            // 转发注册或注销请求给解析单点, 获取响应之后返回
                            String sendToIRSMsg = Util.msgFormat1ToIRSFormat(SocketUtil.bytesToHexString(payload));
                            byte[] receive = SendAndRecv.throughUDP(HexUtil.ip2HexString(irsNa, 32), irsPort, SocketUtil.hexStringToBytes(sendToIRSMsg));
                            if (receive != null) {
                                if (Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).startsWith("01", 10)) {
                                    // 注册或注销成功，改payload为格式2，转发给BGP, 控制器不返回注册注销响应报文
                                    //log.info(">>>> irs-{} response: {} <<<<", queryType.equals("01") ? "register" : "deregister",
//                                            Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).replaceAll("(00)+$", ""));
                                    int total_len = 1 + 20 + 16 + 16 + 4 + bgpNum * 16;
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream(total_len);
                                    try {
                                        baos.write(Arrays.copyOfRange(payload, 0, 37));
                                        baos.write(SocketUtil.hexStringToBytes(fromSwitchIP_hex));
                                        baos.write(SocketUtil.int2Bytes(bgpNum));
                                        for (int i = 0; i < bgpNum; i++) {
                                            String BGP_NA = bgp_Na_List.get(i);
                                            baos.write(SocketUtil.hexStringToBytes(HexUtil.ip2HexString(BGP_NA, 32)));
                                        }
                                    } catch (Exception e) {
                                        log.error(e.getMessage());
                                        e.printStackTrace();
                                        return;
                                    }
                                    byte[] byteToBGP = baos.toByteArray();
                                    nrsPkt.setPayload(byteToBGP);
                                    nrsPkt.setSource((byte) 0x01);
                                    idpPkt.setPayload(nrsPkt.pack());
                                    ipv6Pkt.setPayload(new Data(idpPkt.pack()));
                                    String BGP_NA = bgp_Na_List.get(0); // TODO: 2021/8/23 暂时从BGP列表中选取选取第一个发送
                                    ipv6Pkt.setDestinationAddress(SocketUtil.hexStringToBytes(HexUtil.ip2HexString(BGP_NA, 32)));
                                    ethPkt.setPayload(ipv6Pkt);
                                    //log.info(">>>> {} success! ready to send packet: {} to BGP: {} <<<<", queryType.equals("01") ? "register" : "deregister",
//                                            SocketUtil.bytesToHexString(ethPkt.serialize()), BGP_NA);
                                } else {
                                    flag = false;
                                    log.error("Receive IRS register/deregister response status is failed");
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
                            String isRegister = "function";
                            if (payload != null) {
                                String type = Objects.requireNonNull(SocketUtil.bytesToHexString(payload)).startsWith("6f") ? "70" : "74";
                                isRegister = type.equals("70") ? "register" : "deregister";
                                System.arraycopy(SocketUtil.hexStringToBytes(type), 0, payload_format1, 0, 1);
                                System.arraycopy(SocketUtil.hexStringToBytes("00"), 0, payload_format1, 1, 1); // TODO: 2021/8/25 假设"00"表示失败
                                System.arraycopy(payload, 1, payload_format1, 2, 36);
                            }
                            nrsPkt.setPayload(payload_format1);
                            nrsPkt.setQueryType(SocketUtil.hexStringToBytes(queryType.equals("01") ? "03" : "04")[0]);
                            idpPkt.setPayload(nrsPkt.pack());
                            ipv6Pkt.setPayload(new Data(idpPkt.pack()));
                            ipv6Pkt.setDestinationAddress(ipv6Pkt.getSourceAddress());
                            ipv6Pkt.setSourceAddress(SocketUtil.hexStringToBytes(fromSwitchIP_hex));
                            ethPkt.setPayload(ipv6Pkt);
                            byte[] sourceMACAddress = ethPkt.getSourceMACAddress();
                            ethPkt.setSourceMACAddress(ethPkt.getDestinationMACAddress());
                            ethPkt.setDestinationMACAddress(sourceMACAddress);
                            log.warn(">>>> {} failed in controller, ready to send to client response packet(format1): " +
                                    "{} <<<<", isRegister, SocketUtil.bytesToHexString(ethPkt.serialize()));
                        }
                    }

                    // TODO: 2021/8/25 register response or deregister response
                    else if (queryType.equals("03") || queryType.equals("04")) {
                        byte[] payload = nrsPkt.getPayload();
                        if (payload != null && nrsPkt.getSource() == 0x01) {
                            // 收到BGP发来的注册/注销失败响应报文（格式2），反操作注册注销
                            String sendToIRSMsg = Util.msgFormat2ToIRSFormat(SocketUtil.bytesToHexString(payload));
                            byte[] receive = SendAndRecv.throughUDP(HexUtil.ip2HexString(irsNa, 32), irsPort, SocketUtil.hexStringToBytes(sendToIRSMsg));
                            if (receive != null && Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).startsWith("01", 10)) {
                                // 转发给用户注册/注销失败响应报文，响应报文（格式1）
                                byte[] payload_format1 = new byte[38];
                                System.arraycopy(payload, 0, payload_format1, 0, payload_format1.length);
                                nrsPkt.setPayload(payload_format1);
                                nrsPkt.setSource((byte) 0x00);
                                idpPkt.setPayload(nrsPkt.pack());
                                ipv6Pkt.setDestinationAddress(Arrays.copyOfRange(payload, 22, 38)); // 目的地址修改成用户的NA
                                ipv6Pkt.setPayload(new Data(idpPkt.pack()));
                                ethPkt.setPayload(ipv6Pkt);
                                // TODO: 2021/11/30 这个地方应该把MAC填成合适的地址而不是交换一下，暂时先这样 
                                MacAddress destinationMAC = ethPkt.getDestinationMAC();
                                ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
                                ethPkt.setSourceMACAddress(destinationMAC);
                                log.warn(">>>> {} failed in bgp, ready to send to client response pkt(format1): {} <<<<",
                                        queryType.equals("03") ? "register" : "deregister", SocketUtil.bytesToHexString(ethPkt.serialize()));
                            } else {
                                log.error("IRS don't response correctly, status is not '01'");
                            }
                        }
                    }

                    // TODO: 2021/8/22 resolve
                    else if (queryType.equals("05")) {
//                        byte[] payload = nrsPkt.getPayload().serialize();
                        // 发送给解析单点解析请求 TODO: 暂时未考虑tag解析
                        String resolveMsg = "71" + "000000" + Util.getRandomRequestID() + dstEid + Util.getTimestamp();
                        byte[] receive = SendAndRecv.throughUDP(HexUtil.ip2HexString(irsNa, 32), irsPort, SocketUtil.hexStringToBytes(resolveMsg));
                        String na = HexUtil.zeros(32);
                        int na_num = SocketUtil.byteArrayToShort(receive, 12);
                        if (receive[1] == 1) {
                            //log.info(">>>> irs-resolve response: {} , NA number: {} <<<<",
//                                    Objects.requireNonNull(SocketUtil.bytesToHexString(receive)).replaceAll("(00)+$", ""), na_num);
                            if (na_num > 0) {
                                // 解析成功!，将返回的NA的第一个填入ipv6的dstIP字段 TODO：是否有选ip的策略？
                                na = SocketUtil.bytesToHexString(Arrays.copyOfRange(receive, 34, 50));
//                                eid_na_map.put(dstEid, na);
                                // 给AE发送缓存更新包, 这个包要重新走pipeline->goToTable0
                                nrsPkt.setSource(SocketUtil.hexStringToBytes("02")[0]); // FromAE -> ToAE
                                idpPkt.setPayload(nrsPkt.pack());
                                IPv6 ipv6Pkt_copy = (IPv6) ipv6Pkt.clone();
                                ipv6Pkt_copy.setPayload(new Data(idpPkt.pack()));
                                ipv6Pkt_copy.setDestinationAddress(SocketUtil.hexStringToBytes(na));
                                Ethernet eth_pkt_copy = (Ethernet) ethPkt.clone();
                                eth_pkt_copy.setPayload(ipv6Pkt_copy);
                                // 解析包的话需要把解析结果带给AE进行缓存更新
                                OFInstruction ofInstructionGotoTable1 = new OFInstructionGotoTable(FIRST_TABLE);
                                InstructionTreatment treatment_ae = new InstructionTreatment();
                                treatment_ae.addInstruction(ofInstructionGotoTable1);
                                TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                                builder.extension(treatment_ae, deviceId);
                                byte[] outPutBytes = eth_pkt_copy.serialize();
                                ByteBuffer bf = ByteBuffer.allocate(outPutBytes.length);
                                bf.put(outPutBytes).flip();
                                packetService.emit(new DefaultOutboundPacket(deviceId, builder.build(), bf));
                                //log.info(">>>> packet for updating AE cache: " + SocketUtil.bytesToHexString(outPutBytes) + " <<<<");
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
                                    nrsPkt.setSource(SocketUtil.hexStringToBytes("00")[0]);
                                    nrsPkt.setNa(fromSwitchIP_hex);
                                    na = HexUtil.ip2HexString(bgp_Na_List.get(0), 32); // TODO: 2021/8/24 这里我怎么知道哪个BGP给我发的请求？
                                    idpPkt.setPayload(nrsPkt.pack());
                                    ipv6Pkt.setPayload(new Data(idpPkt.pack()));
                                    MacAddress destinationMAC = ethPkt.getDestinationMAC();
                                    ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
                                    ethPkt.setSourceMACAddress(destinationMAC);
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
                        // TODO: 2021/8/30 是否下发流表项，下发策略？ 解析失败则不下表项？
                        if (dstEid != null && na_num != 0) {
                            {
                                FlowRule blockFlowRule = buildSetAddrAndGotoTableInstructionBlock(deviceId, na, seanrs_next_tableid);
                                flowRuleService.applyFlowRules(blockFlowRule);
                                instructionBlockSentCache.add(blockFlowRule);
                            }
                            String finalNa = na;
                            executor.execute(() -> {
                                if (!allInstructionBlocksInstalled(deviceId)) {
                                    try {
                                        Thread.sleep(1000);
                                        log.warn("allInstructionBlocksInstalled={}, sleep 1s", allInstructionBlocksInstalled(deviceId));
                                    } catch (InterruptedException e) {
                                        e.printStackTrace();
                                    }
                                }
                                addSetIPDstAddrAndGoToTableFlowEntry(deviceId, dstEid, finalNa, seanrs_tableid_ipv6, seanrs_next_tableid);
                            });

                        }
                    }
//                  FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetOffsetAndGotoTableInstructionBlock(deviceId, seanrs_next_tableid).id().value());
//                  send packet out, bind(GoToTable)
                    InstructionTreatment treatment = new InstructionTreatment();
//                    treatment.addInstruction(new OFInstructionMovePacketOffset(0, ETH_HEADER_LEN / 8)); // 这个packetOut不支持！所以所有包重新走pipeline
                    OFInstruction ofInstructionGotoTable = new OFInstructionGotoTable(FIRST_TABLE);
                    treatment.addInstruction(ofInstructionGotoTable);
                    TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                    builder.extension(treatment, deviceId);
                    byte[] outPutBytes = ethPkt.serialize();
                    ByteBuffer bf = ByteBuffer.allocate(outPutBytes.length);
                    bf.put(outPutBytes).flip();
                    packetService.emit(new DefaultOutboundPacket(deviceId, builder.build(), bf));
                    //log.info(">>>> packet out: " + SocketUtil.bytesToHexString(outPutBytes) + " <<<<");
                }
                // 不是网内解析请求则不处理
                else {
                    log.info("receive a SeaDP packet without nrs header, go to next processor");
                }
            }
        }
    }


}
