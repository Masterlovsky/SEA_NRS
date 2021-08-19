package nnnmc.seanet.sea_nrs;

import nnnmc.seanet.controller.api.FlowRuleCache;
import nnnmc.seanet.sea_nrs.util.HexUtil;
import nnnmc.seanet.sea_nrs.util.SocketUtil;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv6;
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
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.*;
import org.onosproject.pof.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.onlab.util.Tools.groupedThreads;


@Component(immediate = true)
public class SeanrsApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final int DISTRIBUTOR_TABLEID = 0;
    private static final int DEFAULT_TABLE_SIZE = 65535;
    private static final int DEFAULT_PRIORITY = 4000;
    private static final int OUTPUT_PRIORITY = 5000;
    private static final int forwardTableId_for_Ipv6 = 6;
    private static final int ETH_HEADER_LEN = 14 * 8;
    private static final int forwardTableId_for_Vlan = 16;
    private static final int forwardTableId_for_Qinq = 26;
    private static final String NA_ZEROS = HexUtil.zeros(32);
    private static final String EID_ZEROS = HexUtil.zeros(40);

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

    private FlowRuleCache instructionBlockSentCache = new FlowRuleCache();
    private FlowRuleCache instructionBlockInstalledCache = new FlowRuleCache();
    private FlowRuleCache flowEntrySentCache = new FlowRuleCache();
    private FlowRuleCache tableSentCache = new FlowRuleCache();
    private FlowRuleCache tableInstalledCache = new FlowRuleCache();

    private final SeaNRSFlowRuleListener flowRuleListener = new SeaNRSFlowRuleListener();
    private SeaNRSPacketProcessor processor = new SeaNRSPacketProcessor();


    private ExecutorService executor;

    private HashMap<String, String> eid_na_map = new HashMap<>();

    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
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
        eid_na_map.put("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "99999999999999999999999999999999");
        eid_na_map.put("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc", "99999999999999999999999999999999");
        eid_na_map.put("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd", "99999999999999999999999999999999");
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

        modified(context);
        //Send flow tables to the switches that have been connected
        for (Device device : deviceService.getAvailableDevices()) {
            if (device.id().toString().startsWith("pof")) {
                DeviceId deviceId = device.id();
                NodeId master = mastershipService.getMasterFor(deviceId);
                if (Objects.equals(local, master)) {
                    FlowRule nrsTableFlowRule = createNRSTable(deviceId);
                    flowRuleService.applyFlowRules(nrsTableFlowRule);
                }
            }
        }
        packetService.addProcessor(processor, PacketProcessor.director(100));
        log.info("============== Sea_NRS app activate! ==============");
    }


    @Deactivate
    public void deactivate(ComponentContext context) {
        instructionBlockSentCache.clear();
        instructionBlockInstalledCache.clear();
        flowEntrySentCache.clear();
        tableSentCache.clear();
        tableInstalledCache.clear();

        packetService.removeProcessor(processor);
        flowRuleService.removeListener(flowRuleListener);

        log.info("================= Sea_NRS app deactivate =================");
    }

    // =================== Flow Tables =======================

    private FlowRule createNRSTable(DeviceId deviceId) {
        log.info("createNRSTable {} begin", deviceId);

        OFMatch20Selector selector = new OFMatch20Selector();
        selector.addOFMatch20(FieldId.PACKET, ETH_HEADER_LEN + 24 * 8, 16 * 8); // DEST_IPV6_ADDR
        selector.addOFMatch20(FieldId.PACKET, ETH_HEADER_LEN + 42 * 8, 1 * 8); // TODO: 2021/7/22 网内解析字段，待定
        selector.addOFMatch20(FieldId.PACKET, ETH_HEADER_LEN + 64 * 8, 16 * 8); // DEST_EID (1-16Byte)
        selector.addOFMatch20(FieldId.PACKET, ETH_HEADER_LEN + 80 * 8, 4 * 8); // DEST_EID (16-20Byte)


        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(new TableModTreatment(OFTableType.OF_MM_TABLE, DEFAULT_TABLE_SIZE, "NRSTable"), deviceId);
        PofFlowRuleBuilder builder = new PofFlowRuleBuilder();
        FlowRule flowRule = builder
                .forDevice(deviceId)
                .forTable(DISTRIBUTOR_TABLEID)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        tableSentCache.add(flowRule);
        return flowRule;
    }

    private boolean allNRSTablesInstalled(DeviceId deviceId) {
        //log.debug("[multicast]allNRSTablesInstalled, tableInstalledCache.size({})={}.",deviceId,tableInstalledCache.size(deviceId));
        //		tableInstalledCache.size(deviceId) == 12

        boolean tableInstalled;
        if (tableSentCache.size(deviceId) == 0) {
            return false;
        }
        tableInstalled = tableSentCache.contrains(tableInstalledCache, deviceId);

        return tableInstalled;
    }

    // ================= Instruction Block =================

    private FlowRule buildPacketInInstructionBlock(DeviceId deviceId) {
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();

        instructionBlockModTreatment.addInstruction(new OFInstructionPacketIn());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildSetAddrAndGotoTableInstructionBlock(DeviceId deviceId, String ipAddress, int gotoTableId) {
        OFMatch20 ofMatch20 = new OFMatch20(FieldId.PACKET, 24 * 8, 16 * 8);
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionSetField(ofMatch20, ipAddress));
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .build();
        return blockFlowRule;
    }

    private FlowRule buildGotoTableInstructionBlock(DeviceId deviceId, int gotoTableId) {
        InstructionBlockModTreatment instructionBlockModTreatment = new InstructionBlockModTreatment();
        instructionBlockModTreatment.addInstruction(new OFInstructionGotoTable(gotoTableId));
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder().extension(instructionBlockModTreatment, deviceId);

        FlowRule blockFlowRule = new PofFlowRuleBuilder()
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
                .forDevice(deviceId)
                .withTreatment(trafficTreatmentBuilder.build())
                .makeStored(false)
                .build();

        return blockFlowRule;
    }

    private void addDefaultInstructionBlock(DeviceId deviceId) {
        {
            FlowRule blockFlowRule = buildPacketInInstructionBlock(deviceId);
            flowRuleService.applyFlowRules(blockFlowRule);
            instructionBlockSentCache.add(blockFlowRule);
        }
    }

    private boolean allDefaultInstructionBlocksInstalled(DeviceId deviceId) {
        boolean instructionBlockInstalled;
        if (instructionBlockSentCache.size(deviceId) == 0) {
            return false;
        }
        instructionBlockInstalled = instructionBlockSentCache.contrains(instructionBlockInstalledCache, deviceId);
        return instructionBlockInstalled;
    }

    // =================== Flow Entries ======================

    private void addPacketInFlowEntry(DeviceId deviceId) {
        //construct selector
        OFMatchXSelector selector = new OFMatchXSelector();
        selector.addOFMatchX("IPV6_DST", FieldId.PACKET, ETH_HEADER_LEN + (24 * 8), (16 * 8), NA_ZEROS, HexUtil.zeros(32));
        selector.addOFMatchX("NRS_TYPE", FieldId.PACKET, ETH_HEADER_LEN + (42 * 8), (1 * 8), "80", "F0");
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);

        FlowModTreatment flowModTreatment = new FlowModTreatment(buildPacketInInstructionBlock(deviceId).id().value());

        //construct treatment
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);


        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(DISTRIBUTOR_TABLEID)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }

    private void addSetIPDstAddrAndGoToTableFlowEntry(DeviceId deviceId, String eid, int gotoTableId) {
        //construct selector
        OFMatchXSelector selector = new OFMatchXSelector();

        selector.addOFMatchX("dstEID1", FieldId.PACKET, ETH_HEADER_LEN + (64 * 8), (16 * 8), eid.substring(0, 16), HexUtil.duplicates('F', 32));
        selector.addOFMatchX("dstEID2", FieldId.PACKET, ETH_HEADER_LEN + (80 * 8), (4 * 8), eid.substring(16, 20), HexUtil.duplicates('F', 8));
        selector.addOFMatchX("SEA_NRS", FieldId.PACKET, ETH_HEADER_LEN + (42 * 8), (1 * 8), "80", "F0");

        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        trafficSelectorBuilder.extension(selector, deviceId);
        String na = eid_na_map.getOrDefault(eid, HexUtil.duplicates('0', 32));
        FlowModTreatment flowModTreatment = new FlowModTreatment(buildSetAddrAndGotoTableInstructionBlock(deviceId, na, gotoTableId).id().value());
        TrafficTreatment.Builder trafficTreatmentBuilder = DefaultTrafficTreatment.builder();
        trafficTreatmentBuilder.extension(flowModTreatment, deviceId);

        FlowRule flowRule = new PofFlowRuleBuilder()
                .fromApp(appId)
                .forDevice(deviceId)
                .forTable(DISTRIBUTOR_TABLEID)
                .withSelector(trafficSelectorBuilder.build())
                .withTreatment(trafficTreatmentBuilder.build())
                .withPriority(OUTPUT_PRIORITY)
                .makePermanent()
                .makeStored(false)
                .build();

        flowRuleService.applyFlowRules(flowRule);
    }

    private void addDefaultFlowEntry(DeviceId deviceId) {
        try {
            addPacketInFlowEntry(deviceId);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    //对于设备标识为DeviceId的某设备，用函数getProcessStatusByDeviceId判断fibApp是否下发过表项，下发过则调用alreadyProcessedSetAdd函数将其记录在processedDeviceIdSet中；
    //当设备下线后，调用resetStatusByDeviceId函数，将该设备的DeviceId从processedDeviceIdSet中移出。以此来避免重复下发表项
    private CopyOnWriteArraySet<DeviceId> processedDeviceIdSet = new CopyOnWriteArraySet<DeviceId>();

    public synchronized void processedSetAdd(DeviceId deviceId) {
        processedDeviceIdSet.add(deviceId);
    }

    public synchronized void resetStatusByDeviceId(DeviceId deviceId) {
        if (!processedDeviceIdSet.isEmpty() && processedDeviceIdSet.contains(deviceId)) {
            processedDeviceIdSet.remove(deviceId);
        }
    }

    public synchronized boolean getProcessStatusByDeviceId(DeviceId deviceId) {
        boolean processed = false;
        if (!processedDeviceIdSet.isEmpty() && processedDeviceIdSet.contains(deviceId)) {
            processed = true;
        }

        return processed;
    }


    /**
     * listener 监听所有flowRule相关事件，包括流表的添加和删除、指令块儿的添加和删除、表项的添加和删除都会触发这个listener
     */
    private class SeaNRSFlowRuleListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule rule = event.subject();
            int tableId = rule.tableId();
            switch (event.type()) {
                //case RULE_ADDED:
                //case RULE_UPDATED:
                case RULE_ADD_REQUESTED: {
                    DeviceId deviceId = rule.deviceId();
                    if (deviceId.toString().startsWith("pof")) {
                        switch (rule.type()) {
                            case FlowRuleType.TABLE_MOD: //flow table add
                            {
                                if (tableSentCache.contains(rule)) {
                                    tableInstalledCache.add(rule);
                                    if (allNRSTablesInstalled(deviceId) && (instructionBlockSentCache.size(deviceId) == 0)) {
                                        executor.execute(() -> {
                                            addDefaultInstructionBlock(deviceId);
                                        });
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
                                        //需要的默认指令块全部添加完毕，则下发表项
                                        if (allDefaultInstructionBlocksInstalled(deviceId) && !getProcessStatusByDeviceId(deviceId)) {
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
                    break;
                }
            }
        }
    }


    // TODO: 2021/7/24 这里是重点，根据packetEID改ip，然后goto Fib表
    private class SeaNRSPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            long firstTime = System.currentTimeMillis();
            InboundPacket pkt = context.inPacket();
            ConnectPoint ingressPort = pkt.receivedFrom();
            DeviceId deviceId = ingressPort.deviceId();
            PortNumber port = ingressPort.port();
            Ethernet ethPkt = pkt.parsed();
            IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
            int nextHdr = HexUtil.byteToUnsignedInt(ipv6Pkt.getNextHeader());
            if (nextHdr == 0x11) {
                // TODO: 2021/7/27 UDP
            } else if (nextHdr == 0x99) {
                // TODO: 2021/7/27 IDP 暂定使用扩展包头的方式
                byte[] ipv6PktByte = ipv6Pkt.serialize();
                byte idpNextHeader = ipv6PktByte[40];
                byte[] idpReserved = {ipv6PktByte[42], ipv6PktByte[43]}; // 网内解析使用该字段前4个bit

                byte[] srcEidByte = new byte[20];
                System.arraycopy(ipv6PktByte, 44, srcEidByte, 0, 20);
                byte[] dstEidByte = new byte[20];
                System.arraycopy(ipv6PktByte, 64, dstEidByte, 0, 20);
                String srcEid = HexUtil.bytes2HexString(srcEidByte);
                String dstEid = HexUtil.bytes2HexString(dstEidByte);
                if ((idpReserved[0] & 0xf0) == 0x80) {
                    if (Objects.equals(dstEid, EID_ZEROS)) {
                        // TODO: 2021/8/13 register or deregister
                        byte[] idpAndUdpPkt_byte = ipv6Pkt.getPayload().serialize(); // 这里payload只去掉IPV6基本包头 (40B)
                        byte[] udpPayload_byte = new byte[idpAndUdpPkt_byte.length - 44 - 8];
                        System.arraycopy(idpAndUdpPkt_byte, 44 + 8, udpPayload_byte, 0, idpAndUdpPkt_byte.length - 44 - 8);
                        String payLoad = SocketUtil.bytesToHexString(udpPayload_byte);
                        // TODO: 2021/8/17 根据payload解析注册注销字段
                        // register
                        if (payLoad != null) {
                            if (payLoad.substring(0,2).equals("6f")) {

                            }
                            // deregister
                            if (payLoad.substring(0,2).equals("73")) {

                            }
                        }

                    } else {
                        // TODO: 2021/8/13 resolve
                        String na = eid_na_map.get(dstEid);
//                        System.arraycopy(SocketUtil.hexStringToBytes(na), 0, ipv6PktByte, 24, 16);
                        ipv6Pkt.setDestinationAddress(SocketUtil.hexStringToBytes(na));
                        ethPkt.setPayload(ipv6Pkt);
                        byte[] outPutBytes = ethPkt.serialize();
                        ByteBuffer bf = ByteBuffer.allocate(outPutBytes.length);
                        bf.put(outPutBytes).flip();
                        FlowModTreatment flowModTreatment = new FlowModTreatment(buildGotoTableInstructionBlock(deviceId, forwardTableId_for_Ipv6).id().value());
                        TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                        builder.extension(flowModTreatment, deviceId);
                        packetService.emit(new DefaultOutboundPacket(deviceId, builder.build(), bf));
                        // TODO: 2021/8/16 是否下发流表项，下发策略？
                        if (dstEid != null) {
                            addSetIPDstAddrAndGoToTableFlowEntry(deviceId, dstEid, forwardTableId_for_Ipv6);
                        }
                    }
                }
            }
        }
    }

}
