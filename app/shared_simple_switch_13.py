# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import logging
import struct
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib.packet import ipv4
from ryu.lib import mac
from ryu.lib.packet import arp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.controller import dpset
from ryu.lib import dpid
from ryu.controller import handler
from threading import Timer
from shared_back_up_flows import *
from simulator_requests import *
import csv
import time
import threading

WAIT_TIME=90.0

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def wait_time(self):
        self.time_pass = WAIT_TIME
        print("Wait time has passed")

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.mac_to_port = {}
        self.switch_port_table = {}
        self.link_to_port = {}
        self.interior_ports = {}
        self.dpid_port_set = set()
        self.ip_mac_table = {}
        self.ip_dpidport = {}
        self.datapath_list = {}
        self.link_ids = {}
        self.key = []
        self.value = []
        self.link_pair={}  ## Update the constant value of 16.
        self.primary_flow_list=[]
        #self.survi_paths = SurvSimReq(self.link_ids,self.datapath_list)
        self.survi_paths=0
        self.switch_io_ports={}
        self.switch_host={}
        self.sum_active_paths=[]
        self.sum_backup_occur=[]
        self.sum_backup_fail=[]
        self.sum_no_update=[]
        self.sum_open_flow=[]
        self.sum_call_for_backup=0
        self.num_link_add_event=0
        self.num_link_delete_event=0
        self.links_deleted=set()
        self.links=[]
        self.time_pass=0

        t = threading.Timer(60.0, self.wait_time)
        t.start()


        with open('/home/taha/Documents/tkhan/QuakeTwo/sum_active_paths.csv', 'ab') as f:
            writer = csv.writer(f)
            writer.writerow([])

        with open('/home/taha/Documents/tkhan/QuakeTwo/sum_backup_occur_paths.csv', 'ab') as f:
            writer = csv.writer(f)
            writer.writerow([])

        with open('/home/taha/Documents/tkhan/QuakeTwo/sum_backup_fail_paths.csv', 'ab') as f:
            writer = csv.writer(f)
            writer.writerow([])

        with open('/home/taha/Documents/tkhan/QuakeTwo/sum_no_update_paths.csv', 'ab') as f:
            writer = csv.writer(f)
            writer.writerow([])

        with open('/home/taha/Documents/tkhan/QuakeTwo/sum_open_flow.csv', 'ab') as f:
            writer = csv.writer(f)
            writer.writerow([])
        #self.bu_flow = Backup_Paths(msg, self.link_ids, self.datapath_list)

    def print_metrics(self):
        print("Sum Active Paths: ", self.sum_active_paths)
        print("Sum Backup Paths: ", self.sum_backup_occur)
        print("Sum Backup Fail: ", self.sum_backup_fail)
        print("Sum No Update: ", self.sum_no_update)
        print("Sum Open Flow: ", self.sum_open_flow)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    ###############################End_of_Group_Mod_Action#####################################

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if ev.state == handler.MAIN_DISPATCHER:
            self.datapath_list[dp.id] = dp
            #self.logger.info("DPIDDDDDDDDDD: {}".format(dp.id))
            msg = 'Join SW'
        elif ev.state == handler.DEAD_DISPATCHER:
            ret = self.datapath_list.pop(dp.id, None)
            if ret is None:
                msg = 'Leave unknown SW'

            else:
                msg = 'Leave sw'
        #self.logger.info('dpid {} {} '.format(msg, self.datapath_list))
        #self.logger.info("port state change event triggered")

    ############  End of Incoming ports at switch 1,4 at port (1) #####################

    def create_port_map(self, switch_list):
        """
            Create interior_port table and access_port table.
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)
            #self.logger.info('Switch_port_table :{}'.format(self.switch_port_table))

    def create_interior_links(self, link_list):
        """
            Get links`source port to dst port from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

            if len(self.link_to_port) >=42:  ## Update this constant, changed it 12 because running normal topology
                for i in self.link_to_port.keys():
                    self.key.append(i)
                for i in self.link_to_port.values():
                    self.value.append(i)
                for i in range(len(self.link_to_port)):
                    self.link_ids[i + 1] = self.key[i] + self.value[i]
                for key, value in self.link_to_port.items():
                    if str(key[0]) in self.switch_io_ports:
                        temp1 = self.switch_io_ports.get(str(key[0]))
                        temp1[str(key[1])] = value[0];
                    else:
                        temp = {}
                        temp[str(key[1])] = value[0];
                        self.switch_io_ports[str(key[0])] = temp;

        #self.logger.info("Switch_io_ports: {}".format(self.switch_io_ports))
        #self.logger.info('Link_ids {}'.format(self.link_ids))
        #self.logger.info('Link_to_Port {}'.format(self.link_to_port))
        #self.logger.info('Interior_Ports {}'.format(self.interior_ports))
        #self.logger.info('Link_Pair {}'.format(self.link_pair))

    def create_access_ports(self):
        """
            Get ports without link into access_ports
        """
        self.dpid_port_set.clear()
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            for port in list(all_port_table - interior_port):
                #self.logger.info('port:{}'.format(port))
                dpid_port_pair = (sw, port)
                self.dpid_port_set.add(dpid_port_pair)

        self.logger.info('Access_ports : {}'.format(self.dpid_port_set))
        if len(self.dpid_port_set)==14:
            for i in self.dpid_port_set:
                self.switch_host[str(i[0])] = ('10.0.0.%s' % str(i[0]), i[1])
            #self.logger.info('Switch Host : {}'.format(self.switch_host))

    events = [event.EventSwitchEnter,event.EventSwitchLeave]

    @set_ev_cls(events)
    def get_switches(self, ev):
        """
            Get topology info and store it.
        """
        self.logger.info("Switch_Enter : {}".format(ev))
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()


    @set_ev_cls(event.EventLinkAdd,event)#.EventLinkDelete)
    def get_links(self, ev):
        self.num_link_add_event = self.num_link_add_event + 1
        self.logger.info("event : {}".format(ev))
        msg = ev.link.to_dict()
        self.logger.info("Event Link : {}".format(ev))
        if self.num_link_add_event == 1:
            self.links = get_link(self.topology_api_app, None)
        self.create_interior_links(self.links)
        print("Finished Create Interior links")
        self.create_access_ports()
        print("Finished Create Access Ports")
        print("Number of link add event: ",self.num_link_add_event)

        if self.num_link_add_event == 42 :### constant change with every topology
            #time.sleep(10)
            #print("Primary Flow Installer Called ")
            self.path_installer()
            self.logger.info("datpath_listttttttttttt {} =".format(self.datapath_list))
        #self.logger.info("datapath_list sahi ho ja : {}".format(self.datapath_list))
        self.logger.info("********************from get_links*********************")

        #self.path_installer()  #Throws Error and program terminates


    @set_ev_cls(event.EventLinkDelete)
    def port_lost(self, ev):
        self.num_link_delete_event = self.num_link_delete_event + 1
        self.logger.info("*********Event Link Delete port lost Called**************")
        msg = ev.link.to_dict()
        print("Event Link Delete inside EventLinkDelete",msg)
        print("Number of link event delete: ", self.num_link_delete_event)
        #self.logger.info("datapath_list sahi ho ja : {}".format(self.datapath_list))
        self.sum_call_for_backup = self.sum_call_for_backup + 1
        print(" Delete event triggered %d times", self.sum_call_for_backup)
        print("Wait Time is ", self.time_pass )

        if self.time_pass == WAIT_TIME:

            msg = ev.link.to_dict()
            dpid = []
            for i in msg.values():
                dpid.append(int(i['dpid'],16))

            print("Links deleted: ", self.links_deleted)
            print("DPID: ", tuple(dpid))


            if self.num_link_add_event >= 42:

                if tuple(dpid) in self.links_deleted:
                    print("Link deleted already present")
                    pass
                else:
                    print("NOT present link deleted")
                    try:
                        sp_active_paths=self.survi_paths.get_active_paths()
                        sp_inactive_paths=self.survi_paths.get_inactive_paths()
                        print("Active Paths", sp_active_paths)
                        print("Inactive Paths from Simulator Requests :", sp_inactive_paths)
                    except:
                        sp_inactive_paths = []
                        sp_active_paths = []
                    bu_flow = shared_back_up_flows.Backup_Paths(msg, self.link_ids, self.datapath_list,sp_active_paths, sp_inactive_paths)

                    sp_bu_paths = self.survi_paths.get_back_up_Paths()
                    sp_link_fail=self.survi_paths.get_link_fail_Map()

                    bu_flow.identify_failed_link(sp_link_fail,sp_bu_paths)

                    sp_total_paths = self.survi_paths.get_total_Paths()
                    sp_route_map=self.survi_paths.get_routeMap()
                    sp_all_flows = self.survi_paths.get_all_Flows()
                    bu_flow.backup_flow_rule_IDs(sp_total_paths,sp_all_flows)


                    bu_flow.failed_flow_rule_IDs(sp_total_paths,sp_all_flows)
                    # Delete

                    bu_flow.delete_flows_failed_paths()
                    # Add

                    bu_flow.add_flows_backup_paths()
                    # Adding the back_up_flows'''
                    self.survi_paths.set_active_paths(bu_flow.get_updated_active_paths())
                    self.survi_paths.set_inactive_paths(bu_flow.get_updated_inactive_paths())

                    metrics_list = bu_flow.get_metrics()

                    self.sum_active_paths.append(metrics_list[0])

                    try:
                        aggregate_backup_occur = self.sum_backup_occur[-1] + metrics_list[1]
                        self.sum_backup_occur.append(aggregate_backup_occur)

                        aggregate_backup_fail = self.sum_backup_fail[-1] + metrics_list[2]
                        self.sum_backup_fail.append(aggregate_backup_fail)

                        aggregate_open_flow =self.sum_open_flow[-1] + metrics_list[4]
                        self.sum_open_flow.append(aggregate_open_flow)

                    except:
                        aggregate_backup_occur = metrics_list[1]
                        self.sum_backup_occur.append(aggregate_backup_occur)

                        aggregate_backup_fail = metrics_list[2]
                        self.sum_backup_fail.append(aggregate_backup_fail)

                        aggregate_open_flow = metrics_list[4]
                        self.sum_open_flow.append(aggregate_open_flow)


                    self.sum_no_update.append(metrics_list[3])
                    self.print_metrics()
                    self.print_tofile(metrics_list[0], aggregate_backup_occur,aggregate_backup_fail, metrics_list[3],aggregate_open_flow)

            self.links_deleted.add(tuple(dpid))
        return

    def print_tofile(self, sum_active_path, sum_backup_occur, sum_backup_fail, sum_no_update,sum_open_flow):
        file_activePaths = open('/home/taha/Documents/tkhan/QuakeTwo/sum_active_paths.csv', 'a')
        file_backupOccur = open('/home/taha/Documents/tkhan/QuakeTwo/sum_backup_occur_paths.csv', 'a')
        file_backupFail = open('/home/taha/Documents/tkhan/QuakeTwo/sum_backup_fail_paths.csv', 'a')
        file_noUpdate = open('/home/taha/Documents/tkhan/QuakeTwo/sum_no_update_paths.csv', 'a')
        file_OpenFlow = open('/home/taha/Documents/tkhan/QuakeTwo/sum_open_flow.csv', 'a')


        file_activePaths.write(str(sum_active_path) + ',')
        file_backupOccur.write(str(sum_backup_occur) + ',')
        file_backupFail.write("%s," % sum_backup_fail)
        file_noUpdate.write("%s," % sum_no_update)
        file_OpenFlow.write("%s," % sum_open_flow)

        file_activePaths.close()
        file_backupOccur.close()
        file_backupFail.close()
        file_noUpdate.close()
        file_OpenFlow.close()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def get_port_status(self,ev):
        msg = ev.msg
        self.try_port_state(msg)
    def try_port_state(self,msg):
        pass
        #self.logger.info(" Inside Trrrrryyyyyyy Port State")
        #self.logger.info(" Tryyyy Port State: {}".format(msg))


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def _register_host_entry(self, arp_src_ip, arp_src_mac, datapathID, port):
        self.ip_mac_table[arp_src_ip] = arp_src_mac
        dpid_port = (datapathID, port)
        self.ip_dpidport[arp_src_ip] = dpid_port

    def arp_forwarding(self, msg, arp_header, from_datapath, ether, ethernet_src, ethernet_dst, in_port):
        ofproto = from_datapath.ofproto
        arp_src_ip = arp_header.src_ip
        arp_dst_ip = arp_header.dst_ip
        arp_src_mac = arp_header.src_mac
        arp_dst_mac = arp_header.dst_mac

        if ethernet_dst == mac.BROADCAST_STR:  # Handle ARP broadcast
            # self.logger.info('This is ARP broadcast received at port {} of switch {} from IP {}, ARP Src Mac {}, ethernet src {} to IP {}, ARP Destn Mac {}, ethernet dst {}'.format(in_port, from_datapath.id,
            # arp_src_ip, arp_src_mac, ethernet_src, arp_dst_ip, arp_dst_mac, ethernet_dst))

            if self.ip_mac_table.get(arp_src_ip) == None:  # No src ip found, so storing it in the table
                self.logger.info("****No mac entry found for IP. adding entry.....****")
                self._register_host_entry(arp_src_ip, arp_src_mac, from_datapath.id, in_port)

            if self.ip_mac_table.get(arp_dst_ip) != None:  # dst_ip exist in ip_mac_table, so proxy it
                ARP_Reply = packet.Packet()
                mac_from_table = self.ip_mac_table.get(arp_dst_ip)
                ARP_Reply.add_protocol(
                    ethernet.ethernet(ethertype=ether.ethertype, dst=ethernet_src, src=mac_from_table))
                ARP_Reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=mac_from_table, src_ip=arp_dst_ip,
                                               dst_mac=arp_src_mac, dst_ip=arp_src_ip))
                ARP_Reply.serialize()
                from_datapath.send_msg(
                    self._build_packet_out(from_datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER,
                                           in_port, ARP_Reply.data))
                self.logger.info("****Found mac entry for IP. Proxy-ing****")

            else:  # no dst_ip in ip_mac_table, flood
                for dpid_port_tup in self.dpid_port_set:
                    if dpid_port_tup not in self.ip_dpidport.values():
                        self.logger.info("********Flooding {}***********".format(dpid_port_tup))
                        datapath = self.datapath_list[dpid_port_tup[0]]
                        datapath.send_msg(self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                                                 ofproto.OFPP_CONTROLLER, dpid_port_tup[1], msg.data))

        else:  # if ARP packet and its a reply
            # self.logger.info('This is ARP reply received at port {} of switch {} from IP {}, ARP Src Mac {}, ethernet src {} to IP {}, ARP Destn Mac {}, ethernet dst {}'.format(
            # in_port, from_datapath.id, arp_src_ip, arp_src_mac, ethernet_src, arp_dst_ip, arp_dst_mac, ethernet_dst))
            self._register_host_entry(arp_src_ip, arp_src_mac, from_datapath.id, in_port)
            dpid_inport = self.ip_dpidport.get(arp_dst_ip)
            datapath = self.datapath_list[dpid_inport[0]]
            datapath.send_msg(self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                                     ofproto.OFPP_CONTROLLER, dpid_inport[1], msg.data))

        #self.logger.info(
            #"*********************************************************************************")
        return

    #####################################Path_installer######################################
    def _send_flow_mod(self, datapath, flow_info, in_port, out_port):
        self.logger.info('flow_mod message called')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(out_port))
        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=flow_info[0], ipv4_dst=flow_info[1])
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
        #self.logger.info('mod {}'.format(mod))
        datapath.send_msg(mod)
        return

    ### --------------------Installing Primary_Flows-----------------------------------###
    ### Creating an object of Class SurvSimReq(self)-----------------------------------###

    def path_installer(self):
        self.survi_paths = SurvSimReq(self.link_ids, self.datapath_list,self.switch_io_ports,self.switch_host)
        #sp_link_fail = self.survi_paths.get_link_fail_Map()
        flows_req=self.survi_paths.get_all_Flows()
        for key,val in flows_req.items():
            if key[1]==1:
                self.primary_flow_list.append(val)
                for i in self.primary_flow_list:
                    #print("i000000",i[0])
                    ofproto = i[0].ofproto
                    parser = i[0].ofproto_parser
                    actions = []
                    actions.append(parser.OFPActionOutput(i[4]))
                    match = parser.OFPMatch(in_port=i[3], eth_type=0x0800, ipv4_src=i[1], ipv4_dst=i[2])
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=i[0], priority=1, match=match, instructions=inst)
                    i[0].send_msg(mod)

    ######################################--End of path_installer################################

    @set_ev_cls(ofp_event.EventOFPPacketIn, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        parser = datapath.ofproto_parser
        ethernet_header = pkt.get_protocol(ethernet.ethernet)
        ethernet_dst = ethernet_header.dst
        ethernet_src = ethernet_header.src
        arp_header = pkt.get_protocol(arp.arp)

        if ethernet_header.ethertype == ether_types.ETH_TYPE_LLDP:  # ignore lldp packet
            return
        #self.logger.info("DataPath_at the bottom : {}:".format(self.datapath_list))

        if ethernet_dst[:5] == "33:33":  # ignore IPV6 multicast packet
            match = parser.OFPMatch(in_port=in_port, eth_dst=ethernet_dst)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return

        #self.logger.info("packet in {} {} {} {}".format(datapath.id, ethernet_src, ethernet_dst, in_port))


        if arp_header:  # handle arp packets
            #self.logger.info("******ARP Processing********")
            self.arp_forwarding(msg, arp_header, datapath, ethernet_header, ethernet_src, ethernet_dst, in_port)
        return


