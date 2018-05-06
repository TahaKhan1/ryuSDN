from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
import logging
import shared_simple_switch_13
import simulator_requests
import _csv


class Backup_Paths():
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, msg, link_ids, datapath_list, active_paths,inactive_paths):
        # super(Backup_Paths, self).__init__(*args, **kwargs)
        ##self.paths= {path_id:[flow_ID's]}
        ### Paths_ID's Identifies the different paths from source to destination.
        # Update dict - change the values to just path IDs
        ## links: paths associated with it.
        # update this to just have path ID key and value only

        self.msg = msg
        self.link_ids = link_ids
        self.datapath_list=datapath_list
        self.failed_paths = []
        self.backup_paths = []
        self.backup_ID = []
        self.flows_failed = []
        self.backup_flows = {}
        self.failed_flows = {}
        self.backup_path_list = []
        self.failed_links = []
        self.path_failed_list = []
        self.result_affected_flows={}
        self.result_unaffected_flows={}
        self.active_paths=active_paths
        self.inactive_paths=inactive_paths
        self.metrics=[]
        self.sum_active_paths=0
        self.sum_backup_occur=0
        self.sum_backup_fail=0
        self.sum_no_update=0
        self.sum_open_flow=0

        # flows[0] = self.paths[self.failed_paths[0]]
    def get_updated_active_paths(self):
        return self.active_paths

    def get_updated_inactive_paths(self):
        return self.inactive_paths

    def identify_failed_link(self,sp_link_fail,sp_bu_paths):
        # list of path IDs affected
        #print("Link Fail Mapppp{}".format(sp_link_fail))
        #print("Active _Paths{}".format(self.active_paths))
        dpid = []
        port_no = []
        for i in self.msg.values():
            dpid.append(int(i['dpid'],16))
            port_no.append(int(i['port_no']))
        #print(dpid)
        #print(port_no)

        link_failed = (dpid[0], dpid[1], port_no[0], port_no[1])
        #print(link_failed)
        # link_ids = {5: (1, '2', '3', '4'), 1: ('2', '3', '6', '7'), 3: ('4', '7', '8', '9')}
        # fail_map = {1: (1, '2', '3', '4')}

        #print("Affected Links tuple:{}".format(i))
        #print("Current Active List :",self.active_paths)
        #print("Current InActive List :", self.inactive_paths)

        link_ids_key = self.link_ids.keys()[self.link_ids.values().index(link_failed)]
        self.failed_links.append(link_ids_key)
        for path in sp_link_fail[link_ids_key]:
            self.inactive_paths.append(path)
            if path in self.active_paths:
                # Here path is primary
                # Delete current path
                current_path = path
                # Remove current path from active paths list
                # the current path was active
                self.active_paths.remove(current_path)
                    #self.failed_paths.append(current_path)
                if current_path in sp_bu_paths:
                    new_path = sp_bu_paths[current_path]
                    if new_path not in self.inactive_paths:


                        #print("1")
                        #print("Current path: ", current_path)
                        #print("New path: ", new_path)
                        self.backup_ID.append(new_path)
                        self.sum_backup_occur = self.sum_backup_occur + 1
                        #Add new path to active paths if
                        #the current path is active and backup
                        #exist for current path
                        self.active_paths.append(new_path)
                    else:
                        self.sum_backup_fail = self.sum_backup_fail + 1
                        #print("2")
                        #print("Current path: ", current_path)
                        #print("New path: ", new_path)
                    self.failed_paths.append(current_path)
                else:
                    ## is it last back up path
                    #print("3")
                    #print("Current path: ", current_path)
                    self.sum_backup_fail = self.sum_backup_fail + 1

            else:
                if path not in self.inactive_paths:
                    # Here path is not primary
                    # Find the primary path of which this path is
                    # a backup
                    current_key = sp_bu_paths.keys()[sp_bu_paths.values().index(path)]
                    # Replace this backup path with the backup path
                    # of this path
                    if path in sp_bu_paths:
                        sp_bu_paths[current_key] = sp_bu_paths[path]

        self.sum_active_paths = len(self.active_paths)
        if self.sum_active_paths != 0:
            self.sum_no_update = self.sum_active_paths - (self.sum_backup_fail+ self.sum_backup_occur)
        else:
            self.sum_no_update = 0
        #print("Backup Flows")
        self.print_metrics()

        self.metrics = [self.sum_active_paths, self.sum_backup_occur, self.sum_backup_fail, self.sum_no_update]


                 ### sp_link_fail returns:link_fail_map
        #print("Active Paths after Failure",self.active_paths)
        #print("Number of Active Paths after Failure",len(self.active_paths))
        #print("InActive Paths after Failure",self.inactive_paths)
        #print("Number of InActive Paths after Failure",len(self.inactive_paths))
        #print("Link_ID affected and appending to failed_link:{}".format(self.failed_links))
        #print("Path failed IDs and appending to failed_paths:{}".format(self.failed_paths))


    ### failed_path=[[(2,2),(4,1)]

    def backup_flow_rule_IDs(self,sp_total_paths,sp_all_flows):
        #print("Backup_Flow_Rule_IDSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")
        #print("Length of All Flows using object:",len(sp_all_flows))
        # iterate backup paths
        for i in self.backup_ID:
            self.backup_paths.append(sp_total_paths[i])
            #print("back_up_path inside method backup_flow_rule_IDS",self.backup_paths)

        # backup_paths=[[(2, 1, '4'), (2, 1, '6'), (2, 1, '5'), (2, 1, '1')],[(3, 2, '1'), (3, 2, '5'), (3, 2, '3'), (3, 2, '4'), (3, 2, '6')]]
        for i in self.backup_paths:
            for path_rule in i:
                for key,val in sp_all_flows.items():
                    #print("total_paths keyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",key)
                    if path_rule == key:
                        self.backup_flows[len(self.backup_flows)+1] = val
        self.sum_open_flow = self.sum_open_flow +len(self.backup_flows)
        #print("Backup_Flows in method shared_back_up_flows",self.backup_flows)
        #self.result_unaffected_flows[len(self.result_unaffected_flows)+1]=len(sp_all_flows)-len(self.backup_flows)


        #self.backup_flows.append(sp_total_paths[path_rule])
        #print("Backup Paths dict: {}".format(self.backup_flows))
        #print("Backup Paths : {}".format(self.backup_paths))

    def failed_flow_rule_IDs(self,sp_total_paths,sp_all_flows):
        for path in self.failed_paths:
                self.path_failed_list.append(sp_total_paths[path])

        #print("Paths Failed List: {}".format(self.path_failed_list))
        for i in self.path_failed_list:
            for flow_dis in i:
                for key,val in sp_all_flows.items():
                    #print("total_paths keyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",key)
                    if flow_dis == key:
                        self.failed_flows[len(self.failed_flows)+1] = val
        #print("Flows to be deleted Failed Flows : {}".format(self.failed_flows))
        self.sum_open_flow= self.sum_open_flow + len(self.failed_flows)

    ### Making failed_flows and backup_flows a list in which primary_flows(tuples) are
    ### appended and later will be iterated in methods like delete_flows_failed_paths
    ### and add_flows_backup_paths.

    def delete_flows_failed_paths(self):
        for i in self.failed_flows.values():
            print('Failed flow_mod message called')
            ofproto = i[0].ofproto
            parser = i[0].ofproto_parser
            actions = []
            actions.append(parser.OFPActionOutput(i[4]))
            match = parser.OFPMatch(in_port=i[3], eth_type=0x0800, ipv4_src=i[1], ipv4_dst=i[2])
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=i[0], priority=1, match=match, instructions=inst,
                                    out_group=ofproto.OFPG_ANY, out_port=ofproto.OFPP_ANY,
                                    command=ofproto.OFPFC_DELETE_STRICT)
            i[0].send_msg(mod)

        '''identify_failed_link()
        failed_flow_rule_paths()'''

    def add_flows_backup_paths(self):
        for i in self.backup_flows.values():
            print('Backup_Flows getting Installed')
            ofproto = i[0].ofproto
            parser = i[0].ofproto_parser
            actions = []
            actions.append(parser.OFPActionOutput(i[4]))
            match = parser.OFPMatch(in_port=i[3], eth_type=0x0800, ipv4_src=i[1], ipv4_dst=i[2])
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=i[0], priority=1, match=match, instructions=inst)
            i[0].send_msg(mod)

    def get_metrics(self):
        self.metrics.append(self.sum_open_flow); #element 4
        return self.metrics

    def print_metrics(self):
        print("Sum Active Paths: ", self.sum_active_paths)
        print("Sum Backup Paths: ", self.sum_backup_occur)
        print("Sum Backup Fail: ", self.sum_backup_fail)
        print("Sum No Update: ", self.sum_no_update)
        print("Sum Open Flow", self.sum_open_flow)


    #print("Nata")
