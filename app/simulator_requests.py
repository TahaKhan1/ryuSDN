import json
import requests
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
import logging
import shared_simple_switch_13
import shared_back_up_flows
import logging
import ast


class SurvSimReq():

    #self.pairMap = {}
    #self.routeMap = {}
    #self.total_Paths = {}
    #self.all_Flows = {}
    #self.link_fail_Map = {}
    #self.back_up_Paths = {}
    #self.nodes = []
    #self.links = []

    #switch_io_ports = {'1': {'2': 1}, '2': {'3': 2, '1': 1}, '3': {'4': 2, '2': 1,'5':3},
                      # '4': {'5': 2, '3': 1}, '5': {'3':2, '4': 1},

    #switch_host = {"1": ('10.0.0.1', 2), "4": ('10.0.0.2', 3)}


    def __init__(self,link_ids,datapath_list,switch_io_ports,switch_host):
        self.link_ids= link_ids
        self.datapath_list=datapath_list
        self.switch_io_ports=switch_io_ports
        self.switch_host=switch_host
        self.pairMap = {}
        self.routeMap_uni = {}
        self.routeMap={}
        self.total_Paths = {}
        self.all_Flows = {}
        self.link_fail_Map = {}
        self.back_up_Paths = {}
        self.rsp_routes_u = 0
        self.rsp_routes={}
        self.active_paths=[]
        self.inactive_paths=[]
        self.populate_mapd_DB()


        #self.switch_io_ports = switch_io_ports
        #self.switch_host = switch_host

    def populate_mapd_DB(self):
        print("Populate map DBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        self.request_routes()
        self.Update_Pair_Map()
        self.Update_Route_Map()
        self.Update_Total_Paths()
        self.Update_All_Flows()
        self.Update_Link_Fail_Map()
        self.Update_Back_Up_Flows()

# populate_maps_DB function:
    def request_routes(self):
        payload = {"routingParams": [{"source": "1", "destinations": [2]},
                                     {"source": "1", "destinations": [3]},
                                     {"source": "1", "destinations": [4]},
                                     {"source": "1", "destinations": [5]},
                                     {"source": "1", "destinations": [6]},
                                     {"source": "1", "destinations": [7]},
                                     {"source": "1", "destinations": [8]},
                                     {"source": "1", "destinations": [9]},
                                     {"source": "1", "destinations": [10]},
                                     {"source": "1", "destinations": [11]},
                                     {"source": "1", "destinations": [12]},
                                     {"source": "1", "destinations": [13]},
                                     {"source": "1", "destinations": [14]},
                                     {"source": "2", "destinations": [3]},
                                     {"source": "2", "destinations": [4]},
                                     {"source": "2", "destinations": [5]},
                                     {"source": "2", "destinations": [6]},
                                     {"source": "2", "destinations": [7]},
                                     {"source": "2", "destinations": [8]},
                                     {"source": "2", "destinations": [9]},
                                     {"source": "2", "destinations": [10]},
                                     {"source": "2", "destinations": [11]},
                                     {"source": "2", "destinations": [12]},
                                     {"source": "2", "destinations": [13]},
                                     {"source": "2", "destinations": [14]},
                                     {"source": "3", "destinations": [4]},
                                     {"source": "3", "destinations": [5]},
                                     {"source": "3", "destinations": [6]},
                                     {"source": "3", "destinations": [7]},
                                     {"source": "3", "destinations": [8]},
                                     {"source": "3", "destinations": [9]},
                                     {"source": "3", "destinations": [10]},
                                     {"source": "3", "destinations": [11]},
                                     {"source": "3", "destinations": [12]},
                                     {"source": "3", "destinations": [13]},
                                     {"source": "3", "destinations": [14]},
                                     {"source": "4", "destinations": [5]},
                                     {"source": "4", "destinations": [6]},
                                     {"source": "4", "destinations": [7]},
                                     {"source": "4", "destinations": [8]},
                                     {"source": "4", "destinations": [9]},
                                     {"source": "4", "destinations": [10]},
                                     {"source": "4", "destinations": [11]},
                                     {"source": "4", "destinations": [12]},
                                     {"source": "4", "destinations": [13]},
                                     {"source": "4", "destinations": [14]},
                                     {"source": "5", "destinations": [6]},
                                     {"source": "5", "destinations": [7]},
                                     {"source": "5", "destinations": [8]},
                                     {"source": "5", "destinations": [9]},
                                     {"source": "5", "destinations": [10]},
                                     {"source": "5", "destinations": [11]},
                                     {"source": "5", "destinations": [12]},
                                     {"source": "5", "destinations": [13]},
                                     {"source": "5", "destinations": [14]},
                                     {"source": "6", "destinations": [7]},
                                     {"source": "6", "destinations": [8]},
                                     {"source": "6", "destinations": [9]},
                                     {"source": "6", "destinations": [10]},
                                     {"source": "6", "destinations": [11]},
                                     {"source": "6", "destinations": [12]},
                                     {"source": "6", "destinations": [13]},
                                     {"source": "6", "destinations": [14]},
                                     {"source": "7", "destinations": [8]},
                                     {"source": "7", "destinations": [9]},
                                     {"source": "7", "destinations": [10]},
                                     {"source": "7", "destinations": [11]},
                                     {"source": "7", "destinations": [12]},
                                     {"source": "7", "destinations": [13]},
                                     {"source": "7", "destinations": [14]},
                                     {"source": "8", "destinations": [9]},
                                     {"source": "8", "destinations": [10]},
                                     {"source": "8", "destinations": [11]},
                                     {"source": "8", "destinations": [12]},
                                     {"source": "8", "destinations": [13]},
                                     {"source": "8", "destinations": [14]},
                                     {"source": "9", "destinations": [10]},
                                     {"source": "9", "destinations": [11]},
                                     {"source": "9", "destinations": [12]},
                                     {"source": "9", "destinations": [13]},
                                     {"source": "9", "destinations": [14]},
                                     {"source": "10", "destinations": [11]},
                                     {"source": "10", "destinations": [12]},
                                     {"source": "10", "destinations": [13]},
                                     {"source": "10", "destinations": [14]},
                                     {"source": "11", "destinations": [12]},
                                     {"source": "11", "destinations": [13]},
                                     {"source": "11", "destinations": [14]},
                                     {"source": "12", "destinations": [13]},
                                     {"source": "12", "destinations": [14]},
                                     {"source": "13", "destinations": [14]}],

                   "network": {"nodes": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"],
                               "links": ["1-7", "1-11", "1-12", "2-6", "2-10", "3-6", "3-8", "3-12", "4-8", "4-10",
                                         "5-6", "5-7",
                                         "5-11", "6-13", "7-10", "9-12", "9-13", "10-11", "4-14", "14-9", "14-13"]
                               },

                   # "survivability":{"failureScenario":"AllLinks" ,"numFailureEvents" : "1"}

                   "survivability": {"numFailureEvents": "2", "failures": ["1-12", "3-6", "3-12", "4-8",
                                                                           "4-10", "4-14", "7-1", "8-3"
                                                                             ]}}

        url = 'http://localhost:9867/simulate'
        headers = {'Content-type': 'application/json'}
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        #print("Status_Code:",r.status_code)
        rsp_routes = r.json()
        #print("RSP_Routes", self.rsp_routes)

        for key in rsp_routes.keys():

            if type(rsp_routes[key]) == bool:
                valueToDump = json.dumps(str(rsp_routes[key]))
            else:
                valueToDump = json.dumps(rsp_routes[key])

            self.rsp_routes[ast.literal_eval(json.dumps(key))] = ast.literal_eval(valueToDump)

        return self.rsp_routes

    def Update_Pair_Map(self):
        for i in self.rsp_routes["connections"]:
            # print(len(data2["connections"]))
            self.pairMap[len(self.pairMap) + 1] = tuple(i["pair"],)
            self.pairMap[len(self.pairMap) + 1] = tuple(i["pair"],)[::-1]

        #print("pairMap:",self.pairMap)
        return self.pairMap

    def Update_Route_Map(self):
        for i in self.rsp_routes.values():
            if type(i) == list:
                for j in i:
                    self.pairMap[tuple(j["pair"])] = len(j['routes'])
                    self.pairMap[tuple(j["pair"][::-1])] = len(j['routes'])
                    ### pairMap_Paths Done ###
                pID = 1
                rID = 1
                for q in range(len(self.rsp_routes["connections"])):
                    for j in i[q]["routes"]:
                        self.routeMap[(pID, rID)] = j
                        rID = rID + 1
                    rID = 1
                    pID = pID + 1
                    for j in i[q]["routes"]:
                        self.routeMap[(pID, rID)] = j[::-1]
                        rID = rID + 1
                    pID = pID + 1
                    rID = 1
        for p in range(1,pID):
            self.active_paths.append((p,1))

        print("Route_map:", self.routeMap)
        print("Active Paths",self.active_paths)
        print("Inactive Paths from Simulator Requests :",self.inactive_paths)
        return self.routeMap


    def Update_Total_Paths(self):
        for key, value_list in self.routeMap.items():
            for val in value_list:
                self.total_Paths.setdefault(key, []).append((key + (val,)))
        #print("\n\n");
        #print("total_Paths:", self.total_Paths)
        #print("Length of Total_Paths : {}".format(len(self.total_Paths)))
        return self.total_Paths

    def Update_All_Flows(self):
        pID = 1
        rID = 1
        for i in self.rsp_routes.values():
            if type(i) == list:
                for q in range(len(self.rsp_routes["connections"])):
                    #print("qqq", q)
                    for j in i[q]["routes"]:
                        for e in j:
                            if j.index(e) == 0:  ## for first switch
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                self.switch_host[i[q]["pair"][0]][0], self.switch_host[i[q]["pair"][1]][0],
                                self.switch_host[i[q]["pair"][0]][1], self.switch_io_ports[e][j[j.index(e) + 1]])
                            elif j.index(e) == (len(j) - 1):  ## for the destination switch
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                self.switch_host[i[q]["pair"][0]][0], self.switch_host[i[q]["pair"][1]][0],
                                self.switch_io_ports[e][j[j.index(e) - 1]], self.switch_host[i[q]["pair"][1]][1])
                            else:  ## for the middle switches in the route lists
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                self.switch_host[i[q]["pair"][0]][0], self.switch_host[i[q]["pair"][1]][0],
                                self.switch_io_ports[e][j[j.index(e) - 1]], self.switch_io_ports[e][j[j.index(e) + 1]])
                        rID = rID + 1
                    rID = 1
                    pID = pID + 1
                    for j in i[q]["routes"]:
                        for e in j[::-1]:  ### reverse of the primary route
                            rev = j[::-1]
                            if rev.index(e) == 0:  ### first switch
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                    self.switch_host[i[q]["pair"][1]][0], self.switch_host[i[q]["pair"][0]][0],
                                    self.switch_host[i[q]["pair"][1]][1],
                                    self.switch_io_ports[e][rev[rev.index(e) + 1]])
                            elif rev.index(e) == (len(rev) - 1):  ## destination switch
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                    self.switch_host[i[q]["pair"][1]][0], self.switch_host[i[q]["pair"][0]][0],
                                    self.switch_io_ports[e][rev[rev.index(e) - 1]], self.switch_host[i[q]["pair"][0]][1])
                            else:  ### for all other switches in the route lists
                                self.all_Flows[(pID, rID, e)] = (self.datapath_list[int(e)],
                                    self.switch_host[i[q]["pair"][1]][0], self.switch_host[i[q]["pair"][0]][0],
                                    self.switch_io_ports[e][rev[rev.index(e) - 1]],
                                    self.switch_io_ports[e][rev[rev.index(e) + 1]])
                        rID = rID + 1
                    rID = 1  ## reverts to 1 after every iteration of primary(src,dst) and reverse(dst,src) iteration.
                    pID = pID + 1
        '''pID increments after every pair of source and destination flow entries are added in primary_flows. i.e, for all the routes of particular  pair source and destionation. So it is incremented first when forward flow entries are done (src,dst) and reverse block is iterated and again incremented when reverse block finishes(dst,src) '''
        #print("All_flows:", self.all_Flows)

        return self.all_Flows


    def Update_Link_Fail_Map(self):
        for sw_id, sw_link in self.link_ids.items():
            link = (int(sw_link[0]), int(sw_link[1]))
            for r_key, r_val in self.routeMap.items():
                for first, second in zip(r_val, r_val[1:]):
                    var = (int(first), int(second))
                    if link == var:
                        self.link_fail_Map.setdefault(sw_id, []).append(r_key)
                    else:
                        pass

        #print("link_fail_Map",self.link_fail_Map)
        return self.link_fail_Map

    def Update_Back_Up_Flows(self):
        p_key = (1, 1)
        b_key = (1, 2)
        while (1):
            if b_key in self.total_Paths:
                self.back_up_Paths[p_key] = b_key
                p_key = b_key
                b_key = (b_key[0], (b_key[1] + 1))

            else:
                p_key = (b_key[0] + 1, 1)
                b_key = (p_key[0], (p_key[1] + 1))
                if p_key not in self.total_Paths:
                    break

        #print("back_up_paths", self.back_up_Paths)
        return self.back_up_Paths

    def get_routeMap(self):
        return self.routeMap

    def get_total_Paths(self):
        return self.total_Paths

    def get_all_Flows(self):
        return self.all_Flows

    def get_link_fail_Map(self):
        return self.link_fail_Map

    def get_back_up_Paths(self):
        return self.back_up_Paths

    def get_active_paths(self):
        return self.active_paths

    def set_active_paths(self,active_paths):
        self.active_paths=active_paths
        #print("Active Paths",self.active_paths)
        return

    def get_inactive_paths(self):
        return self.inactive_paths

    def set_inactive_paths(self,inactive_paths):
        self.inactive_paths=inactive_paths
        #print("Inactive Paths from Simulator Requests :",self.inactive_paths)
        return


    #  1. call request_routes -> rsp_routes
    #  2. update_pair_Map
    #  3. update_route_Map
    #  4. update_total_paths
    #  5. update_all_flows
    #  6. update_link_fail_Map
    #  7. update_back_up_flows









