#!/usr/bin/python3
# Filename: uplink_latency_analyzer.py
"""
uplink_latency_analyzer.py
An analyzer to monitor uplink packet waiting and processing latency
"""


__all__ = ["FirstByteAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from numpy.core.defchararray import decode
from mobile_insight.analyzer.analyzer import *


import time
import dis
import json
from datetime import datetime
import numpy as np


# import threading


class SchedulingLatencyAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)
        #self.register_coordinator_cb(self.__msg_callback)

        # Timers 
        self.fn = -1
        self.sfn = -1

        # PHY stats
        self.cum_err_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink
        self.cum_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink
        self.loss_block = 0

        # MAC buffer
        self.last_buffer = 0
        self.packet_queue = []

        # Stats
        self.all_packets = []
        self.tx_packets = []
        self.tmp_dict = {}

        ########### added ################
        self.init_timestamp = None

        # Record per-second downlink bandwidth
        self.lte_dl_bw = 0  # Downlink bandwidth (from PDSCH)
        self.lte_ul_bw = 0  # Uplink bandwidth (from PUSCH DCI grants)
        self.lte_ul_grant_utilized = 0  # Uplink grant utilization (in bits)
        self.prev_timestamp_dl = None  # Track timestamp to calculate avg DL bandwidth
        self.prev_timestamp_ul = None  # Track timestamp to calculate avg DL bandwidth
        self.avg_window = 1.0  # Average link BW time window (in seconds)

        # Statistics for PDSCH modulation
        self.mcs_qpsk_count = 0
        self.mcs_16qam_count = 0
        self.mcs_64qam_count = 0

        # Record last observed CQI (for DL bandwidth prediction)
        self.cur_cqi0 = 0
        self.cur_cqi1 = 0
        self.cur_tbs = None

        # Flag to show if it is the first sr event
        self.init_flag = False

        # Resource slot used by SR
        self.rb_slot1 = None
        self.rb_slot2 = None

        # Scheduled SR subframenumber
        self.sr_sfn = None

        self.grant_list = []
        self.sent_list = []

        # Get scheduling latency: 210526 Goodsol
        self.state = 1 # 0: scheduling request 1: others
      
        self.blank = []
        self.sr = []
        self.tx = []

        self.sr_start = 0
        self.tx_start = 0
        self.tx_end = 0

        self.total_tx = 0
        self.total_buffer = 0
        self.total_grant = 0
        self.my_last_buffer = 0
        self.total_utilized = 0
        self.log_time = 0
        self.my_last_tx = 0 
        self.total_tb = 0
        
        # Measure time
        self.second = 0
        self.last_f_time = 0
        self.counter = 0
        self.started = False

        # record events
        self.record_time = 100000
        self.record = np.zeros([self.record_time,3]) #0: sr, #1: tx start, #2: tx end
        self.whole_record = np.zeros([self.record_time, 5]) #0: sr occurence, #1: tx byte  #2: buffer size #3
        self.buffer_record = np.zeros(self.record_time)
        self.rb_record = np.zeros(self.record_time)
        self.sr_point = []
        self.sr_latency = []
        self.blank_latency = []
        self.tx_latency = []


    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        source.enable_log("LTE_PHY_PUSCH_Tx_Report")
        source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        source.enable_log("LTE_PHY_PUCCH_Tx_Report")
        #source.enable_log("LTE_MAC_UL_Transport_Block")
        source.enable_log("LTE_MAC_UL_Tx_Statistics")
        source.enable_log("LTE_MAC_Rach_Trigger")
        source.enable_log("LTE_MAC_Rach_Attempt")
        #source.enable_log("LTE_MAC_Configuration")

    # get difference between two time value
    def __f_time_diff(self, t1, t2):
        if t1 > t2:
            print('bug', t1,t2)
            t_diff = t2 + 10240 - t1
        else:
            t_diff = t2 - t1 + 1
        return t_diff

    # get absolute time
    def __f_time(self):
        return self.fn * 10 + self.sfn

    def __cmp_queues(self, type, data):
        if type == 1:
            for pkt in self.all_packets:
                if pkt[-2] == data[0]:
                    # print the stats

                    self.all_packets.remove(pkt)
                    return
            self.tx_packets.append(data)
        if type == 2:
            for pkt in self.tx_packets:
                if pkt[0] == data[-2]:
                    # print the stats
                    self.tx_packets.remove(pkt)
                    return
            self.all_packets.append(data)

    def __print_buffer(self):
        pass

    def __msg_callback(self, msg):

        if msg.type_id == "LTE_PHY_PUSCH_Tx_Report":
            log_item = msg.data.decode()
            print('PUSCH_Tx_Report callback: ', log_item,"\n")
            if 'Records' in log_item:
                for record in log_item['Records']:
                    #print(record)
                    current_time = record['Current SFN SF']
                    self.total_tb += record['PUSCH TB Size']
                    self.whole_record[10240*self.second + current_time][2] += record['PUSCH TB Size']
                    self.rb_record[10240*self.second + current_time] += record['Num of RB']
                    #print('PHY TB Size: ', record['Current SFN SF'], record['PUSCH TB Size'])
                    retx_time = record['Current SFN SF']
                    if retx_time < 0:
                        retx_time += 1024

                    if record['Re-tx Index'] == 'First':
                        self.cum_block[0] += 1
                    else:
                        # print(record['Re-tx Index'])
                        self.cum_err_block[0] += 1

                        ## should set retx time according to the Re-tx Index
                        if record['Re-tx Index'] == 'Second':
                            retx_latency = 8
                        if record['Re-tx Index'] == 'Third':
                            retx_latency = 16
                        if record['Re-tx Index'] == 'Fourth':
                            retx_latency = 24
                            self.loss_block += 1
                        else:
                            retx_latency = 8
                        if retx_time in self.tmp_dict :
                            self.tmp_dict[retx_time]['Retx Latency'] = retx_latency
                        else:
                            self.tmp_dict[retx_time] = {'Retx Latency': retx_latency}
                    
                    for t in list(self.tmp_dict):
                        # print t, retx_time
                        # print self.tmp_dict
                        if (t < retx_time or (t > 1000 and retx_time < 20)):
                            if 'Retx Latency' not in self.tmp_dict[t]:
                                self.tmp_dict[t]['Retx Latency'] = 0
                            
                            if len(self.tmp_dict[t]) == 3:
                                #print ('Waiting Latency:', self.tmp_dict[t]['Waiting Latency'], 'Tx Latency:', self.tmp_dict[t]['Tx Latency'], 'Retx Latency:', self.tmp_dict[t]['Retx Latency'])
                                self.all_packets.append(self.tmp_dict[t])
                                del(self.tmp_dict[t])




                    # self.__cmp_queues(1, (record['Current SFN SF'], record['Re-tx Index']))

        if msg.type_id == "LTE_MAC_UL_Buffer_Status_Internal":
            for packet in msg.data.decode()['Subpackets']:
                for sample in packet['Samples']:
                    #print('Buffer Status', sample)
                    SFN = sample['Sub FN']
                    FN = sample['Sys FN']
                    self.update_time(SFN, FN)
                    if (sample['LCIDs'] == []):
                        # print "error here!!"
                        continue
                    # print SFN, FN, self.sfn, self.fn
                    data = sample['LCIDs'][-1]
                    # print sample
                    
                    total_b = data['Total Bytes']
                    new_c = data['New Compressed Bytes']
                    retx_b = data['Retx bytes']
                    ctrl_b = data['Ctrl bytes']
                    
                    self.whole_record[10240*self.second + self.__f_time()][3] = total_b

                    ## 210526Goodsol second unit time measurement
                    if self.__f_time() < self.last_f_time and self.__f_time() >= 0 and self.started:
                        print('sec', self.__f_time(), self.last_f_time)
                        self.second = self.second + 1 
                    #print('sec2', self.__f_time(), self.last_f_time)
                    self.last_f_time = self.__f_time()

                    # if (total_b > new_c) and ctrl_b == 0:
                    if total_b > self.last_buffer: 
                        # size, remaining buffer, incoming time, first byte time
                        self.packet_queue.append([total_b - self.last_buffer, total_b - self.last_buffer, self.__f_time(), -1])
                    elif total_b < self.last_buffer:
                        outgoing_bufer = self.last_buffer - total_b
                        self.total_buffer += outgoing_bufer
                        
                        self.whole_record[10240*self.second + self.__f_time()][1] += outgoing_bufer
                        #print('Time: ', 10000*self.second + self.__f_time(), 'total outgoing: ', outgoing_bufer, 'total buffer: ', self.total_buffer)
                        #self.total_tx += outgoing_bufer
                        #print('Time: ', 10000*self.second + self.__f_time(), ' Transmit bytes: ', outgoing_bufer, 'State: ', self.state, ' Total Tx: ',self.total_tx)
                        while 1:
                            if self.packet_queue == []:
                                break
                            packet = self.packet_queue[0]
                            #print('Time: ', self.__f_time(), ' Buffer: ', packet[1], self.last_buffer)
                            #self.whole_record[2] = self.last_buffer
                            if self.my_last_buffer != packet[0]:
                                #self.total_buffer += packet[0] + self.my_last_tx
                                self.my_last_buffer = packet[0]
                            '''
                            print('Time: ', self.__f_time(), 'MAC UL Packet 0: ', packet[0], "1: ", packet[1], "2: ", packet[2], "3: ", packet[3], 
                                  ' My last tx: ', self.my_last_tx, 'Outgoing: ', outgoing_bufer, ' Total tx: ', self.total_tx)
                            '''
                            #      " total buffer: ", self.total_buffer, "\n")
                            self.total_tx += outgoing_bufer
                            if packet[3] == -1:
                                packet[3] = self.__f_time()
                            if packet[1] > outgoing_bufer:
                                packet[1] -= outgoing_bufer
                                #self.total_tx += outgoing_bufer
                                break
                            else:
                                # size, waiting latency, transmission latency
                                # print self.packet_queue, self.all_packets, outgoing_bufer
                                t_now = self.__f_time()
                                if (t_now not in self.tmp_dict):
                                    self.tmp_dict[t_now] = {}
                                #self.tmp_dict[t_now]['Waiting Latency'] = self.__f_time_diff(packet[2], packet[3])
                                #self.tmp_dict[t_now]['Tx Latency'] = self.__f_time_diff(packet[3], self.__f_time())
                                
                                #print ([self.__f_time(), packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[3], self.__f_time())])
                                #self.my_last_tx = outgoing_bufer
                                '''
                                print('Time: ', self.__f_time(), ' Tx: ', outgoing_bufer, ' Packet size: ', packet[0], 
                                ' Remaining buffer: ', packet[1], ' Incoming time: ',packet[2],
                                ' Packet tx time: ', packet[3])
                                '''

                                outgoing_bufer -= packet[1]
                                #self.total_tx += outgoing_bufer
                                self.my_last_tx = packet[1]
                                del self.packet_queue[0]
                                #self.__cmp_queues(2, (packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[2], t_now), t_now, self.last_buffer - new_c) )
                
                    self.last_buffer = total_b

        if msg.type_id == "LTE_PHY_PUCCH_Tx_Report":
            self.callback_pucch(msg)
        if msg.type_id == "LTE_MAC_UL_Transport_Block":
            self.callback_ul_transport(msg)
        if msg.type_id == "LTE_MAC_UL_Tx_Statistics":
            self.callback_pusch_grant(msg)
        if msg.type_id == "LTE_MAC_Rach_Trigger":
            self.callback_rach_trigger(msg)
        if msg.type_id == "LTE_MAC_Rach_Attempt":
            self.callback_rach_attempt(msg)
        if msg.type_id == "LTE_MAC_Configuration":
            self.callback_mac_configuration(msg)


    def update_time(self, SFN, FN):
        if self.sfn >= 0:      
            self.sfn += 1
            if self.sfn == 10:
                self.sfn = 0
                self.fn += 1
            if self.fn == 1024:
                self.fn = 0
        if SFN < 10:
            self.sfn = SFN
            self.fn = FN


    ###############added#####################

    def callback_pucch(self, msg):
        """
        Dump PUCCH scheduling request information
        :param msg: raw LTE_PHY_PUCCH_Tx_Report packet
        :return:
        """
        log_item = msg.data.decode()
        records = log_item['Records']
        timestamp = str(log_item['timestamp'])

        for record in records:
            pucch_tx_power = record['PUCCH Tx Power (dBm)']
            bcast_dict = {}
            bcast_dict['tx power'] = pucch_tx_power
            bcast_dict['timestamp'] = timestamp
            self.broadcast_info("PUCCH_TX_POWER", bcast_dict)
            self.log_debug("PUCCH_TX_POWER: " + str(bcast_dict))
            uciformat = record['Format']
            if uciformat == 'Format 1':
                self.init_flag = True
                self.rb_slot1 = record['Start RB Slot 0']
                self.rb_slot2 = record['Start RB Slot 1']
                self.sr_sfn = record['Current SFN SF'] % 10  # subframenumber
                sr_dict = {}
                sr_dict['timestamp'] = timestamp
                sr_dict['fn and subfn'] = record['Current SFN SF']
                self.broadcast_info("SR_EVENT", sr_dict)
                self.log_info("SR_EVENT: " + str(sr_dict))
                #print('SR time1: ',10240*self.second + sr_dict['fn and subfn'])
                # 210526Goodsol
                self.whole_record[10240*self.second + sr_dict['fn and subfn']][0] = 1
                
                if self.state != 0:
                    #self.tx.append([self.tx_start, self.tx_end])
                    #self.blank.append([self.tx_end, 10000*self.second + sr_dict['fn and subfn']])
                    self.started = True

            elif uciformat == 'Format 1B' or uciformat == 'Format 1A':
                # TODO: reset init_flag for new logs
                if self.init_flag:
                    if int(record['Start RB Slot 1']) == self.rb_slot2 and int(record['Start RB Slot 0']) == self.rb_slot1 \
                            and record['Current SFN SF'] % 10 == self.sr_sfn:
                        sr_dict = {}
                        sr_dict['timestamp'] = timestamp
                        sr_dict['fn and subfn'] = record['Current SFN SF']
                        self.broadcast_info("SR_EVENT", sr_dict)
                        self.log_info("SR_EVENT: " + str(sr_dict))
                        #print('SR time2: ', 10240*self.second +sr_dict['fn and subfn'])    
                        # 210526Goodsol
                        self.whole_record[10240*self.second + sr_dict['fn and subfn']][0] = 1
                        '''
                        if self.state != 0:
                            #self.tx.append([self.tx_start, self.tx_end])
                            #self.blank.append([self.tx_end, 10000*self.second + sr_dict['fn and subfn']])
                            self.started = True
                            self.state = 0
                            self.sr_start = 10000*self.second + sr_dict['fn and subfn']
                            ##recording method
                            self.record[self.sr_start][0] = 1
                        '''

            elif uciformat == "Format 3":
                # TODO: Deal with SR event in format 3
                pass

    def callback_ul_transport(self, msg):
        log_item = msg.data.decode()
        print('UL transport: ', log_item)

        subpackets = log_item['Subpackets']
        
        for subpacket in subpackets:
            samples = subpacket['Samples']
            for sample in samples:
                sfn = sample['SFN']
                subfn = sample['Sub-FN']
                grant = sample['Grant (bytes)']
                
                #print('Time: ', 10000*self.second + sfn*10+subfn, ' Grant bytes: ', grant)

    def callback_pusch_grant(self, msg):

        log_item = msg.data.decode()
        #print('PUSCH_Tx_statistics callback: ', log_item,"\n")
        if not self.init_timestamp:
            self.init_timestamp = log_item['timestamp']

        if not self.prev_timestamp_ul:
            self.prev_timestamp_ul = log_item['timestamp']

        # Calculate PUSCH uplink utilization
        grant_received = 0
        grant_utilized = 0
        grant_utilization = 0

        for i in range(0, len(log_item['Subpackets'])):
            grant_received += log_item['Subpackets'][i]['Sample']['Grant received']
            grant_utilized += log_item['Subpackets'][i]['Sample']['Grant utilized']

        if grant_received != 0:
            grant_utilization = round(
                100.0 * grant_utilized / grant_received, 2)

        self.total_utilized += grant_utilized
        self.total_grant += grant_received
        self.log_time += 1
        
        self.log_info(str(log_item['timestamp']) +
                       " PUSCH UL grant: received=" +
                       str(grant_received) +
                       " bytes" +
                       " used=" +
                       str(grant_utilized) +
                       " bytes" +
                       " utilization=" +
                       str(grant_utilization) +
                       "%" + 
                       " total utilized"+ 
                       str(self.total_utilized))
        
        '''
        print("Stats: ", self.log_time ," "+ str(log_item['timestamp']) +
                       " PUSCH UL grant: received=" +
                       str(grant_received) +
                       " bytes" +
                       " used=" +
                       str(grant_utilized) +
                       " bytes" +
                       " utilization=" +
                       str(grant_utilization)+
                       "% total utilized",  
                       self.total_utilized)
        '''
        self.grant_list.append(grant_received)
        self.sent_list.append(grant_utilized)

        self.lte_ul_grant_utilized += grant_utilized * 8
        self.lte_ul_bw += grant_received * 8

        if (log_item['timestamp'] -
                self.prev_timestamp_ul).total_seconds() >= self.avg_window:

            bcast_dict = {}
            bandwidth = self.lte_ul_bw / \
                ((log_item['timestamp'] - self.prev_timestamp_ul).total_seconds() * 1000000.0)
            grant_utilization = self.lte_ul_grant_utilized / \
                ((log_item['timestamp'] - self.prev_timestamp_ul).total_seconds() * 1000000.0)
            bcast_dict['Bandwidth (Mbps)'] = str(round(bandwidth, 2))
            bcast_dict['Utilized (Mbps)'] = str(round(grant_utilization, 2))
            if self.lte_ul_bw:
                bcast_dict['Utilization (%)'] = str(
                    round(self.lte_ul_grant_utilized * 100.0 / self.lte_ul_bw, 2))
            else:
                bcast_dict['Utilization (%)'] = '0'

            # self.log_info(str(log_item['timestamp']) + ' LTE_UL_Bandwidth=' + bcast_dict['Bandwidth (Mbps)'] + "Kbps "
            #              + "UL_utilized="+bcast_dict['Utilized (Mbps)']+"Kbps "
            #              + "Utilization="+bcast_dict['Utilization (%)']+"%")

            self.log_debug(str(log_item['timestamp']) +
                           ' UL ' +
                           bcast_dict['Bandwidth (Mbps)'] +
                           " " +
                           bcast_dict['Utilized (Mbps)'] +
                           " " +
                           bcast_dict['Utilization (%)'] +
                           "")

            self.broadcast_info('LTE_UL_BW', bcast_dict)
            # Reset bandwidth statistics
            self.prev_timestamp_ul = log_item['timestamp']
            self.lte_ul_bw = 0
            self.lte_ul_grant_utilized = 0

    def callback_rach_trigger(self, msg):
        log_item = msg.data.decode()
        print('Rach trigger: ', log_item)
        
    def callback_rach_attempt(self, msg):
        log_item = msg.data.decode()
        print('Rach attempt: ', log_item)
        
    def callback_mac_configuration(self, msg):
        log_item = msg.data.decode()
        print('Mac configuration: ', log_item)
    
    def replay_record(self):
        total_tx = 0
        total_grant = 0
        for i, t in enumerate(self.whole_record):
            if t[0] == 1: ## record SR event
                print(i//10240, i%10240, 'SR')
                self.sr_point.append(i)
                if self.state != 0:
                    self.state = 0
                    self.record[i][0] = 1
            if t[1] > 0: ## record Tx event
                total_tx += t[1]
                total_grant += t[2]
                #print(i, 'Tx: ', t[1], ' Grant: ', t[2], 'total_tx: ', total_tx, 'total_grant: ', total_grant)
                if t[1] > 200 and self.state != 1:
                    #print(i, 'Tx start', t[1])
                    self.state = 1
                    self.record[i][1] = 1
                if self.state == 1:
                    self.record[i][2] = 1
            #if t[3] > 0:
                #print(i, ' Buffer size: ', t[3])
            if t[2] > 0 or t[3] > 0:
                print(i//10240, i%10240, ' Granted size: ', t[2], ' Txed size: ', t[1], ' Buffer size: ',t[3], ' RB: ', self.rb_record[i])
            if i==0:
                self.whole_record[i][4] = t[2]
            if i!= 0:
                self.whole_record[i][4] = self.whole_record[i-1][4] + t[2]

    def summary_record(self):
        for i, t in enumerate(self.record):
            if t[0]==1:
                ###
                j = 0
                k = 0
                while 1:
                    j += 1
                    if i-j==0:
                        print('First or error for tx start')
                        break
                    if self.record[i-j][1]==1:
                        break
                while 1:
                    k += 1
                    if i-k==0:
                        print('First or error for tx end')
                        break
                    if self.record[i-k][2]==1:
                        break
                tx_start = i-j
                tx_end = i-k
                self.tx.append([tx_start, tx_end])
                self.blank.append([tx_end, i])
                
            if t[1]==1:
                ###
                j = 0
                while 1:
                    j += 1
                    if i-j==0:
                        print('First or error for sr start')
                        break
                    if self.record[i-j][0]==1:
                        break
                sr_start = i-j
                self.sr.append([sr_start, i])


    def calc_delay (self):
        self.replay_record()
        self.summary_record()

        first_delay = 0
        blank_delay = 0
        scheduling_delay = 0
        tx_delay = 0

        start_time = 0
        fin_time = 100000

        for i, t in enumerate(self.blank):
            if i!= 0 and i!=len(self.blank) and t[0] >= start_time and t[1] <= fin_time:
                blank_delay += self.__f_time_diff(t[0], t[1])
                self.blank_latency.append(self.__f_time_diff(t[0], t[1]))

        for i, t in enumerate(self.sr):
            if i == 0 and t[0] >= start_time and t[1] <= fin_time:
                first_delay = self.__f_time_diff(t[0], t[1])
            elif i!= 0 and t[0] >= start_time and t[1] <= fin_time:
                scheduling_delay += self.__f_time_diff(t[0], t[1])
                self.sr_latency.append(self.__f_time_diff(t[0], t[1]))
                
                #print('Sched: ',self.__f_time_diff(t[0], t[1]), scheduling_delay)

        for i, t in enumerate(self.tx):
            if i != 0 and t[0] >= start_time and t[1] <= fin_time:
                tx_delay += self.__f_time_diff(t[0], t[1])
                self.tx_latency.append(self.__f_time_diff(t[0], t[1]))

        #print('Blank set: ',self.blank)
        #print('Scheduling set: ',self.sr)
        #print('Tx set: ',self.tx)

        print('Total TX: ', np.sum(self.whole_record[0:fin_time, 1]))
        print('Total TB: ', np.sum(self.whole_record[0:fin_time, 2]))
        print('Total utiilized: ', self.total_utilized)
        print('Total grant: ', self.total_grant)
        print('Retx: ' ,self.cum_err_block[0])
        print('Loss num: ', self.loss_block)

        print('SYN delay: ', first_delay)
        print('Blank delay: ', blank_delay)
        print('Scheduling delay: ', scheduling_delay)
        print('Tx delay: ', tx_delay)
        
        self.rlc_buffer = self.whole_record[self.sr[0][1]:self.tx[-1][1], 3]
        self.resource_block = self.rb_record[self.sr[0][1]:self.tx[-1][1]]
        self.all_grant = self.whole_record[self.sr[0][1]:self.tx[-1][1], 2]
        #self.rlc_buffer = self.whole_record[7180:7200, 3]
        self.sr_point = [x[0] - self.sr[0][1] for x in self.sr[1:]]
        self.sr_end_point = [x[1] - self.sr[0][1] for x in self.sr[1:]] 
        #self.sr_point = [x - self.sr[0][1] for x in self.sr_point[1:]]
        
        start_point = 99999
        start_stack = 0
        fin_point = 0
        fin_stack = 0
        for i in range(len(self.grant_list)):
            if self.sent_list[i] > 300 and start_stack == 0:
                start_point = i
                start_stack = 1
            if start_stack == 1:
                if self.sent_list[i] == 0:
                    #print('fin stack: ', i)
                    fin_stack += 1
                    if fin_stack == 3:
                        fin_point = i - 3
                        break
                else:
                    fin_stack = 0
                    
        if fin_point == 0:
            fin_point = len(self.grant_list)
                    
        #print(self.sent_list[start_point:])
        #print(start_point, fin_point)
        
        self.grant_show_list = [x*80/(1024*1024) for x in self.grant_list[start_point:fin_point]]
        self.sent_show_list = [x*80/(1024*1024) for x in self.sent_list[start_point:fin_point]]
        
        #print(self.whole_record[(start_point-1)*100:(fin_point+1)*100, 2])
        #self.pusch_list = self.whole_record[(start_point-1)*100:(fin_point+1)*100, 2]
        self.pusch_list = self.whole_record[self.sr[0][1]:self.tx[-1][1],4]
        #self.pusch_list = self.whole_record[7180:7200, 4]

        return blank_delay, scheduling_delay, tx_delay
