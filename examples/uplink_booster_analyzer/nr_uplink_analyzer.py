from mobile_insight.analyzer.analyzer import *

import time
import dis
import json
from datetime import datetime
import numpy as np

class NrUplinkAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)
    
        self.grant_record = np.zeros(200000);
        self.second = 0
        self.prev_frame_num = 0
        self.grant_start = 0
        self.grant_end = 0
    
    def set_source(self, source):
        Analyzer.set_source(self, source)
        #source.enable_log('5G_NR_MAC_UL_TB_Stats')
        #source.enable_log('5G_NR_ML1_Searcher_Measurement_Database_Update_Ext')
        #source.enable_log('5G_NR_MAC_UL_Physical_Channel_Schedule_Report')
        source.enable_log('5G_NR_L2_UL_TB')
        #source.enable_log('5G_NR_ML1_Serving_Cell_Beam_Management')s
        
    def __msg_callback(self, msg):
        '''
        if msg.type_id == "5G_NR_MAC_UL_TB_Stats":
            self.callback_5g_mac_ul_tb_stats(msg)
        if msg.type_id == "5G_NR_ML1_Searcher_Measurement_Database_Update_Ext":
            self.callback_5g_ml1_searcher(msg)
        '''
        if msg.type_id == "5G_NR_L2_UL_TB":
            self.callbcak_5g_l2_ul_tb(msg)
        '''
        if msg.type_id == "5G_NR_MAC_UL_Physical_Channel_Schedule_Report":
            self.callback_5g_mac_sched_report(msg)
        if msg.type_id == "5G_NR_ML1_Serving_Cell_Beam_Management":
            self.callback_5g_beam(msg)
        '''
            
    def callback_5g_mac_ul_tb_stats(self, msg):
        log_item = msg.data.decode()
        #print("5G TB Stats: ", log_item)
        
    def callback_5g_ml1_searcher(self, msg):
        log_item = msg.data.decode()
        #print("5G ml1 searcher: ", log_item)    
    
    def callbcak_5g_l2_ul_tb(self, msg):
        log_item = msg.data.decode()
        try:
            num_tti = log_item['Meta']['Num TTI']
        except:
            num_tti = 0
        tti_info = log_item['TTI Info']
        for i in range(num_tti):
            tti_code = 'TTI Info ['+(str)(i)+']'
            current_tti = tti_info[tti_code]
            current_tti_meta = current_tti['TTI Info Meta']
            tb_num = current_tti_meta['Num TB']
            slot_num = current_tti_meta['Slot Number']
            frame_num = current_tti_meta['FN']
            if frame_num < self.prev_frame_num:
                self.second += 1
            self.prev_frame_num = frame_num
            
            for j in range(tb_num):
                tb_code = 'TB Info ['+(str)(j)+']'
                current_tb_info = current_tti['TB Info'][tb_code] 
                grant_size = current_tb_info['Grant Size']
                self.grant_record[frame_num*2 + slot_num] += grant_size
                if self.grant_start == 0:
                    self.grant_start = frame_num*2 + slot_num
                self.grant_end = (self.second*10240 + frame_num)*2 + slot_num
                self.log_info(str(log_item['timestamp']) +' FN/SlotNum: ' + str(frame_num)+'/'+str(slot_num)+ " Grant Size: " + str(grant_size))
        #print("5G L2 TB: ", log_item)
        
    def callback_5g_mac_sched_report(self, msg):
        log_item = msg.data.decode()
        #print("5G phy schedule report: ", log_item)
        
    def callback_5g_beam(self, msg):
        log_item = msg.data.decode()
        #print("5G Beam: ", log_item)