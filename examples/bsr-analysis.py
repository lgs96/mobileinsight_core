#!/usr/bin/python

import os
import sys
import shutil
import traceback

import matplotlib.pyplot as plt
import numpy as np
import logging

from mobile_insight.monitor import OfflineReplayer
from uplink_booster_analyzer import lte_measurement_analyzer
from uplink_booster_analyzer import goodsol_analyzer
from uplink_booster_analyzer import uplink_latency_analyzer
from uplink_booster_analyzer import ul_mac_latency_analyzer
from uplink_booster_analyzer import lte_wireless_error_analyzer
from uplink_booster_analyzer import object_latency_analyzer
from uplink_booster_analyzer import lte_mac_analyzer
from uplink_booster_analyzer import lte_rlc_analyzer
from uplink_booster_analyzer import lte_rrc_analyzer
from uplink_booster_analyzer import bsr_table
from uplink_booster_analyzer import lte_pdcp_ulgap_analyzer

def lte_phy_analysis(input_path):
  src = OfflineReplayer()
  #src.set_input_path("./logs/latency_sample.mi2log")
  src.set_input_path(input_path)
  # print (sys.argv[1])

  phy_analyzer = goodsol_analyzer.MyAnalyzer()
  #phy_analyzer.set_source(src)

  meas_analyzer = lte_measurement_analyzer.LteMeasurementAnalyzer()
  meas_analyzer.set_source(src)

  uplink_analyzer = uplink_latency_analyzer.UplinkLatencyAnalyzer()
  #uplink_analyzer.set_source(src)

  mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
  #mac_analyzer.set_source(src)
  
  rlc_analyzer = lte_rlc_analyzer.LteRlcAnalyzer()
  rlc_analyzer.set_source(src)

  error_analyzer = lte_wireless_error_analyzer.LteWirelessErrorAnalyzer()
  #error_analyzer.set_source(src)

  fb_analyzer = object_latency_analyzer.ObjectLatencyAnalyzer()
  fb_analyzer.set_source(src)

  pdcp_analyer = lte_pdcp_ulgap_analyzer.LtePdcpUlGapAnalyzer()
  pdcp_analyer.set_source(src)

  #mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
  #mac_analyzer.set_source(src)
  
  rrc_analyzer = lte_rrc_analyzer.LteRrcAnalyzer()
  #rrc_analyzer.set_source(src)

  src.run()

  return phy_analyzer, meas_analyzer, mac_analyzer, rlc_analyzer, fb_analyzer, pdcp_analyer

def bsr_analysis(input_path):
  print(input_path)
  phy, meas, mac, rlc, fb, pdcp = lte_phy_analysis(input_path)
  # print stats.all_packets
  # print stats.cum_err_block
  # print stats.cum_block

  #print('Total Tx (MAC analyzer) ', mac.total_tx)
  #fb.calc_delay(start_time = 100, fin_time = 100000)
  bsr_rb_list, bsr_grant_list = fb.calc_bsr_grant()

  bsr_rb_list = np.array(bsr_rb_list)
  bsr_grant_list = np.array(bsr_grant_list)

  sample_cnt = np.zeros(6)
  sample_bsr = 0
  sample_tbs = np.zeros(6)
  sample_rb = np.zeros(6)

  for i, bsr in enumerate(bsr_grant_list[:,0]):
    if 0 < bsr <= 30000:
      sample_cnt[0] += 1
      sample_tbs[0] += bsr_grant_list[i,1]
      sample_rb[0] += bsr_rb_list[i,1]
    elif 30000 < bsr <= 60000:
      sample_cnt[1] += 1
      sample_tbs[1] += bsr_grant_list[i,1]
      sample_rb[1] += bsr_rb_list[i,1]
    elif 60000 < bsr <= 90000:
      sample_cnt[2] += 1
      sample_tbs[2] += bsr_grant_list[i,1]
      sample_rb[2] += bsr_rb_list[i,1]
    elif 90000 < bsr <= 120000:
      sample_cnt[3] += 1
      sample_tbs[3] += bsr_grant_list[i,1]
      sample_rb[3] += bsr_rb_list[i,1]
    elif 120000 < bsr <= 150000:
      sample_cnt[4] += 1
      sample_tbs[4] += bsr_grant_list[i,1]
      sample_rb[4] += bsr_rb_list[i,1]
    elif bsr > 150000:
      sample_cnt[5] += 1
      sample_tbs[5] += bsr_grant_list[i,1]
      sample_rb[5] += bsr_rb_list[i,1]    
    sample_bsr += bsr
      
  for i in range(6):
    mean_tbs = sample_tbs[i]/sample_cnt[i]
    mean_rb = sample_rb[i]/sample_cnt[i]
    
    print('BSR range ' ,i, ': ', mean_tbs, mean_rb, sample_cnt[i])
  print('Overall mean: ', sample_bsr/np.sum(sample_cnt),
        np.sum(sample_tbs)/np.sum(sample_cnt), np.sum(sample_rb)/np.sum(sample_cnt))

  rsrp_list = meas.serv_cell_rsrp
  rsrq_list = meas.serv_cell_rsrq
  print('Cell Id: ', fb.cell_id)
  print('RSRP mean, std: ', np.mean(rsrp_list), np.std(rsrp_list))
  print('RSRQ mean, std: ', np.mean(rsrq_list), np.std(rsrq_list))

  return np.sum(sample_tbs)/np.sum(sample_cnt), np.sum(sample_rb)/np.sum(sample_cnt), sample_cnt

### analysis for files in the whole folder ###

folder_list = ['80']
target_buffer_list = ['30000','60000','90000','120000','150000']
tbs_stats = np.zeros([len(folder_list), len(target_buffer_list)])
rb_stats = np.zeros([len(folder_list), len(target_buffer_list)])
sample_dist = np.zeros([len(folder_list), len(target_buffer_list),6])

for i, folder_name in enumerate(folder_list):
  for j, target_buffer in enumerate(target_buffer_list):
    try:
      folder_path = './paper_motivation/bsr_throughput/'+folder_name+'/'+target_buffer
      txt_list = os.listdir(folder_path)
      for txt in txt_list:
        mean_tbs, mean_rb ,sample_cnt = bsr_analysis(folder_path+'/'+txt)
        tbs_stats[i,j] += mean_tbs/len(txt_list)
        rb_stats[i,j] += mean_rb/len(txt_list)
        for k in range(len(sample_cnt)):
          sample_dist[i][j][k] += sample_cnt[k]
    except:
      print(folder_name, ' ', target_buffer, ' does not exists')


print('=================Result=================')
for i, folder_name in enumerate(folder_list):
  print('RSRP: ',folder_name)
  for j, target_buffer in enumerate(target_buffer_list):
    print('Target buffer ',target_buffer, 'Mean TBS, RB: ', tbs_stats[i,j], rb_stats[i,j])
    print('Sample dist: ', sample_dist[i,j,:]/np.sum(sample_dist[i,j,:]))
    

    

