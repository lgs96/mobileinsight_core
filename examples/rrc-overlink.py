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
from uplink_booster_analyzer import scheduling_latency_analyzer
from uplink_booster_analyzer import lte_mac_analyzer
from uplink_booster_analyzer import lte_rlc_analyzer
from uplink_booster_analyzer import lte_rrc_analyzer
from uplink_booster_analyzer import lte_rrc_SR_analyzer

def lte_phy_analysis():
    src = OfflineReplayer()
    #src.set_input_path("./logs/latency_sample.mi2log")
    src.set_input_path(sys.argv[1])
    # print (sys.argv[1])

    phy_analyzer = goodsol_analyzer.MyAnalyzer()
    #phy_analyzer.set_source(src)

    meas_analyzer = lte_measurement_analyzer.LteMeasurementAnalyzer()
    #meas_analyzer.set_source(src)

    uplink_analyzer = uplink_latency_analyzer.UplinkLatencyAnalyzer()
    #uplink_analyzer.set_source(src)

    mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
    #mac_analyzer.set_source(src)
    
    rlc_analyzer = lte_rlc_analyzer.LteRlcAnalyzer()
    #rlc_analyzer.set_source(src)

    error_analyzer = lte_wireless_error_analyzer.LteWirelessErrorAnalyzer()
    #error_analyzer.set_source(src)

    fb_analyzer = lte_rrc_SR_analyzer.SchedulingLatencyAnalyzer()
    fb_analyzer.set_source(src)

    #mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
    #mac_analyzer.set_source(src)
    
    rrc_analyzer = lte_rrc_analyzer.LteRrcAnalyzer()
    rrc_analyzer.set_source(src)

    src.run()

    return phy_analyzer, meas_analyzer, mac_analyzer, rlc_analyzer, fb_analyzer


phy, meas, mac, rlc, fb = lte_phy_analysis()
# print stats.all_packets
# print stats.cum_err_block
# print stats.cum_block

#print('Total Tx (MAC analyzer) ', mac.total_tx)
print('Total data Tx (RLC analyzer): ', rlc.total_data_pdu)
print('Total ctrl Tx (RLC analyzer): ', rlc.total_ctrl_pdu)
fb.calc_delay()

print('Blank: ', fb.blank)
print('Scheduling: ', fb.sr)
print('Tx burst: ', fb.tx)

print('Scheduling mean, std: ', np.mean(fb.sr_latency), np.std(fb.sr_latency))
print('Blank mean, std: ',np.mean(fb.blank_latency), np.std(fb.blank_latency))
print('Tx mean, std: ',np.mean(fb.tx_latency), np.std(fb.tx_latency))

rsrp_list = meas.serv_cell_rsrp
rsrq_list = meas.serv_cell_rsrq
print('RSRP list: ', rsrp_list)
print('RSRQ list: ', rsrq_list)
print('RSRP mean, std: ', np.mean(rsrp_list), np.std(rsrp_list))
print('RSRQ mean, std: ', np.mean(rsrq_list), np.std(rsrq_list))

enableFig = True
if enableFig:
  #fig1 = plt.figure(1)
  fig1, ax1 = plt.subplots()
  plt.title('RLC buffer and Resource Block')
  plt.xlabel('Time (ms)')
  
  ax1.plot(fb.rlc_buffer[:], c = 'blue')
  ax1.set_ylabel('Buffer size (Bytes)')
  
  #ax2 = ax1.twinx()
  #ax2.plot(fb.resource_block[:], c = 'orange')
  #ax2.set_ylabel('Num of RB')
  
  for i in range(len(fb.sr_point)):
    plt.scatter(fb.sr_point[i], 0, marker = 'x',  c = 'r', s = 100)
    plt.scatter(fb.sr_end_point[i], 0, marker = 'o',  c = 'g', s = 100)
    plt.plot([fb.sr_point[i], fb.sr_end_point[i]], [0,0], c = 'r', linestyle ='--')
    
  grant_x = np.arange(len(fb.grant_show_list))*100

  plt.figure(2)
  plt.title('Wireless throughput')
  plt.xlabel('Time (ms)')
  plt.ylabel('Mbps')
  plt.plot(grant_x, fb.grant_show_list)
  plt.plot(grant_x, fb.sent_show_list)
  plt.legend(['Granted', 'Utilized'])

  plt.figure(3)
  plt.title('Grant list')
  plt.xlabel('Time (ms)')
  plt.ylabel('Bytes')
  plt.plot(fb.pusch_list[:])

  plt.figure(4)
  plt.title('RSRP')
  plt.xlabel('Time')
  plt.ylabel('dBm')
  plt.plot(meas.timestamp, rsrp_list)

  plt.show()
np.save('./rlc_buffer', fb.rlc_buffer)
np.save('./all_grant', fb.all_grant)

#plt.savefig('buffer.png')
