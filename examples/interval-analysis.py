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
    

def lte_phy_analysis():
  src = OfflineReplayer()
  #src.set_input_path("./logs/latency_sample.mi2log")
  src.set_input_path(sys.argv[1])
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


phy, meas, mac, rlc, fb, pdcp = lte_phy_analysis()
# print stats.all_packets
# print stats.cum_err_block
# print stats.cum_block

#print('Total Tx (MAC analyzer) ', mac.total_tx)
fb.calc_delay(start_time = 100, fin_time = 100000)


mask = fb.rsrp_toShow < 0
rsrp = fb.rsrp_toShow[mask]
mask = fb.rsrq_toShow < 0
rsrq = fb.rsrq_toShow[mask]

print('Cell Id: ', fb.cell_id)
print('RSRP mean, std: ', np.mean(rsrp), np.std(rsrp))

temp_mcs = fb.mcs_record[fb.whole_record[:,3] > 2000]
temp_tbs = fb.whole_record[:,2][fb.whole_record[:,2] > 200]
temp_rb = fb.rb_record[fb.whole_record[:,3] > 2000]
print('MCS mean, std: ', np.mean(temp_mcs), np.std(temp_mcs))
print('TBS mean, std: ', np.mean(temp_tbs), np.std(temp_tbs))
print('RB mean, std: ', np.mean(temp_rb), np.std(temp_rb))

plt.figure(0)
plt.title('MCS')
plt.xlabel('Time (ms)')
plt.ylabel('bits per resource element')

plt.plot(fb.mcs_toShow)

#plt.show()
