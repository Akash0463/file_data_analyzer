from django.shortcuts import render
import pandas as pd
import psycopg2
from sqlalchemy import create_engine
from django.contrib import messages
import os
import numpy as np
from collections import defaultdict

df =""

def home(request):
    return render(request,'apply.html')

def displayFile(request):
    head = list(df.columns)

    df1 = pd.DataFrame(df)

    data = df1.to_numpy()
    
    head_len = len(head)
    
    return render(request,'displayFile.html',{'head':head,'data':data, 'range':range(head_len)})

def updateFile(request):
    return render(request,'apply.html')

def saveData(request):
    selected_col = request.POST.getlist('checkval')

    list1 = list(df.columns)

    list2 = set(list1) - set(selected_col)
    final_list = list(list2)

    data = df.drop(final_list,axis=1)
    
    engine = create_engine('postgresql://postgres:12345@localhost:5432/SampleDB')
    data.to_sql('student', engine)
    return render(request,'apply.html')   


def show_file_details(request):
    global df
    data_file = request.FILES['myfile']
    df = pd.read_csv(data_file)
    head = list(df.columns)
    column_len = len(head)

    context = {'ftype' : data_file, 'columns':head, 'column_len':column_len}
    return render(request, 'file_details.html',context)

def showChart(request):
    column = list(df.columns)
    return render(request,'chart.html',{'column':column})

def showOptions(request):
    return render(request,'options.html')

def showUniqueIPs(request,pk):
    total_vul_cnt = 0
    total_high_cnt = 0
    total_critical_cnt = 0
    total_low_cnt = 0
    total_medium_cnt = 0
    total_none_cnt = 0
    context ={}

    vul_per_host = list()
    ports_without_zero = list()
    vul_per_host_dict = defaultdict(list)
    vul_ports_per_host = {}
    col_val = df[["Host"]].values
    ip_list = np.unique(col_val)
    ip_len = len(ip_list)

    vul_port = df[["Port"]].values
    vul_port_list = np.unique(vul_port)
    vul_port_len = len(vul_port_list)

    for ip in ip_list:
        sum = (df.Host == ip).sum()
        vul_per_host.append(sum)
        total_vul_cnt = total_vul_cnt + sum

    for i in range (0,ip_len):
        vul_per_host_dict[ip_list[i]].append(vul_per_host[i])

    for ip in ip_list:
        ports_without_zero.clear()
        ports = df['Port'][df['Host']==ip].values
        ports_list = list(ports)

        for i in ports_list:
            if(i!= 0):
                ports_without_zero.append(i)

        ports_len = len(ports_without_zero)

        vul_ports_per_host[ip] = ports_len


    unique_vul = df[["Description"]].values
    unique_vul_list = np.unique(unique_vul)
    unique_vul_list_len = len(unique_vul_list)

    for ip in ip_list:
        high_count = 0
        low_count = 0
        medium_count = 0
        critical_count = 0
        none_count = 0

        ports1 = df['Risk'][df['Host']==ip].values
        ports_list1 = list(ports1)
        
        if "High" in ports_list1:
            high_count = ports_list1.count("High")
            total_high_cnt = total_high_cnt + high_count

        if "Low" in ports_list1:
            low_count = ports_list1.count("Low")
            total_low_cnt = total_low_cnt + low_count

        if "Medium" in ports_list1:
            medium_count = ports_list1.count("Medium")
            total_medium_cnt = total_medium_cnt + medium_count

        if "Critical" in ports_list1:
            critical_count = ports_list1.count("Critical")
            total_critical_cnt = total_critical_cnt + critical_count

        if "None" in ports_list1:
            none_count = ports_list1.count("None")
            total_none_cnt = total_none_cnt + none_count

        vul_per_host_dict[ip].append(critical_count)
        vul_per_host_dict[ip].append(high_count)
        vul_per_host_dict[ip].append(medium_count)
        vul_per_host_dict[ip].append(low_count)
        vul_per_host_dict[ip].append(none_count)

    count_list = [ip_len, total_vul_cnt, total_critical_cnt, total_high_cnt, total_medium_cnt, total_low_cnt, total_none_cnt]

    print(count_list[0])

    if pk == '1':
        context = {'ip_list':ip_list, 'ip_len':ip_len,'pk1':'pk1'}
 
    if pk == '2':
        context ={'vul_per_host':dict(vul_per_host_dict), 'count_list':count_list, 'pk2':'pk2'}
 
    if pk == '3':
        context = {'vul_port_list':vul_port_list, 'vul_port_len':vul_port_len,'pk3':'pk3'}
 
    if pk == '4':
        context ={'vul_ports_per_host':vul_ports_per_host,'pk4':'pk4'}
 
    if pk == '6':
        context = {'unique_vul_list':unique_vul_list, 'unique_vul_list_len':unique_vul_list_len,'pk6':'pk6'}
        
    return render(request,'report.html',context)

def showVulInfo(request,pk,val):
    context = {}
    if val == "vul_cnt":
        df1 = df[(df.Host == pk)]
        host_details = df1[["Host", "Risk", "Plugin ID", "CVE", "Port", "Name", "Description", "Solution"]]

        host_details_data = host_details.to_numpy()
        context = {'host_details_col':host_details, 'host_details_data':host_details_data}

    else:
        df1 = df[(df.Risk == val) & (df.Host == pk)]
        host_details = df1[["Host", "Risk", "Plugin ID", "CVE", "Port", "Name", "Description", "Solution"]]

        host_details_data = host_details.to_numpy()
        
        context = {'host_details_col':host_details, 'host_details_data':host_details_data}

    return render(request, 'showVulInfo.html',context)