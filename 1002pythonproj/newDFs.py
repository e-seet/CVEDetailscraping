"""
This module is to create new dataframes from cveDetailsFull.csv / cveProductsFull.csv to suit the needs of the graphs plotted.
"""

import pandas as pd

years = [2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022]

def newVulnDF():
    """
    Creates new dataframe on vulnerability types based on the year selected
    """
    df = pd.read_csv('CleanCVEs/cveDetailsFull.csv')
    data = {}
    year = []
    data_category = []
    instances = []
    category = "Vulnerability Type(s)"
    for y in years:
        for v in list(df[category].unique()):
            dff = df.copy()
            dff = dff[dff[category] == v]
            dff = dff[dff['Year'] == y]
            year.append(y)
            data_category.append(v)
            instances.append(len(dff.index))
    data['Year'] = year
    data[category] = data_category
    data['Total'] = instances
    plotdata = pd.DataFrame(data, index=[i for i in range(len(instances))])
    return plotdata

def newVendorDF(year_selected, num_selected):
    """
    Creates new dataframe on product vendors based on the year selected
    """
    data = {}
    year = []
    data_category = []
    instances = []
    dict1 = {}
    category = "Vendor"
    df = pd.read_csv(f"CleanCVEs/cveProducts{year_selected}.csv")
    for i in list(df[category]):
        if i not in dict1:
            dict1[i] = 1
        else:
            dict1[i] += 1
    dict1 = dict(sorted(dict1.items(), key=lambda x:x[1], reverse=True))
    count = 0
    for i in dict1:
        if count < num_selected:
            year.append(year_selected)
            data_category.append(i)
            instances.append(dict1[i])
            count += 1
    data['Year'] = year
    data[category] = data_category
    data['Total'] = instances
    plotdata = pd.DataFrame(data, index=[i for i in range(len(instances))])
    return plotdata

def newfullDF(category, num_selected=0):
    """
    Creates new dataframe on vulnerability types or product vendors for all the years 2015-2022
    """
    data = {}
    data_category = []
    instances = []
    dict1 = {}
    df = ''
    if category == "VulnType":
        category = "Vulnerability Type(s)"
        df = pd.read_csv(f"CleanCVEs/cveDetailsFull.csv")
    elif category == "Vendors":
        category = "Vendor"
        df = pd.read_csv(f"CleanCVEs/cveProductsFull.csv")
    for i in list(df[category]):
        if i not in dict1:
            dict1[i] = 1
        else:
            dict1[i] += 1
    if num_selected > 0:
        count = 0
        dict1 = dict(sorted(dict1.items(), key=lambda x:x[1], reverse=True))
        for i in dict1:
            if count < num_selected:
                data_category.append(i)
                instances.append(dict1[i])
                count += 1
            else:
                break
    else:
        for i in dict1:
            data_category.append(i)
            instances.append(dict1[i])
    data[category] = data_category
    data['Total'] = instances
    plotdata = pd.DataFrame(data, index=[i for i in range(len(instances))])
    return plotdata

def singlevulnDF(vulnType):
    """
    Creates new dataframe on a single vulnerability type for all years
    """
    df = pd.read_csv(f"CleanCVEs/cveDetailsFull.csv")
    data = {}
    year = []
    instances = []
    df = df[df['Vulnerability Type(s)'] == vulnType]
    for y in years:
        dff = df.copy()
        dff = dff[dff['Year'] == y]
        year.append(y)
        instances.append(len(dff.index))
    data['Year'] = year
    data['Total'] = instances
    plotdata = pd.DataFrame(data, index=[i for i in range(len(instances))])
    return plotdata

def cvssScoreDF():
    """
    Creates a new dataframe on average CVSS score across the years
    """
    df = pd.read_csv(f"CleanCVEs/cveDetailsFull.csv")
    plotingDF3 = df.groupby(['Year', "Vulnerability Type(s)"]).CVSS_Score.mean().to_frame()
    plotingDF3 = plotingDF3.reset_index(level=[0, 1])
    return plotingDF3