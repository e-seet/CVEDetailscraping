"""
This module is for creating the various graphs as denoted by the function name
We will be using the plotly express library to integrate the graphs onto Dash
WordCloud library is also used to display the word cloud as an image on Dash
"""

import plotly.express as px
from wordcloud import WordCloud
import pandas as pd
import base64
from io import BytesIO

def bargraph(dff, year_selected, data, num_selected=0):
    """
    Bar Graphs are used for data categories vulnerability types and product vendors
    Graphs are filtered by years
    """
    if data == "VulnType":
        fig = px.bar(
            data_frame=dff,
            x='Vulnerability Type(s)',
            y='Total',
            color='Vulnerability Type(s)',
            orientation='v',
            barmode='relative',
            text='Total',
            labels={"Total": "Number of CVEs", "Vulnerability Type(s)": "Vulnerability Types"},
            title=f"Number of CVEs by Vulnerability Type in {year_selected}",
        )
    else:
        fig = px.bar(
            data_frame=dff,
            x='Vendor',
            y='Total',
            color='Vendor',
            orientation='v',
            barmode='relative',
            text='Total',
            labels={"Total": "Number of Products", "Vendor": "Product Vendors"},
            title=f"Top {num_selected} Product Vendors affected by CVEs in {year_selected}",
        )
    # Removes chart background
    fig.update_layout(showlegend=False, paper_bgcolor='rgba(0,0,0,0)')

    return fig

def piechart(dff, year_selected):
    """
    Pie Chart is used for data category vulnerability types
    Graph is filtered by years
    """
    fig = px.pie(dff,
                 values='Total',
                 names='Vulnerability Type(s)',
                 title=f'Number of CVEs by Vulnerability Type in {year_selected}',
                 labels={"Total": "Number of CVEs", "Vulnerability Type(s)": "Vulnerability Types"},
                 hole=.3,
                 )
    # Removes chart background
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)')
    return fig

def linegraph(dff, vulnType):
    """
    Line Graph is used to display trend over the years of a particular vulnerability type
    Can be altered by hovering over any of the vulnerability types in the bar graph
    """
    fig = px.line(
        data_frame=dff,
        x='Year',
        y='Total',
        labels={"Total": "Number of CVEs"},
        title=f"Number of CVEs with {vulnType} from 2015 to 2022",
        markers=True,
    )
    # Removes chart background
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)')
    return fig

def scatterplot(dff):
    """
    Scatter plot is used to display the average CVSS Score over the years
    """
    fig = px.scatter(data_frame=dff,
                     x="Year",
                     y="CVSS_Score",
                     color="Vulnerability Type(s)",
                     trendline="ols",
                     labels={"CVSS_Score": "CVSS Score"},
                     title='Average CVSS Score against Year'
                     )
    # Removes chart background
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)')

    # Display the regression lines and scatter plots for vulnerability types with an r2 > 0.7
    results = px.get_trendline_results(fig)
    for x in range(len(results.px_fit_results)):  # 0.75
        if results.px_fit_results.iloc[x].rsquared > 0.7:
            # keep the graph
            continue
        else:
            fig.data[(x * 2)]["visible"] = "legendonly"
            fig.data[(x * 2 + 1)]["visible"] = "legendonly"
    return fig

def boxplot(dff, data_selected, year_selected=0):
    """
    Box plot for statistics on CVSS scores
    Can be filtered to view x-axis as vulnerability type or year
    If year is chosen, box plot can be viewed for a particular year or all years
    """
    if data_selected == 'Year':
        if year_selected != 'All Years':
            df2 = dff[dff['Year'] == year_selected]
            fig = px.box(
                data_frame=df2,
                x='Vulnerability Type(s)',
                y='CVSS_Score',
                title=f"CVSS Score Distribution by Vulnerability Types for {year_selected}",
                color='Vulnerability Type(s)',
                labels={'CVSS_Score': 'CVSS Score'},
            )
        else:
            fig = px.box(
                data_frame=dff,
                x='Year',
                y='CVSS_Score',
                title=f"CVSS Score Distribution for Each Year",
                color='Year',
                labels={'CVSS_Score': 'CVSS Score'},
            )
    else:
        fig = px.box(
            data_frame=dff,
            x='Vulnerability Type(s)',
            y='CVSS_Score',
            title="CVSS Score Distribution by Vulnerability Types",
            color='Vulnerability Type(s)',
            labels={'CVSS_Score': 'CVSS Score'},
        )
    fig.update_layout(showlegend=False, paper_bgcolor='rgba(0,0,0,0)')
    return fig

def wordcloud(year_selected):
    """
    Word Cloud on different vulnerability types
    Can be filtered by years
    """
    df = pd.read_csv('CleanCVEs/cveDetailsFull.csv')
    if year_selected != "All Years":
        df = df[df['Year'] == year_selected]
    df["Vulnerability Type(s)"] = df["Vulnerability Type(s)"].str.lower()

    freqofVul1 = df["Vulnerability Type(s)"].value_counts().to_frame()

    freqofVul1.index.name = "vul"

    freqofVul1 = freqofVul1.reset_index(level=[0])

    d = dict(zip(freqofVul1['vul'], freqofVul1['Vulnerability Type(s)']))
    wordcloud = WordCloud(background_color='#CAF1FF',
                          colormap='tab10',
                          width=512,
                          height=384,
                          normalize_plurals=True,
                          collocations=False).generate_from_frequencies(d)
    wc_img = wordcloud.to_image()
    with BytesIO() as buffer:
        wc_img.save(buffer, 'png')
        img = base64.b64encode(buffer.getvalue()).decode()
    #will be called into the app callback output
    return img