# User-Defined Modules
from newDFs import *
from createGraphs import *

# Dash libraries
import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output

# Pandas library
import pandas as pd

# Deep-Learning model
from trainedModel import prediction, graph, get_data
import keras

# Initializing the Dash App
app = dash.Dash(__name__)
# Ignoring Dash callback exceptions
app.config.suppress_callback_exceptions = True
# CSS file for Dash App
app.css.append_css({'external_url': '/assets/reset.css'})

# Dash App Layout
app.layout = html.Div([
    # Title of webpage
    html.H1("Data Analysis on CVE Vulnerabilities", style={'text-align':'center', 'font-family': 'Arial', 'color': '#a0816c'}),

    # Filtering data by year
    html.Div(id="year", children=[
        html.P("Year:", style={'display': 'inline'}),

        dcc.RadioItems(
            id='select_year',
            options=[
                {"label": "2015", "value": 2015},
                {"label": "2016", "value": 2016},
                {"label": "2017", "value": 2017},
                {"label": "2018", "value": 2018},
                {"label": "2019", "value": 2019},
                {"label": "2020", "value": 2020},
                {"label": "2021", "value": 2021},
                {"label": "2022 (Jan-Aug)", "value": 2022},
                {"label": "All Years", "value": 'All Years'},

            ],
            value=2022,
            inline=True,
            style={'padding': 10, 'display': 'inline'},
        ),
    ], style={'font-family': 'Arial', 'display': 'inline'}),

    # Filtering type of data category to view
    html.Div(id="category", children=[
        html.P("Data Category:", style={'font-family': 'Arial',}),
        dcc.Dropdown(id='select_data',
             options=[
                 {"label": "Vulnerability Types", "value": 'VulnType'},
                 {"label": "CVSS Score", "value": 'CVSS Score'},
                 {"label": "Product Vendors", "value": 'Vendors'},
                 {"label": "All Categories", "value": 'All Categories'},],
             multi=False,
             value='VulnType',
             style={"width": "40%", 'font-family': "Arial", 'margin-left': '0.5%', 'margin-top':'0.3%'}
             )],
        style={'display': 'flex'}),

    # Filtering graph type for the data category: Vulnerability Types
    html.Div(id="graphType", children=[
        html.P("Graph for Vulnerability Types:", style={'font-family': 'Arial', }),
        dcc.Dropdown(id='select_vulngraph',
                     options=[
                         {"label": "Bar Graph", "value": "Bar Graph"},
                         {"label": "Pie Chart", "value": "Pie Chart"},
                         {"label": "Word Cloud", "value": "Word Cloud"},
                     ],
                     multi=False,
                     value="Bar Graph",
                     style={"width": "30%", 'font-family': "Arial", 'margin-left': '0.5%', 'margin-top': '0.3%'}
                     ),
    ],),

    # To display word cloud if option is chosen
    html.Div(id="wordcloud", children=[], style={'display': 'block', 'margin': 'auto'}),

    # Displaying various graphs
    html.Div([dcc.Graph(id='graph1',
                        # Hovering over the various bar graphs
                        hoverData={'points': [{'label': 'Execute Code'}]}),
              html.P('Hover over any of the Vulnerability Types to view the trend over the years', style={'font-family': 'Arial'}),], id="data_graph1"),
    html.Div([dcc.Graph(id='graph2')], id="data_graph2"),

    # Filtering to view box plot on CVSS Scores by vulnerability type or year
    html.Div(id="cvssScore_criteria", children=[
        html.P("Sort CVSS Scores by:", style={'font-family': 'Arial', }),
        dcc.Dropdown(id='cvssScore_sortby',
                     options=[
                         {"label": "Vulnerability Types", "value": 'Vulnerability Type(s)'},
                         {"label": "Year", "value": 'Year'},
                     ],
                     multi=False,
                     value='Vulnerability Type(s)',
                     style={"width": "40%", 'font-family': "Arial", 'margin-left': '0.5%', 'margin-top': '0.3%'}
                     ),
    ], ),

    # Displaying various graphs
    html.Div([dcc.Graph(id='graph3')], id="data_graph3"),
    html.Div([dcc.Graph(id='graph4')], id="data_graph4"),
    html.Div([dcc.Graph(id='graph5')], id="data_graph5"),

    # Selecting the number of product vendors to display
    html.Div(id="numOfProducts", children=[
        html.P("Top", style={'font-family': 'Arial', }),
        dcc.Dropdown(id='select_num',
                     options=[
                         {"label": "5", "value": 5},
                         {"label": "10", "value": 10},
                         {"label": "15", "value": 15},
                         {"label": "20", "value": 20},
                     ],
                     multi=False,
                     value=15,
                     style={"width": "30%", 'font-family': "Arial", 'margin-left': '0.5%', 'margin-top': '0.3%'}
                     ),
        html.P("Product Vendors", style={'font-family': 'Arial', 'position': 'relative', 'right': '350px'}),
    ], ),


    html.Div([dcc.Graph(id='graph6')], id="data_graph6"),
])

@app.callback(
    [
    # Callback to display the graphs
     Output('graph1', 'figure'),
     Output('graph2', 'figure'),
     Output('graph3', 'figure'),
     Output('graph4', 'figure'),
     Output('graph5', 'figure'),
     Output('graph6', 'figure'),

    # Callback to change the display of graphs / various inputs
     Output('data_graph1', 'style'),
     Output('data_graph2', 'style'),
     Output('data_graph3', 'style'),
     Output('data_graph4', 'style'),
     Output('data_graph5', 'style'),
     Output('data_graph6', 'style'),
     Output('graphType', 'style'),
     Output('numOfProducts', 'style'),
     Output('cvssScore_criteria', 'style'),
     Output('wordcloud', 'children'),
     ],
    [
    # Taking in the values of the various inputs
     Input(component_id='select_year', component_property='value'),
     Input(component_id='select_data', component_property='value'),
     Input(component_id='select_num', component_property='value'),
     Input(component_id='select_vulngraph', component_property='value'),
     Input(component_id='cvssScore_sortby', component_property='value'),
     Input('graph1', 'hoverData'),
    ],
)
def graph_output(year_selected, data_selected, num_selected, vulngraph, cvsscriteria, hoverData):
    # Data Category: Vulnerability Type
    if data_selected == 'VulnType':

        # Depending on whether a particular year is selected or all years
        if year_selected != "All Years":
            df = newVulnDF()
            dff = df.copy()
            dff = dff[dff['Year'] == year_selected]
        else:
            dff = newfullDF(data_selected)
        graph1Style = {'display': 'inline-block', 'width': '49%', 'float': 'left'}
        graph2Style = {'display': 'inline-block', 'width': '49%', 'float': 'right'}
        wordcloudoutput = ''
        # Depending on which type of graph is chosen, to call the respective function in createGraphs.py
        if vulngraph == 'Bar Graph':
            fig1 = bargraph(dff, year_selected, data_selected)
        elif vulngraph == 'Pie Chart':
            fig1 = piechart(dff, year_selected)
        else:
            fig1 = wordcloud(year_selected)
            graph1Style = {'display': 'none'}
            graph2Style = {'display': 'none'}
            wordcloudoutput = html.P(f'Vulnerability Type Word Cloud for {year_selected}', style={'font-family': 'Arial', 'text-align': 'center'}),\
                              html.Img(src="data:image/png;base64," + fig1, style={'display': 'block', 'margin': 'auto'}),\
                              html.Br()

        # Retrieve out the hovered vulnerability type for line graph
        vulnType = hoverData['points'][0]['label']
        if vulnType not in dff['Vulnerability Type(s)'].unique():
            vulnType = 'Execute Code'
        dff2 = singlevulnDF(vulnType)
        fig2 = linegraph(dff2, vulnType)

        # Rest of the graphs are hidden from view
        fig3 = ''
        fig4 = ''
        fig5 = ''
        fig6 = ''
        graph3Style = {'display': 'none'}
        graph4Style = {'display': 'none'}
        graph5Style = {'display': 'none'}
        graph6Style = {'display': 'none'}

        # Various input displays
        graphtype = {'display': 'flex'}
        vendorinput = {'display': 'none'}
        cvssinput = {'display': 'none'}
        return fig1, fig2, fig3, fig4, fig5, fig6,\
               graph1Style, graph2Style, graph3Style, graph4Style, graph5Style, graph6Style,\
               graphtype, vendorinput, cvssinput, wordcloudoutput

    # Data Category: CVSS Score
    elif data_selected == "CVSS Score":
        df1 = pd.read_csv("CleanCVEs/cveDetailsFull.csv")

        # To check if viewing box plot by year or vulnerability type
        if cvsscriteria == 'Year':
            fig3 = boxplot(df1, cvsscriteria, year_selected)
        else:
            fig3 = boxplot(df1, cvsscriteria)
        df2 = cvssScoreDF()
        fig1 = ''
        fig2 = ''
        # To plot scatter plot on average CVSS score over the years
        fig4 = scatterplot(df2)

        # To load deep learning model
        model = keras.models.load_model('./model.h5')

        # Split the data
        x_train, x_test, y_train, y_test = get_data()

        # Create predictions on testing set
        predictions = prediction(model, x_test, y_test)

        # Plot the scatter plot on predicted over actual values
        fig5 = graph(y_test, predictions)
        fig6 = ''
        graph1Style = {'display': 'none'}
        graph2Style = {'display': 'none'}
        graph3Style = {'display': 'block'}
        graph4Style = {'display': 'block'}
        graph5Style = {'display': 'block'}
        graph6Style = {'display': 'none'}
        graphtype = {'display': 'none'}
        vendorinput = {'display': 'none'}
        cvssinput = {'display': 'flex'}
        wordcloudoutput = ''
        return fig1, fig2, fig3, fig4, fig5, fig6,\
               graph1Style, graph2Style, graph3Style, graph4Style, graph5Style, graph6Style,\
               graphtype, vendorinput, cvssinput, wordcloudoutput

    # Data Category: Product Vendors
    elif data_selected == 'Vendors':

        # Depending on whether a particular year is selected or all years
        if year_selected != "All Years":
            df = newVendorDF(year_selected, num_selected)
        else:
            df = newfullDF(data_selected, num_selected)
        fig1 = ''
        fig2 = ''
        fig3 = ''
        fig4 = ''
        fig5 = ''
        fig6 = bargraph(df, year_selected, data_selected, num_selected)
        graph1Style = {'display': 'none'}
        graph2Style = {'display': 'none'}
        graph3Style = {'display': 'none'}
        graph4Style = {'display': 'none'}
        graph5Style = {'display': 'none'}
        graph6Style = {'display': 'block'}
        graphtype = {'display': 'none'}
        vendorinput = {'display': 'flex'}
        cvssinput = {'display': 'none'}
        wordcloudoutput = ''
        return fig1, fig2, fig3, fig4, fig5, fig6,\
               graph1Style, graph2Style, graph3Style, graph4Style, graph5Style, graph6Style,\
               graphtype, vendorinput, cvssinput, wordcloudoutput

    # To view all data categories
    elif data_selected == 'All Categories':

        # Depending on whether a particular year is selected or all years
        if year_selected != "All Years":
            df2 = newVulnDF()
            dff = df2.copy()
            dff = dff[dff['Year'] == year_selected]
            df5 = newVendorDF(year_selected, num_selected)
        else:
            dff = newfullDF("VulnType")
            df5 = newfullDF("Vendors", num_selected)
        graph1Style = {'display': 'inline-block', 'width': '49%', 'float': 'left'}
        graph2Style = {'display': 'inline-block', 'width': '49%', 'float': 'right'}
        wordcloudoutput = ''

        # Based on the vulnerability type graph choosen
        if vulngraph == 'Bar Graph':
            fig1 = bargraph(dff, year_selected, 'VulnType')
        elif vulngraph == 'Pie Chart':
            fig1 = piechart(dff, year_selected)
        else:
            fig1 = wordcloud(year_selected)
            graph1Style = {'display': 'none'}
            graph2Style = {'display': 'none'}
            wordcloudoutput = html.P(f'Vulnerability Type Word Cloud for {year_selected}', style={'font-family': 'Arial', 'text-align': 'center'}),\
                              html.Img(src="data:image/png;base64," + fig1, style={'display': 'block', 'margin': 'auto'}),\
                              html.Br()

        # Retrieve out the hovered vulnerability type for line graph
        vulnType = hoverData['points'][0]['label']
        if vulnType not in dff['Vulnerability Type(s)'].unique():
            vulnType = 'Execute Code'
        dff2 = singlevulnDF(vulnType)
        fig2 = linegraph(dff2, vulnType)
        df3 = pd.read_csv("CleanCVEs/cveDetailsFull.csv")

        # To check if viewing box plot by year or vulnerability type
        if cvsscriteria == 'Year':
            fig3 = boxplot(df3, cvsscriteria, year_selected)
        else:
            fig3 = boxplot(df3, cvsscriteria)

        # Scatter plot
        df4 = cvssScoreDF()
        fig4 = scatterplot(df4)

        # Scatter plot for deep learning model on actual vs predicted cvss score
        model = keras.models.load_model('./model.h5')
        x_train, x_test, y_train, y_test = get_data()
        predictions = prediction(model, x_test, y_test)
        fig5 = graph(y_test, predictions)

        # Bar graph on product vendors
        fig6 = bargraph(df5, year_selected, 'Vendors', num_selected)

        graph3Style = {'display': 'block', 'clear': 'both'}
        graph4Style = {'display': 'block', 'clear': 'both'}
        graph5Style = {'display': 'block', 'clear': 'both'}
        graph6Style = {'display': 'block', 'clear': 'both'}
        graphtype = {'display': 'flex'}
        vendorinput = {'display': 'flex', 'clear': 'both'}
        cvssinput = {'display': 'flex', 'clear': 'both'}
        return fig1, fig2, fig3, fig4, fig5, fig6,\
               graph1Style, graph2Style, graph3Style, graph4Style, graph5Style, graph6Style,\
               graphtype, vendorinput, cvssinput, wordcloudoutput

if __name__ == '__main__':
    app.run_server()