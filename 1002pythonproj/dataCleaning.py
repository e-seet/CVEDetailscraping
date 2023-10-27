import pandas as pd

years = [2022, 2021, 2020, 2019, 2018, 2017, 2016, 2015]
includedCVEs = ['CVE-2022', 'CVE-2021', 'CVE-2020', 'CVE-2019', 'CVE-2018', 'CVE-2017', 'CVE-2016', 'CVE-2015']

# Remove CVEs that are not from 2015-2022
def dropCVEs(df):
    droppedCVEs = []
    for i in list(df['CVE ID']):
        if i[:8] not in includedCVEs:
            droppedCVEs.append(i)
    df.index = list(df['CVE ID'])
    df.drop(droppedCVEs, axis=0, inplace=True)

# Clean CVE Details file
def cleanCVEDetails(year):
    df_CVE = pd.read_csv(f"cveDetails{year}.csv", encoding="cp1252")
    # Replace ?? to '' in Authentication column
    df_CVE['Authentication'] = df_CVE['Authentication'].replace(['??'], '')
    # Replace - to '' in Vulnerability Type(s) column
    df_CVE['Vulnerability Type(s)'] = df_CVE['Vulnerability Type(s)'].replace(['-'], '')
    # Call function to remove unwanted CVEs
    dropCVEs(df_CVE)
    # Save the CSV file
    df_CVE.to_csv(f'cveDetails{year}.csv', index=False)

# Remove rows that contain null data
def dropNullRows(year):
    df_CVE = pd.read_csv(f"cveDetails{year}.csv", encoding="cp1252")
    # Drop rows with null values
    df_CVE.dropna(inplace=True)
    # Save the CSV file
    df_CVE.to_csv(f'CleanCVEs/cveDetails{year}.csv', index=False)

# Clean Affected Products file
def cleanCVEProducts(year):
    df_Products = pd.read_csv(f"cveProducts{year}.csv", encoding="cp1252")
    # Remove the columns "Update", "Edition" and "Language" as it is mostly made of * values
    try:
        df_Products = df_Products.drop(["Update", "Edition", "Language"], axis=1)
    except:
        pass
    # Call function to remove unwanted CVEs
    dropCVEs(df_Products)
    # Save the CSV file
    df_Products.to_csv(f"CleanCVEs/cveProducts{year}.csv", index=False)

# Merge all the years worth of CVE details and affected products
def mergeFiles(years):
    df1 = pd.read_csv('CleanCVEs/cveDetails2022.csv')
    for i in years:
        df2 = pd.read_csv(f'CleanCVEs/cveDetails{i}.csv')
        df1 = pd.merge(df1, df2, how='outer')
    df1.to_csv(f"CleanCVEs/cveDetailsFull.csv", index=False)
    df3 = pd.read_csv('CleanCVEs/cveProducts2022.csv')
    for i in years:
        df4 = pd.read_csv(f'CleanCVEs/cveProducts{i}.csv')
        df3 = pd.merge(df3, df4, how='outer')
    df3.to_csv(f"CleanCVEs/cveProductsFull.csv", index=False)
#
for i in years:
    cleanCVEDetails(i)
    dropNullRows(i)
    cleanCVEProducts(i)
mergeFiles(years)