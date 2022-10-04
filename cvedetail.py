import csv
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium_stealth import stealth
from webdriver_manager.chrome import ChromeDriverManager

driver = webdriver.Chrome(ChromeDriverManager().install())
options = webdriver.ChromeOptions()

options.add_argument("start-maximized")
options.add_experimental_option("excludeSwitches", ["enable-automation"])
options.add_experimental_option('useAutomationExtension', False)


stealth(driver,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
        )

pageLinks = []
# Get all the pages from 1 to last
def CveAllPageLinks(year, pages, sha, trc):

    for page in range(1, pages+1):
        thelink = f"https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page={page}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=4&cvssscoremax=10&year={year}&month=0&cweid=0&order=1&trc={trc}&sha={sha}"
        if thelink not in pageLinks:
            pageLinks.append(thelink)

linkList = []
# Get all the links to each CVE in a page
def CveSinglePageLinks(pageLinks):

    for x in pageLinks:
        driver.get(x)
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'lxml')

        for a in soup.find_all('a', href=lambda href: href and href.startswith("/cve/")):
            thelink = "https://www.cvedetails.com" + a['href']
            if thelink not in linkList:
                linkList.append(thelink)

# Scrape info from website about each CVE
cveDetails = []
affectedProducts = []
def CveDetails(linkList):
    for link in linkList:
        driver.get(link)
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'lxml')
        text = soup.get_text()

        # Getting various details on CVEs
        cveID = link[link.find('cve/') + 4:-1]
        cvssScore = str(soup.find("div", {"class": "cvssbox"}))
        cvssScore = cvssScore[cvssScore.find('>') + 1:cvssScore.find('</div>')]
        confidentialityImpact = text[text.find('Confidentiality') + len('Confidentiality Impact') + 1:text.find('Integrity Impact') - 3]
        integrityImpact = text[text.find('Integrity') + len('Integrity Impact') + 1:text.find('Availability Impact') - 3]
        availabilityImpact = text[text.find('Availability') + len('Availability Impact') + 1:text.find('Access Complexity') - 3]
        authentication = text[text.find('Authentication') + len('Authentication') + 1:text.find('Gained Access') - 3]
        gainedAccess = text[text.find('Gained Access') + len('Gained Access') + 1:text.find('Vulnerability Type(s)') - 3]
        vulnerabilityType = text[text.find('Vulnerability Type(s)') + len('Vulnerability Type(s)') + 2:text.find('CWE ID') - 3]

        # To check if CVEs have multiple vulnerability types
        index1 = 0
        vulnList = []
        for i in range(len(vulnerabilityType)):
            if i == 0:
                index1 = i
            if vulnerabilityType[i].isupper() and vulnerabilityType[i-1].islower():
                index2 = i
                vulnList.append(vulnerabilityType[index1:index2])
                index1 = i
            elif i == len(vulnerabilityType)-1:
                if vulnerabilityType[i-1] == ' ':
                    index2 = i-1
                else:
                    index2 = i
                vulnList.append(vulnerabilityType[index1:index2])
        if vulnList == []:
            vulnList.append('')

        # Checking if CVE has any affected products
        productList = []
        count = 0
        if soup.find("div", {"class": "errormsg"}) == None:
            vulnProduct = soup.find("table", {"id": "vulnprodstable"})
            vulnProduct = str(vulnProduct)
            vulnProduct = vulnProduct.replace('\t', '')
            vulnProduct = vulnProduct.replace('\n', '')
            vulnProduct = vulnProduct.split("<")
            # Getting details on affected products
            for j in range(24, len(vulnProduct)):
                if vulnProduct[j].startswith('td'):
                    if vulnProduct[j][vulnProduct[j].find('>') + 1:] != '':
                        productList.append(vulnProduct[j][vulnProduct[j].find('>') + 1:])
                elif vulnProduct[j].startswith('a'):
                    productList.append(vulnProduct[j][vulnProduct[j].find('>') + 1:])
            # Counting the number of products affected
            for i in range(len(vulnProduct)):
                if 'td class="num">' in vulnProduct[i]:
                    count += 1
            # Keeping the relevant details on affected products
            countIndex = 0
            for i in range(count):
                product = []
                product.append(cveID)
                for j in range(countIndex, len(productList)):
                    if productList[j] == 'Version Details':
                        countIndex = j + 2
                        affectedProducts.append(product)
                        break
                    else:
                        product.append(productList[j])
            # print(affectedProducts)

        # Append the CVE details into list for storing into CSV file
        for i in vulnList:
            cveDetail = []
            cveDetail.append(cveID)
            cveDetail.append(link)
            cveDetail.append(cvssScore)
            cveDetail.append(confidentialityImpact[:confidentialityImpact.index('\n')])
            cveDetail.append(integrityImpact[:integrityImpact.index('\n')])
            cveDetail.append(availabilityImpact[:availabilityImpact.index('\n')])
            if "???" not in authentication:
                cveDetail.append(authentication[:authentication.index('\n')])
            else:
                cveDetail.append(authentication)
            cveDetail.append(gainedAccess)
            if i != '':
                cveDetail.append(i)
            else:
                cveDetail.append('-')
            # if productList != []:
            #     cveDetail.append(productList[2])  # Appending the vendor of the product
            # else:
            #     cveDetail.append('-')
            # if count != 0:
            #     cveDetail.append(count)
            # else:
            #     cveDetail.append('-')
            cveDetails.append(cveDetail)

# Write the cve details to CSV file
def writeToCSV(year):
    header1 = ["CVE ID", 'Link to CVE', 'CVSS Score', 'Confidentiality Impact', 'Integrity Impact',
              'Availability Impact', 'Authentication', 'Gained Access', 'Vulnerability Type(s)']
    # CSV file containing details on CSV
    with open(f'cveDetails{year}.csv', 'w', newline='') as f:
        # create the csv writer
        writer = csv.writer(f)
        writer.writerow(header1)
        for i in cveDetails:
            writer.writerow(i)

    header2 = ["CVE ID", "#", "Product Type", "Vendor", "Product", "Version", "Update", "Edition", "Language"]
    # CSV file containing details on products affected
    with open(f'cveProducts{year}.csv', 'w', newline='') as f:
        # create the csv writer
        writer = csv.writer(f)
        writer.writerow(header2)
        for i in affectedProducts:
            writer.writerow(i)

# list includes number of pages for the year, sha and total number of cve records for the year
# numOfpages = {'2022':[227, 'd379b99e409beb3e8822b833b9d92abdf4097feb', '11308'], '2021':[338, 'c2af181acc00f9c48c361450a6d53e25a002e412', '16873'], '2017':[266, '726cb9ed34d371bec461bce4d79640eb0f40a3ed', '13269'], '2015':[119, '99f0a8da10052844e77baad5467f2e32d90c05fe', '5913'], }
numOfpages = {'2020':[312, '03a9f57c6a47567bde261912fdb6d3ae622905e7', '15555'], '2019':[307, '6998c9b0e476e9f2dcbfd6ebff9503d774847252', '15306'], '2018':[296, '6988686c94470e073608fae0b039e4d06272a47d', '14759'], '2016':[117, '7b19190aa3dbaa35d014ff44a5cf607bec3f4565', '5837']}
def main():
    for year in numOfpages:
        CveAllPageLinks(year, numOfpages[year][0], numOfpages[year][1], numOfpages[year][2])
        CveSinglePageLinks(pageLinks)
        CveDetails(linkList)
        writeToCSV(year)
    driver.close()

if __name__ == '__main__':
    main()