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


linkList = []
# get all the links in a page


def CveSinglePageLinks(pageLinks):

    for x in pageLinks:
        driver.get(x)
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'lxml')

        for a in soup.find_all('a', href=lambda href: href and href.startswith("/cve/")):
            thelink = "https://www.cvedetails.com" + a['href']
            if thelink not in linkList:
                linkList.append(thelink)


pageLinks = []
# Get all the pages from 1 to last


def CveAllPageLinks(year, pages):

    for page in range(1, pages+1):
        thelink = f"https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page={page}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=4&cvssscoremax=10&year={year}&month=0&cweid=0&order=1&trc=11309&sha=d379b99e409beb3e8822b833b9d92abdf4097feb"
        if thelink not in pageLinks:
            pageLinks.append(thelink)


def writeToCSV(links, year):

    # for x in links:
    #     print(x)
    header = ['link']
    # open the file in the write mode
    with open(f'cve{year}.csv', 'w', newline='') as f:
        # create the csv writer
        writer = csv.writer(f)
        writer.writerow(header)

        for x in links:
            writer.writerow([x])

numOfpages = {'2022':227} #, '2015':119, '2016':117, '2017':266, '2018':296}

def main():
    for year in numOfpages:
        CveAllPageLinks(year, numOfpages[year])
        CveSinglePageLinks(pageLinks)
        print(len(pageLinks))
        print(len(linkList))
        writeToCSV(linkList, year)
        driver.close()


if __name__ == '__main__':
    main()
