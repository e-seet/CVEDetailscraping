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


linkList2022 = []
# get all the links in a page


def Cve2022SinglePageLinks(pages):

    for x in range(len(pages)):
        driver.get(pages[x])
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'lxml')

        for a in soup.find_all('a', href=lambda href: href and href.startswith("/cve/")):
            thelink = "https://www.cvedetails.com" + a['href']
            if thelink not in linkList2022:
                linkList2022.append(thelink)


pageLink2022 = []
# Get all the pages from 1 to last


def Cve2022AllPageLinks():

    for x in range(2):  # 361
        thelink = "https://www.cvedetails.com/vulnerability-list.php?page={}&year=2022".format(
            x)
        if thelink not in pageLink2022:
            pageLink2022.append(thelink)


def writeToCSV(links):

    for x in range(len(links)):
        print(links[x])
    header = ['link']
    # open the file in the write mode
    with open('cve2022.csv', 'w', newline='') as f:
        # create the csv writer
        writer = csv.writer(f)
        writer.writerow(header)

        for x in range(len(links)):
            writer.writerow([links[x]])


def main():
    Cve2022AllPageLinks()
    Cve2022SinglePageLinks(pageLink2022)
    writeToCSV(linkList2022)
    driver.close()


if __name__ == '__main__':
    main()
