import urllib.request
import os
from bs4 import BeautifulSoup
from tkinter import messagebox
from tkinter import *
from tkinter import ttk
from pandas import DataFrame
import urllib.request
from urlextract import URLExtract
import tldextract
from threading import Thread as process
import ssl, urllib

if not (os.path.isdir(".\\urlextract\\data")):  # 이거 안해주면 urlextract모듈 오류남
    os.makedirs(".\\urlextract\\data")
    urllib.request.urlretrieve("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", ".\\urlextract\\data\\tlds-alpha-by-domain.txt")

#snort------------------------------------------------------------------------------------------------------------------
#snort search 함수 정의
def search(event=None):
    entry_result.delete(1.0,END)
    find = entry_search.get()
    f = open("C:\\RuleSearch\merge\merge_snort.txt")
    ff = f.read()

    str_n = "\n"
    lines = ff.split(str_n)
    test = open("./search_result.txt",'w')
    for each_line in lines:
        abc=[]
        if each_line.find(find)>0:
            el=each_line
            print(el+"\n끝")
            test.write(el+"\n\n")
        else:
            pass
    test.close()
    test = open("./search_result.txt", 'r')


    abc=test.read()
    print(abc)
    result_test.set("결과는"+ abc +'이거')
    entry_result.insert(CURRENT,abc)
    test.close()
    os.remove("./search_result.txt")

#update 함수 정의
def update():
    messagebox.showinfo("확인창", "업데이트를 실행하였습니다.")
    aaa = os.path.exists("C:\RuleSearch")
    if aaa == False:
        os.mkdir("C:\RuleSearch")
    bbb = os.path.exists("C:\RuleSearch\merge")
    if bbb == False:
        os.mkdir("C:\RuleSearch\merge")

    #08-18 14:00 코딩 시작
    #BeautifulSoup를 이용하여 아래 페이지 내용 크롤링

    url = "https://rules.emergingthreats.net/open/snort-2.9.0/rules/"
    soup = BeautifulSoup(urllib.request.urlopen(url).read(), features="html.parser")

    #refer.txt 파일 생성 후 href로 링크만 선별 후 '\n'을 이용하여 한줄씩 입력
    text1 = open('refer.txt','w')
    for link in soup.findAll("a"):
        if 'href' in link.attrs:
            list = link.attrs['href']
            text1.write(list + "\n")
    text1.close()

    #입력된 refer.txt의 전체 내용을 변수에 지정한 후 "rules" 확장자 선별
    t = open('refer.txt','r')

    text = t.read()
    t.close()
    view = text
    print(view)
    entry_result.insert(1.0, view + '\n')

    count=0
    good = text.split('\n')
    for each_line in good :
        if each_line.find(".rules")>0:
            dest = each_line
            down = url + dest
            done = urllib.request.urlopen(down).read()
            open('C:\\RuleSearch\\'+dest + ".txt",'wb').write(done)
            count = count + 1
            view = "현재 파일을 다운로드 중 입니다. {0}".format(count)
            entry_result.insert(1.0, view + '\n')
            #print(down)
    else:
        pass
    entry_result.insert(1.0, "파일을 결합 중 입니다.\n")

    ####08-19 01:23 접근 너무많이해서 차단당함
    directory = "C:\RuleSearch\\"
    mf_name = "merge\merge_snort.txt"
    path = directory + mf_name
    mf= open(path, 'w')
    files = os.listdir(directory)
    for filename in files:
        if ".txt" not in filename:
            continue
        file = open(directory + filename)
        for line in file:
            mf.write(line)
        mf.write("\n\n")
        file.close()
    mf.close()
    entry_result.insert(1.0, "업데이트가 완료 되었습니다.\n")
    messagebox.showinfo("완료창","업데이트가 완료되었습니다.")

    '''
    os.remove(".\\urlextract\\data\\tlds-alpha-by-domain.txt")
    os.rmdir(".\\urlextract\\data")
    os.rmdir(".\\urlextract")
    '''
##snort-----------------------------------------------------------------------------------------------------------------


#IP 국가 조회------------------------------------------------------------------------------------------------------------
def trans(event=None):
    messagebox.showinfo("확인창", "조회 중입니다. 잠시만 기다려주세요")
    text2.delete(1.0,END)
    count = 1
    while text1.get(count + .0, count + .15) != "":
        ips = text1.get(count + .0, count + .15)
        try:
            from urllib.error import HTTPError
            url = "https://xn--c79as89aj0e29b77z.xn--3e0b707e/openapi/ipascc.jsp?answer=[xml,json]&key=2019081808130366639834&query=" + ips
            soup = BeautifulSoup(urllib.request.urlopen(url).read(), features="html.parser")
            print(soup)
            whois = soup.countrycode.string
            # print(whois)
        except (HTTPError, AttributeError, TypeError) as e:
            print("128줄 오류발생IP: {0}".format(ips))
            return messagebox.showwarning("오류창", "IP주소를 형식에 맞게 입력해 주세요\n에러메시지 : {0}".format(e))
        whois_kr = find_ip(whois)
        text2.insert(count + .0, ips + " (" + whois_kr+")\n")
        count = count + 1

#도메인 조회-------------------------------------------------------------------------------------------------------------
def ip_domain(trash):
    global ip_domain_find_result
    #ip_domain_find = re.compile('[/]((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[\/a-zA-Z0-9._%+-]+)')
    ip_domain_find = re.compile('([a-z]{4,5}://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):?[0-9]{1,5}?[\/a-zA-Z0-9._%+-]+)')
    result = ip_domain_find.findall(trash)
    print(result)
    print("뭐라할까")
    result1 = result

    abcd = result1 == []
    if abcd is True:
        print("없음")
        global max
        max = 0
        ip_domain_find_result = ("IP로 된 도메인 없음")
    else:
        max = len(result)
        count = 0
        while count < max: #IP로 된 도메인 파싱과정
            print("IP로 분류된것 : {0}".format(result[count]))
            protocol_for_ip_raw = result[count][0:5]
            protocol_for_ip = protocol_for_ip_raw.replace(":", "")

            port_raw2 = result[count].replace("://", "")
            port_raw_end = port_raw2.find("/")
            port_raw_start = port_raw2.find(":")
            if port_raw_start == -1:  # 뒤에 :8080 같은게 없을때
                print("protocol : {0}".format(protocol_for_ip))
                if protocol_for_ip == "http" or protocol_for_ip == 'hxxp':
                    port = "80"
                elif protocol_for_ip == "https" or protocol_for_ip == 'hxxps':
                    port = "443"
                else:
                    port = ""
                    protocol_for_ip = ""
            else:  # 뒤에 8080같은게 있을때
                if port_raw_end == -1:  # /가 없을때
                    print(port_raw_end)
                    port = port_raw2[port_raw_start + 1:]
                else:
                    port = port_raw2[port_raw_start + 1:port_raw_end]

            Sub_URL_raw2 = result[count].replace("://", "")
            Sub_URL_raw1 = Sub_URL_raw2.find("/")
            Sub_URL = Sub_URL_raw2[Sub_URL_raw1:]

            URL_start = result[count].find("://")
            URL_end_for = result[count].replace("://","")
            URL_end = URL_end_for.find("/")
            if URL_end == -1:
                URL = result[count][URL_start+3:]
            else:
                URL = result[count][URL_start+3:URL_end+3]
            if URL.find(":") == -1 : #URL에 포트표기되어있는지 확인하려고
                whois = ip_to_country(URL)
                country = "{0},{1}".format(URL, whois)
            else:

                URL = URL[:URL.find(":")]
                whois = ip_to_country(URL)
                country = "{0},{1}".format(URL, whois)

            print(ip_domain_find_result)
            ip_domain_find_result = "{0}".format(ip_domain_find_result) + "\nCategory,{0},{1},{2},{3},{4},{5},D".format(protocol_for_ip, URL, Sub_URL, result[count],port,country)
            count += 1


def ip_to_country(ip):
    try:
        from urllib.error import HTTPError, URLError
        url = "https://xn--c79as89aj0e29b77z.xn--3e0b707e/openapi/ipascc.jsp?answer=[xml,json]&key=2019081808130366639834&query=" + ip
        soup = BeautifulSoup(urllib.request.urlopen(url, timeout=1).read(), features="html.parser")
        whois = soup.countrycode.string
    except (HTTPError, AttributeError, TypeError) as e:
        print("208줄 오류발생IP: {0}".format(ip))
        return messagebox.showwarning("오류창", "IP주소를 형식에 맞게 입력해 주세요\n에러메시지 : {0}".format(e))
    except (TimeoutError, URLError) as e:
        print("{0}".format(e))
        url = "https://xn--c79as89aj0e29b77z.xn--3e0b707e/openapi/ipascc.jsp?answer=[xml,json]&key=2019081808130366639834&query=" + ip
        soup = BeautifulSoup(urllib.request.urlopen(url, timeout=1).read(), features="html.parser")
        whois = soup.countrycode.string
        print("됨?")
    return  whois
    #whois_kr = find_ip(whois)
    #zzan = ip + " (" + whois_kr + ")"
    #return zzan

def ip_to_country_for_csv_to(ip):
    try:
        from urllib.error import HTTPError, URLError
        url = "https://xn--c79as89aj0e29b77z.xn--3e0b707e/openapi/ipascc.jsp?answer=json&key=2019081808130366639834&query=" + ip
        soup = BeautifulSoup(urllib.request.urlopen(url, timeout=1).read(), features="html.parser")
        whois = soup.countrycode.string
    except (HTTPError, AttributeError, TypeError) as e:
        print("228줄 오류발생IP: {0}".format(ip))
        return messagebox.showwarning("오류창", "IP주소를 형식에 맞게 입력해 주세요\n에러메시지 : {0}".format(e))
    except (TimeoutError, URLError) as e:
        print("{0}".format(e))
        url = "https://xn--c79as89aj0e29b77z.xn--3e0b707e/openapi/ipascc.jsp?answer=json&key=2019081808130366639834&query=" + ip
        soup = BeautifulSoup(urllib.request.urlopen(url, timeout=1).read(), features="html.parser")
        whois = soup.countrycode.string
        print("됨?")
    zzan = ip + ","  + whois
    return zzan

def domains_to_parse(url):
    urlc = url.replace("\'", "")
    urlb = urlc.replace("[", "")
    global  urla
    urla = urlb.replace("]", "")
    extracted1 = tldextract.extract(urla)
    print("머가머가{0}".format(extracted1))
    if extracted1.subdomain == "":
        if extracted1.suffix == "":
            a = "{}".format(extracted1.domain)
        else:
            a = "{}.{}".format(extracted1.domain, extracted1.suffix)
    else:
        a = "{}.{}.{}".format(extracted1.subdomain, extracted1.domain, extracted1.suffix)
    print("추출된 도메인 : {0}".format(a))
    nslookup_pcre = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
    yesorno = nslookup_pcre.findall(a)
    if yesorno != []:
        print("얜 IP로 된 도메인이라 패스~")
    else:
        find_domain_ip(a)

def find_all_domain_11_06(rawall):
    ip_domain_find = re.compile('(?://?\/?)')

#ip_domain_find_result = []
def rawdomains(event=None):
    messagebox.showinfo("확인창", "조회 중입니다. 잠시만 기다려주세요")
    text3_2.delete(1.0, END)
    text3_csv.delete(1.0,END)
    text3_csv_to.delete(1.0, END)

    global ip_domain_find_result
    ip_domain_find_result = []

    aaa = text3_1.get(1.0,END)
    ip_domain(aaa)

    extractor = URLExtract()
    urls = extractor.find_urls(aaa) #urlextract_core.py 에서 host.split(".") 을 str(host).split(".")로
    print("URL들 : {0}".format(urls))
    count = len(urls)
    if urls == []:
        text3_2.insert(1.0, aaa + "도메인이 아닙니다.")
        text3_csv.insert(1.0, aaa + "도메인이 아닙니다.")
        text3_csv_to.insert(1.0, aaa + "도메인이 아닙니다.")
    else:
        ip_pcre = re.compile('([a-z]{4,5}://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?:?)[\/a-zA-Z0-9._%+-]+)')
        cc= 0
        bbagi = 0
        for i in urls:
            abcd = ip_pcre.findall(urls[cc])
            if abcd != []:
                print("뺄녀석 : {0}".format(abcd))
                bbagi = bbagi + 1
                cc = cc + 1
            else:
                print("안뺄녀석 : {0}".format(urls[cc]))
                bbagi = bbagi + 0
                cc = cc + 1
        count2 = count - bbagi
        print("총 갯수 : {0}, 뺄 갯수 : {1}, 뺀 갯수 : {2}".format(count,bbagi,count2))
        a = 0
        text3_2.insert(1.0, "\t- 분석 도메인 갯수 : {0}개 -\n".format(count2))

        text3_csv.insert(1.0, "도메인 (총 : {0}개),IP,국가명,확인용\n".format(count2))
        text3_csv_to.insert(1.0, "Category, Protocol, URL, Sub_URL, Full_URL, Port, IP, Country, Action, Ext1, Ext2\n")
        while a < count:
            if a == count -1:
                domains_to_parse(urls[a])

                text3_2.insert(END, "\n\t- 조회가 끝났습니다. -")
                text3_csv.insert(END, "조회가 끝났습니다.\n\n")

                ip_domain_find_result = "{0}".format(ip_domain_find_result)
                print("IP로 된 도메인 결과는 : {0}".format(ip_domain_find_result))
                text3_csv.insert(END, "IP로 된 도메인 결과 : \n{0}".format(ip_domain_find_result))
                text3_csv_to.insert(END, "IP로 된 도메인 결과 : \n{0}".format(ip_domain_find_result))
                global max
                text3_2.insert(END, "\n\nIP로 된 도메인 결과 : {0}개\n\n".format(max))
                a = a + 1
            else:
                domains_to_parse(urls[a])
                a = a + 1
    print(text3_csv.get(1.0, END))

def export_csv():
    print("hello")
    try:
        file = open("Mal.csv", 'w')
        file.write(text3_csv.get(1.0,END))
        file.close()
        os.popen("Mal.csv")
    except:
        messagebox.showerror("오류창", "현재 파일이 열려있습니다. 종료 후 다시 눌러주세요.")

def export_csv_to():
    print("hello")
    try:
        file = open("Mal_to.csv", 'w')
        file.write(text3_csv_to.get(1.0,END))
        file.close()
        os.popen("Mal_to.csv")
    except:
        messagebox.showerror("오류창", "현재 파일이 열려있습니다. 종료 후 다시 눌러주세요.")
'''
def getIpAddr(url):
    command = 'nslookup ' + url
    process = os.popen(command)
    results = str(process.read())
    hehe = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
    helloo = hehe.findall(results)
    print(helloo)
getIpAddr("cdn.discordapp.com")
'''
def nslookup(domain): #nslookup timed out 발생 시 재조회 기능
    command = 'nslookup ' + domain + ' 8.8.8.8'
    process = os.popen(command)
    results = "{0}".format(process.read())
    find_error = results.find("timed out")

    if find_error != -1:
        process.close()
        print("exception 발생")
        raise Exception('timed out! 재조회합니당')
    return results

def find_domain_ip(domain):
    global urla
    print(urla)
    print(urla.find(""))
    protocol_raw = urla[0:5]
    protocol = protocol_raw.replace(":", "")
    Sub_URL_raw2 = urla.replace("://", "")
    Sub_URL_raw1 = Sub_URL_raw2.find("/")
    Sub_URL_raw = Sub_URL_raw2[Sub_URL_raw1:]
    port_raw2 = urla.replace("://", "")
    port_raw_end = port_raw2.find("/")
    port_raw_start = port_raw2.find(":")
    if port_raw_start == -1: #뒤에 :8080 같은게 없을때
        print("protocol : {0}".format(protocol))
        if protocol == "http" or protocol == 'hxxp':
            port = "80"
        elif protocol == "https" or protocol =='hxxps':
            port = "443"
        else:
            port = ""
            protocol = ""
    else: #뒤에 8080같은게 있을때
        if port_raw_end == -1: #/가 없을때
            print(port_raw_end)
            port = port_raw2[port_raw_start+1:]
        else:
            port = port_raw2[port_raw_start+1:port_raw_end]
    if Sub_URL_raw1 == -1 or Sub_URL_raw == "/":
        Sub_URL_raw = ""

    try:
        results = nslookup(domain)
    except:
        print("재조회중")
        results = nslookup(domain)

    results = results.replace('8.8.8.8',"")
    print(results)
    nslookup_pcre = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
    nslookup_IPs = nslookup_pcre.findall(results)
    print(nslookup_IPs)
    #else:
    #    nslookup_IPs = ["0.0.0.0"]
    #    pass

    bbb = 0
    URL = domain
    count = len(nslookup_IPs)
    text3_2.insert(END, domain + "=> {0}개\n".format(count))
    #text3_csv.insert(END, domain + " {0}개".format(count))
    if count == 0:
        text3_2.insert(END, " \t=>nslookup 조회 안됨\n")
        text3_csv.insert(END, domain + ",nslookup 조회 안됨\n")
        text3_csv_to.insert(END, ",{0},{1},{2},{3},{4}".format(protocol, URL, Sub_URL_raw, urla, port) + ",조회 불가,,D,,\n")
    while bbb < count:
        test = nslookup_IPs[bbb]
        whois = ip_to_country(test)
        good = "{0} ({1})".format(test, find_ip(whois))
        good_csv = "{0},({1})".format(test, find_ip(whois))
        good_csv_to = "{0},{1}".format(test, whois)
        if bbb == 0:
            text3_2.insert(END, "\t" + good + "\n")
            text3_csv.insert(END, "{0},".format(urla) + good_csv + ",{0}개\n".format(count))
            text3_csv_to.insert(END, ",{0},{1},{2},{3},{4}".format(protocol,URL, Sub_URL_raw ,urla, port) +","+ good_csv_to + ",D,,\n")

        elif bbb == count - 1:
            print(good)
            text3_2.insert(END, "\t" + good + "\n")
            #text3_csv.insert(END, ip_to_country_for_csv(test) + "\n")

            #text3_csv.insert(END, "{0},".format(urla) + domain + "," + ip_to_country_for_csv(test) + "\n")
            text3_csv.insert(END, "\t{0},".format(urla) + good_csv + "\n")
            text3_csv_to.insert(END, ",{0},{1},{2},{3},{4}".format(protocol,URL, Sub_URL_raw ,urla, port) +","+ good_csv_to + ",D,\n")
        else:
            print(good)
            text3_2.insert(END, "\t" + good + "\n")
            #text3_csv.insert(END, ip_to_country_for_csv(test)+" ")
            #text3_csv.insert(END, "{0},".format(urla) + domain + "," + ip_to_country_for_csv(test) + "\n")
            text3_csv.insert(END, "\t{0},".format(urla) + good_csv + "\n")
            text3_csv_to.insert(END, ",{0},{1},{2},{3},{4}".format(protocol,URL, Sub_URL_raw ,urla, port) +","+good_csv_to + ",D,\n")
        bbb = bbb + 1
    '''
    except socket.gaierror:
        text3_2.insert(END,domain +" =>\n\tnslookup 조회 안됨\n")
        text3_csv.insert(END, domain + ",nslookup 조회 안됨\n")
        text3_csv_to.insert(END, domain + ",nslookup 조회 안됨\n")
        pass
    except socket.error as e:
        text3_2.insert(END, " => 서버 오류로 해당 도메인 재조회 필요\n")
        text3_csv.insert(END, domain + ",,,서버 오류로 해당 도메인 재조회 필요\n")
        text3_csv_to.insert(END, ",,{0},서버 오류로 해당 도메인 재조회 필요\n".format(domain))
        #messagebox.showerror("오류창", "연결된 구성으로부터, 응답이 없어 연결하지 못했거나, 호스트로부터 응답이 없어 연결이 끊어졌습니다. 해당 도메인만 다시 조회해주세요")
        print(e)
    '''


    #text3_2.insert(END," \n입니다.")
    #print("입니다.")
    #(


def find_ip(whois):
    raw_code = {'AD': ['안도라'],
            'AE': ['아랍에미리트'],
            'AF': ['아프가니스탄'],
            'AG': ['안티구아 바부다'],
            'AI': ['앙길라'],
            'AL': ['알바니아'],
            'AM': ['아르메니아'],
            'AN': ['네덜란드령 안틸레스'],
            'AO': ['앙골라'],
            'AQ': ['안타티카'],
            'AR': ['아르헨티나'],
            'AS': ['아메리칸 사모아'],
            'AT': ['오스트리아'],
            'AU': ['호주'],
            'AW': ['아루바'],
            'AX': ['알랜드 군도'],
            'AZ': ['아제르바이잔'],
            'BA': ['보스니아 헤르체고비나'],
            'BB': ['바베이도스'],
            'BD': ['방글라데시'],
            'BE': ['벨기에'],
            'BF': ['부르키나파소'],
            'BG': ['불가리아'],
            'BH': ['바레인'],
            'BI': ['브룬디'],
            'BJ': ['베냉'],
            'BL': ['세인트 바르탤르미'],
            'BM': ['버뮤다'],
            'BN': ['브루나이'],
            'BO': ['볼리비아'],
            'BQ': ['보네르'],
            'BR': ['브라질'],
            'BS': ['바하마'],
            'BT': ['부탄'],
            'BV': ['부베섬'],
            'BW': ['보츠와나'],
            'BY': ['벨라루스'],
            'BZ': ['벨리즈'],
            'CA': ['캐나다'],
            'CC': ['코코스 제도'],
            'CD': ['콩고민주공화국'],
            'CF': ['중앙아프리카공화국'],
            'CG': ['콩고'],
            'CH': ['스위스'],
            'CI': ['코트디부아르'],
            'CK': ['쿡 제도'],
            'CL': ['칠레'],
            'CM': ['카메룬'],
            'CN': ['중국'],
            'CO': ['콜롬비아'],
            'CR': ['코스타리카'],
            'CU': ['쿠바'],
            'CV': ['카보베르데'],
            'CW': ['큐라소'],
            'CX': ['크리스마스섬'],
            'CY': ['사이프러스'],
            'CZ': ['체코공화국'],
            'DE': ['독일'],
            'DJ': ['지부티'],
            'DK': ['덴마크'],
            'DM': ['도미니카'],
            'DO': ['도미니카 공화국'],
            'DZ': ['알제리'],
            'EC': ['에쿠아도르'],
            'EE': ['에스토니아'],
            'EG': ['이집트'],
            'EH': ['서사하라'],
            'ER': ['에리트레아'],
            'ES': ['스페인'],
            'ET': ['이디오피아'],
            'FI': ['핀란드'],
            'FJ': ['피지'],
            'FK': ['포클랜드섬'],
            'FM': ['미크로네시아'],
            'FO': ['페로 군도'],
            'FR': ['프랑스'],
            'GA': ['가봉'],
            'GB': ['영국'],
            'GD': ['그레나다'],
            'GE': ['구루지아'],
            'GF': ['프랑스령 기아나'],
            'GG': ['건지'],
            'GH': ['가나'],
            'GI': ['지브랄타'],
            'GL': ['그린랜드'],
            'GM': ['감비아'],
            'GN': ['기니'],
            'GP': ['과들루프'],
            'GQ': ['적도 기니'],
            'GR': ['그리스'],
            'GS': ['사우스조지아 사우스샌드위치 제도'],
            'GT': ['과테말라'],
            'GU': ['괌'],
            'GW': ['기네비쏘'],
            'GY': ['가이아나'],
            'HK': ['홍콩'],
            'HM': ['허드 맥도날드 군도'],
            'HN': ['온두라스'],
            'HR': ['크로아티아'],
            'HT': ['아이티'],
            'HU': ['헝가리'],
            'ID': ['인도네시아'],
            'IE': ['아일랜드'],
            'IL': ['이스라엘'],
            'IM': ['맨섬'],
            'IN': ['인도'],
            'IO': ['영인도 제도'],
            'IQ': ['이라크'],
            'IR': ['이란'],
            'IS': ['아이슬랜드'],
            'IT': ['이탈리아'],
            'JE': ['저지'],
            'JM': ['자메이카'],
            'JO': ['요르단'],
            'JP': ['일본'],
            'KE': ['케냐'],
            'KG': ['키르기스스탄'],
            'KH': ['캄보디아'],
            'KI': ['키리바시'],
            'KM': ['코모르'],
            'KN': ['세인트 키츠 네비스'],
            'KP': ['북한'],
            'KR': ['한국'],
            'KV': ['코소보'],
            'KW': ['쿠웨이트'],
            'KY': ['케이맨섬'],
            'KZ': ['카자흐스탄'],
            'LA': ['라오스'],
            'LB': ['레바논'],
            'LC': ['세인트 루시아'],
            'LI': ['리히텐슈타인'],
            'LK': ['스리랑카'],
            'LR': ['라이베리아'],
            'LS': ['레소토'],
            'LT': ['리투아니아'],
            'LU': ['룩셈부르크'],
            'LV': ['라트비아'],
            'LY': ['리비아'],
            'MA': ['모로코'],
            'MC': ['모나코'],
            'MD': ['몰도바'],
            'MF': ['세인트 마틴'],
            'MG': ['마다가스카르'],
            'MH': ['마샬군도'],
            'MK': ['마케도니아'],
            'ML': ['말리'],
            'MM': ['미얀마'],
            'MN': ['몽골'],
            'MO': ['마카오'],
            'MP': ['북마리아나 군도'],
            'MQ': ['마르티니크'],
            'MR': ['모리타니'],
            'MS': ['몬트세라트'],
            'MT': ['말타'],
            'MU': ['모리셔스'],
            'MV': ['몰디브'],
            'MW': ['말라위'],
            'MX': ['멕시코'],
            'MY': ['말레이지아'],
            'MZ': ['모잠비크'],
            'NA': ['나미비아'],
            'NC': ['뉴칼레도니아'],
            'NE': ['니제르'],
            'NF': ['노퍽섬'],
            'NG': ['나이지리아'],
            'NI': ['니카라과'],
            'NL': ['네덜란드'],
            'NO': ['노르웨이'],
            'NP': ['네팔'],
            'NR': ['나우루'],
            'NT': ['중립지대'],
            'NU': ['니우에'],
            'NZ': ['뉴질랜드'],
            'OM': ['오만'],
            'PA': ['파나마'],
            'PE': ['페루'],
            'PF': ['프랑스령 폴리네시아'],
            'PG': ['파푸아뉴기니'],
            'PH': ['필리핀'],
            'PK': ['파키스탄'],
            'PL': ['폴란드'],
            'PM': ['세인트 피에르 미?론'],
            'PN': ['핏케언 군도'],
            'PR': ['푸에르토리코'],
            'PS': ['팔레스타인'],
            'PT': ['포르투갈'],
            'PW': ['팔라우'],
            'PY': ['파라과이'],
            'QA': ['카타르'],
            'RE': ['리유니언'],
            'RO': ['루마니아'],
            'RS': ['세르비아'],
            'RU': ['러시아'],
            'RW': ['르완다'],
            'SA': ['사우디아라비아'],
            'SB': ['솔로몬 군도'],
            'SC': ['세이셸'],
            'SD': ['수단'],
            'SE': ['스웨덴'],
            'SG': ['싱가포르'],
            'SH': ['세인트 헬레나'],
            'SI': ['슬로베니아'],
            'SJ': ['스발바르드 얀마이엔 제도'],
            'SK': ['슬로바키아'],
            'SL': ['시에라리온'],
            'SM': ['산마리노'],
            'SN': ['세네갈'],
            'SO': ['소말리아'],
            'SR': ['수리남'],
            'SS': ['남수단'],
            'ST': ['쌍투메 프린시페'],
            'SV': ['엘살바도르'],
            'SX': ['신트마르텐'],
            'SY': ['시리아'],
            'SZ': ['스와질랜드'],
            'TC': ['터크스 카이코스 제도'],
            'TD': ['차드'],
            'TF': ['프랑스 남부지역'],
            'TG': ['토고'],
            'TH': ['태국'],
            'TJ': ['타지키스탄'],
            'TK': ['토켈라우'],
            'TL': ['동티모르'],
            'TM': ['투르크메니스탄'],
            'TN': ['튀니지'],
            'TO': ['통가'],
            'TR': ['터키'],
            'TT': ['트리니다드토바고'],
            'TV': ['투발루'],
            'TW': ['대만'],
            'TZ': ['탄자니아'],
            'UA': ['우크라이나'],
            'UG': ['우간다'],
            'UM': ['미국령 소군도'],
            'US': ['미국'],
            'UY': ['우루과이'],
            'UZ': ['우즈베키스탄'],
            'VA': ['바티칸'],
            'VC': ['세인트 빈센트 그레나딘스'],
            'VE': ['베네수엘라'],
            'VG': ['영국령 버진아일랜드'],
            'VI': ['미국령 버진아일랜드'],
            'VN': ['베트남'],
            'VU': ['바누아투'],
            'WF': ['월리스 후트나'],
            'WS': ['사모아'],
            'YE': ['예멘'],
            'YT': ['마요트'],
            'YU': ['유고슬라비아'],
            'ZA': ['남아프리카공화국'],
            'ZM': ['잠비아'],
            'ZR': ['자이르'],
            'ZW': ['짐바브웨'],
            'ZZ': ['국적불명'],
            'none' : ['확인불가'],
            'EU' : ['유럽연합']
            }
    code = DataFrame(raw_code)
    whois_kr = code.at[0, whois]
    return whois_kr

def reputation(event=None):
    j=0
    entry_result_repute.delete(1.0, END)
    import requests
    import json
    platform = platform_combo_repute.get()
    repute_ip = entry_search_repute.get()
    if platform == 'Malware API':
        print("malware OK" + repute_ip)
        url = "https://public.api.malwares.com/v3/ip/info?api_key=6CAD7E5F0B6B45178584894543005C4AD184363CE0E4774ECD87A69488482FD0&host=1&url=3&downfile=3&comfile=3&ip=" + repute_ip
        source = urllib.request.urlopen(url)
        data=source.read()
        j=json.loads(data)
        print(j)
        try:
            ip = j['ip']
        except:
            messagebox.showerror("오류창", "IP를 입력해주세요")
            pass
        a = "#정보 확인을 요청한 IP (String) : {0}\n".format(ip)
        entry_result_repute.insert(END, a)

        #view_count = j['view_count']
        #a = "*IP 조회 카운트 (Number) : {0}\n".format(view_count)
        #entry_result_repute.insert(END, a)
        try:
            location_a = j['location']
            location_b = location_a['cname']
            location_c = location_a['city']
            location = "{0}({1})".format(location_b,location_c)
        except:
            location = "조회 안됨"
        a = "*지역 : {0}\n".format(location)
        entry_result_repute.insert(END, a)
        try:
            hostname_history_a = j['hostname_history']
        except:
            messagebox.showerror("오류창","일시적 오류 재 조회버튼을 눌러주세요")
        hostname_history_b = hostname_history_a['total']
        hostname_history_list = hostname_history_a['list']
        if hostname_history_b ==0:
            hostname_history = "\n-없음\n"
            a = "\n*사용된 호스트 : {0}\n".format(hostname_history)
            entry_result_repute.insert(END, a)
        else:
            hostname_history = " \n-개수:{0}개\n-목록:".format(hostname_history_b)
            a = "\n*사용된 호스트 : {0}\n".format(hostname_history)
            entry_result_repute.insert(END, a)
            count = 0
            for i in hostname_history_list:
                hostname_history_date = hostname_history_list[count]['date']
                hostname_history_hostname = hostname_history_list[count]['hostname']
                hostname_history_c = "등록일 : {0}, 호스트명 : {1}\n".format(hostname_history_date,hostname_history_hostname)
                entry_result_repute.insert(END, hostname_history_c)
                count = count + 1

        detected_url_a = j['detected_url']
        detected_url_b = detected_url_a['total']
        detected_url_list = detected_url_a['list']
        if detected_url_b == 0:
            detected_url = "\n-없음\n"
            a = "\n*사용된 악성 URL : {0}\n".format(detected_url)
            entry_result_repute.insert(END, a)
        else:
            detected_url = " \n-개수:{0}개\n-목록:".format(detected_url_b)
            a = "\n*사용된 악성 URL : {0}\n".format(detected_url)
            entry_result_repute.insert(END, a)
            count = 0
            for i in detected_url_list:
                detected_url_date = detected_url_list[count]['date']
                detected_url_hostname = detected_url_list[count]['url']
                detected_url_c = "등록일 : {0}, URL : {1}\n".format(detected_url_date, detected_url_hostname)
                entry_result_repute.insert(END, detected_url_c)
                count = count + 1

        undetected_url_a = j['undetected_url']
        undetected_url_b = undetected_url_a['total']
        undetected_url_list = undetected_url_a['list']
        if undetected_url_b == 0:
            undetected_url = "\n-없음\n"
            a = "\n*사용된 정상 URL : {0}\n".format(undetected_url)
            entry_result_repute.insert(END, a)
        else:
            undetected_url = " \n-개수:{0}개\n-목록:".format(undetected_url_b)
            a = "\n*사용된 정상 URL : {0}\n".format(undetected_url)
            entry_result_repute.insert(END, a)
            count = 0
            for i in undetected_url_list:
                undetected_url_date = undetected_url_list[count]['date']
                undetected_url_hostname = undetected_url_list[count]['url']
                undetected_url_c = "등록일 : {0}, URL : {1}\n".format(undetected_url_date, undetected_url_hostname)
                entry_result_repute.insert(END, undetected_url_c)
                count = count + 1

        detected_downloaded_file_a = j['detected_downloaded_file']
        detected_downloaded_file_b = detected_downloaded_file_a['total']
        detected_downloaded_file_list = detected_downloaded_file_a['list']
        if detected_downloaded_file_b == 0:
            detected_downloaded_file = "\n-없음\n"
            a = "\n*IP에서 다운로드된 악성 파일 : {0}\n".format(detected_downloaded_file)
            entry_result_repute.insert(END, a)
        else:
            detected_downloaded_file = " \n-개수:{0}개\n-목록:".format(detected_downloaded_file_b)
            a = "\n*IP에서 다운로드된 악성 파일 : {0}\n".format(detected_downloaded_file)
            entry_result_repute.insert(END, a)
            count = 0
            for i in detected_downloaded_file_list:
                detected_downloaded_file_date = detected_downloaded_file_list[count]['date']
                detected_downloaded_file_hostname = detected_downloaded_file_list[count]['sha256']
                detected_downloaded_file_c = "등록일 : {0}\nSHA256 : {1}\n\n".format(detected_downloaded_file_date, detected_downloaded_file_hostname)
                entry_result_repute.insert(END, detected_downloaded_file_c)
                count = count + 1

        undetected_downloaded_file_a = j['undetected_downloaded_file']
        undetected_downloaded_file_b = undetected_downloaded_file_a['total']
        undetected_downloaded_file_list = undetected_downloaded_file_a['list']
        if undetected_downloaded_file_b == 0:
            undetected_downloaded_file = "\n-없음\n"
            a = "\n*IP에서 다운로드된 정상 파일 : {0}\n".format(undetected_downloaded_file)
            entry_result_repute.insert(END, a)
        else:
            undetected_downloaded_file = " \n-개수:{0}개\n-목록:".format(undetected_downloaded_file_b)
            a = "\n*IP에서 다운로드된 정상 파일 : {0}\n".format(undetected_downloaded_file)
            entry_result_repute.insert(END, a)
            count = 0
            for i in undetected_downloaded_file_list:
                undetected_downloaded_file_date = undetected_downloaded_file_list[count]['date']
                undetected_downloaded_file_hostname = undetected_downloaded_file_list[count]['sha256']
                undetected_downloaded_file_c = "등록일 : {0}\nSHA256 : {1}\n\n".format(undetected_downloaded_file_date,undetected_downloaded_file_hostname)
                entry_result_repute.insert(END, undetected_downloaded_file_c)
                count = count + 1

        detected_communicating_file_a = j['detected_communicating_file']
        detected_communicating_file_b = detected_communicating_file_a['total']
        detected_communicating_file_list = detected_communicating_file_a['list']
        if detected_communicating_file_b == 0:
            detected_communicating_file = "\n-없음\n"
            a = "\n*IP와 통신한 악성 파일 : {0}\n".format(detected_communicating_file)
            entry_result_repute.insert(END, a)
        else:
            detected_communicating_file = " \n-개수:{0}개\n-목록:".format(detected_communicating_file_b)
            a = "\n*IP와 통신한 악성 파일 : {0}\n".format(detected_communicating_file)
            entry_result_repute.insert(END, a)
            count = 0
            for i in detected_communicating_file_list:
                detected_communicating_file_date = detected_communicating_file_list[count]['date']
                detected_communicating_file_hostname = detected_communicating_file_list[count]['sha256']
                detected_communicating_file_c = "등록일 : {0}\nSHA256 : {1}\n\n".format(detected_communicating_file_date,detected_communicating_file_hostname)
                entry_result_repute.insert(END, detected_communicating_file_c)
                count = count + 1

        undetected_communicating_file_a = j['undetected_communicating_file']
        undetected_communicating_file_b = undetected_communicating_file_a['total']
        undetected_communicating_file_list = undetected_communicating_file_a['list']
        if undetected_communicating_file_b == 0:
            undetected_communicating_file = "\n-없음\n"
            a = "\n*IP와 통신한 정상 파일 : {0}\n".format(undetected_communicating_file)
            entry_result_repute.insert(END, a)
        else:
            undetected_communicating_file = " \n-개수:{0}개\n-목록:".format(undetected_communicating_file_b)
            a = "\n*IP와 통신한 정상 파일 : {0}\n".format(undetected_communicating_file)
            entry_result_repute.insert(END, a)
            count = 0
            for i in undetected_communicating_file_list:
                undetected_communicating_file_date = undetected_communicating_file_list[count]['date']
                undetected_communicating_file_hostname = undetected_communicating_file_list[count]['sha256']
                undetected_communicating_file_c = "등록일 : {0}\nSHA256 : {1}\n\n".format(
                    undetected_communicating_file_date, undetected_communicating_file_hostname)
                entry_result_repute.insert(END, undetected_communicating_file_c)
                count = count + 1

    elif platform == 'IBM API':
        #1d22c957-3871-4b81-9135-754d0cc28a0d api key
        #3a4cd4a8-6990-4427-a28b-da0fddb27995 api pswd
        url = "https://api.xforce.ibmcloud.com/ipr/" + repute_ip
        print(url)
        hdr = {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Authorization' : 'Basic MWQyMmM5NTctMzg3MS00YjgxLTkxMzUtNzU0ZDBjYzI4YTBkOjNhNGNkNGE4LTY5OTAtNDQyNy1hMjhiLWRhMGZkZGIyNzk5NQ==','Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3', 'Accept-Encoding': 'none', 'Accept-Language': 'ko', 'Connection': 'keep-alive'}
        req = urllib.request.Request(url, headers=hdr)
        print(req)
        data = urllib.request.urlopen(req).read()
        print(data)
        j = json.loads(data)
        #print(j)
        history_inside= j.get('history')
        print("\n")
        a=len(history_inside)-1
        entry_result_repute.insert(END, "조회 건수는 {0}건입니다.\n\n".format(len(history_inside))) #139.199.22.202
        entry_result_repute.insert(END, "-"*50 + "\n\n")
        for i in history_inside:
            cm_hh = history_inside[a]
            cm_h_a = cm_hh['created']
            cm_h_b = cm_hh['reason']
            cm_h_c = cm_hh['ip']
            cm_h_dd = cm_hh['categoryDescriptions']
            cm_h_ee = cm_hh['reasonDescription']
            cm_h_ff = cm_hh['score']
            print(cm_hh)
            cm_hh_valid = cm_hh['cats'] #125.84.179.182

            if '다이나믹 IP' in cm_hh_valid.keys() != False:
                cm_h_d= " 다이나믹 IP \n  = {0}".format(cm_h_dd['다이나믹 IP'])
            elif '보츠' in cm_hh_valid.keys() != False:
                cm_h_d = " Bots \n  = {0}".format(cm_h_dd['보츠'])
            elif '스팸' in cm_hh_valid.keys() != False:
                cm_h_d = " 스팸 \n  = {0}".format(cm_h_dd['스팸'])
            elif '익명화 서비스' in cm_hh_valid.keys() != False:
                cm_h_d = " 익명화 서비스 \n  = {0}".format(cm_h_dd['익명화 서비스'])
            elif '악성\xa0소프트웨어' in cm_hh_valid.keys() != False:
                cm_h_d = " 악성 소프트웨어 \n  = {0}".format(cm_h_dd['악성\xa0소프트웨어'])
            elif '스캐닝 IP' in cm_hh_valid.keys() != False:
                cm_h_d = " 스캐닝 IP \n  = {0}".format(cm_h_dd['스캐닝 IP'])
            else:
                try:
                    abc = cm_hh['malware_extended']
                    abcd = abc['BotNet']
                    abcde = abc['CC']
                    cm_h_d = "봇넷명({0}/{1})".format(abcd,abcde)
                except:
                    cm_h_d = "없음"
            entry_result_repute.insert(END, "1.등록일 : {0}\n2.근거 : {1}\n3.IP대역 : {2}\n4.카테고리 : {3}\n5.사유 : \n  - {4}\n6.점수 : {5}\n\n".format(cm_h_a, cm_h_b, cm_h_c, cm_h_d, cm_h_ee, cm_h_ff))
            a=a-1
            entry_result_repute.insert(END, "-"*50 + "\n\n")

#class sensitive_search:
count = 0
minus_count = 0
minus_count = 0
email_result = []
IDnum_result = []
ph_num_result = []
passport_num_result = []

def search(target, pages):  # 페이지 함수에서 실행됨 = 검색어 관련 모든 URL 크롤링

    base_url = 'https://www.google.co.kr/search'
    #: 검색조건 설정
    values = {'q': target,  # 검색할 내용
              'oq': target,
              'aqs': 'chrome..69i57.35694j0j7',
              'sourceid': 'chrome',
              'ie': 'UTF-8'
              }
    # Google에서는 Header 설정 필요
    hdr = {'User-Agent': 'Mozilla/5.0'}
    query_string = urllib.parse.urlencode(values)
    param = {'start': pages}
    params = urllib.parse.urlencode(param)
    print("검색중인 페이지: {0}\n".format(pages/10))
    entry_result_sensitive.insert(END,"검색중인 페이지: {0}\n".format(pages/10))
    req = urllib.request.Request(base_url + '?' + query_string + '&' + params, headers=hdr)
    context = ssl._create_unverified_context()
    try:
        res = urllib.request.urlopen(req, context=context)
    except:
        traceback.print_exc()
    html_data = BeautifulSoup(res.read(), 'html.parser')
    # print(html_data)
    global count
    for datas in html_data.find_all('a', href=re.compile("^(/url?)+")):
        if 'href' in datas.attrs:
            result = datas.attrs['href']
            google = "https://google.co.kr" + result
            print(google)
            entry_result_sensitive.insert(END,"{0}\n".format(google))
            crawling(google)
            count = count + 1
def email(bsObj):
    domain = entry_sensitive_email_format.get()
    email = re.compile(r'''(
        ([a-zA-Z0-9._%+-]+)      # 사용자명
        @                        # @
        {0}        # 최상위 도메인
        )'''.format(domain), re.VERBOSE)
    result = email.findall(bsObj)
    abcd = result == []
    if abcd is True:
        print("Email 확인 x")
        entry_result_sensitive.insert(END,"Email 확인 x\n")
    else:
        print(result)
        entry_result_sensitive.insert(END, "{}\n".format(result))
        global email_result
        email_result = email_result + result

def IDnum(bsObj):
    IDnum = re.compile('(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1,2][0-9]|3[0,1]))\s?-\s?[1-4][0-9]{6}')
    result = IDnum.findall(bsObj)
    abcd = result == []
    if abcd is True:
        print("주민번호 확인 x")
        entry_result_sensitive.insert(END,"주민번호 확인 x\n")
    else:
        print(result)
        entry_result_sensitive.insert(END, "{}\n".format(result))
        global IDnum_result
        IDnum_result = IDnum_result + result

def ph_num(bsObj):
    ph_num = re.compile('((01[016789]{1}|02|0[3-9]{1}[0-9]{1})-[0-9]{3,4}-[0-9]{4})')
    result = ph_num.findall(bsObj)
    abcd = result == []
    if abcd is True:
        print("전화번호 확인 x")
        entry_result_sensitive.insert(END,"전화번호 확인 x\n")
    else:
        print(result)
        try:
            entry_result_sensitive.insert(END, "{}\n".format(result))
        except:
            print("이거냐제발")
        global ph_num_result
        ph_num_result = ph_num_result + result
'''
def passport_num(bsObj):
    passport_num = re.compile('([m|s|r|o|d|M|S|R|O|D|g|G]{1}\d{8}|[a-zA-Z]{2}\d{7})')
    result = passport_num.findall(bsObj)
    abcd = result == []
    if abcd is True:
        print("여권번호 확인 x")
        entry_result_sensitive.insert(END,"여권번호 확인 x\n")
    else:
        print(result)
        entry_result_sensitive.insert(END,"{0}\n".format(result))
        global passport_num_result
        passport_num_result = passport_num_result + result
'''
def crawling(url):
    from urllib.error import HTTPError, URLError
    hdr = {'User-Agent': 'Mozilla/5.0'}
    try:
        req = urllib.request.Request(url, headers=hdr)
        context = ssl._create_unverified_context()
        res = urllib.request.urlopen(req, context=context)
        bsObj = BeautifulSoup(res.read(), "html.parser")
        bsObj = "{0}".format(bsObj)
        email(bsObj)
        IDnum(bsObj)
        ph_num(bsObj)
        #passport_num(bsObj)
    except (HTTPError, AttributeError, TypeError, URLError) as e:
        print("오류:{0}".format(e))
        entry_result_sensitive.insert(END, "오류:{0}\n".format(e))
        global minus_count
        minus_count = minus_count + 1

def pages(event=None):  # 검색할 페이지 수
    entry_result_sensitive.delete(1.0, END)
    target = entry_sensitive_search.get()
    number = int(pages_combo_sensitive.get())
    print(number)
    pages = (number + 1) * 10
    count_to_pages = 10
    while count_to_pages < pages:
        search(target, count_to_pages)
        print(count_to_pages)
        count_to_pages = count_to_pages + 10
    print("확인된 URL의 수는 {0}이며, 오류를 제외한 수는 {1}입니다.".format(count, count - minus_count))
    entry_result_sensitive.insert(END, "확인된 URL의 수는 {0}이며, 오류를 제외한 수는 {1}입니다.".format(count, count - minus_count))
    email_result_plus = email_result == []
    IDnum_result_plus = IDnum_result == []
    ph_num_result_plus = ph_num_result == []
    passport_num_result_plus = passport_num_result == []
    if email_result_plus is True:
        print("검색된 메일 주소가 없습니다.")
        entry_result_sensitive.insert(END, "검색된 메일 주소가 없습니다.\n")
    else:
        print("검색된 메일 주소는 {0}입니다.".format(email_result))
        entry_result_sensitive.insert(END, "검색된 메일 주소는 {0}입니다.\n".format(email_result))
    if IDnum_result_plus is True:
        print("검색된 주민번호가 없습니다.")
        entry_result_sensitive.insert(END, "검색된 주민번호가 없습니다.\n")
    else:
        print("검색된 주민번호는 {0}입니다.".format(IDnum_result))
        entry_result_sensitive.insert(END, "검색된 주민번호는 {0}입니다.\n".format(IDnum_result))
    if ph_num_result_plus is True:
        print("검색된 전화번호가 없습니다.")
        entry_result_sensitive.insert(END, "검색된 전화번호가 없습니다.\n")
    else:
        print("검색된 전화번호는 {0}입니다.".format(ph_num_result))
        entry_result_sensitive.insert(END, "검색된 전화번호는 {0}입니다.\n".format(ph_num_result))
    '''
    if passport_num_result_plus is True:
        print("검색된 여권번호가 없습니다.")
        entry_result_sensitive.insert(END, "검색된 여권번호가 없습니다\n.")
    else:
        print("검색된 여권번호는 {0}입니다.".format(passport_num_result))
        entry_result_sensitive.insert(END, "검색된 여권번호는 {0}입니다.\n".format(passport_num_result))
    '''

###윈도우 창

win = Tk()
win.title("통합 보안관제 유틸 프로그램 ver 5.0")
win.geometry('670x420+400+400')

notebook=ttk.Notebook(win, width=600, height=420)
notebook.pack(fill='both', expand=TRUE)

#첫번째 탭 내용 작성은 여기로
frame_tab_page1=Frame(win)
notebook.add(frame_tab_page1, text="Snort Rule Search")

label1=Label(frame_tab_page1, text="검색어 : ")
label2=Label(frame_tab_page1, text="결과값 : ")
label1.grid(column=0, row=0, sticky="ew")
label2.grid(column=0, row=3, sticky=E+W)

frame_search = Frame(frame_tab_page1, borderwidth=0, relief='ridge', width=1, bd=1)
frame_search.grid(column=1, row=0, columnspan=1, sticky="news")
entry_search = Entry(frame_search)
entry_search.pack(fill='x', side="bottom")

search_action = Button(frame_tab_page1, text='검색' ,command=lambda: process (target = search).start (), bg='white')
search_action.grid(column=2, row=0, columnspan=1,sticky="news")
#search_action.bind("<Return>",search_action)

result_test = StringVar()
entry_result = Text(frame_tab_page1)
entry_result.grid(column=1, row=3)
entry_result.insert(1.1,"처음 사용하실 경우 업데이트를 하신 후에 검색을 해주세요\n신규 패턴이 업로드될 수 있으므로 검색이 필요할 시 주기적 업데이트를 권장드립니다.\n ex) CVE코드, 패턴, port 등")

import threading ##멀티 스레드를 통한 프로그램 응답 없음 현상 제거
task1 = threading.Thread(target=update)
action = Button(frame_tab_page1, text='업데이트', command=task1.start, bg='white')
action.grid(column=1, row=9, sticky=N+W+E+S, pady=10)

entry_search.bind('<Return>', search)

#두번째 탭 내용 작성은 여기로

frame_tab_page2=Frame(win)
notebook.add(frame_tab_page2, text="Whois IP 국가 조회")

from tkinter import Text
label2=Label(frame_tab_page2, text="IP 입력").grid(column=0, row=0, sticky="n")
label2=Label(frame_tab_page2, text="IP 결과").grid(column=1, row=0, sticky="n")

text1=Text(frame_tab_page2, width=47)
text1.grid(column=0,row=1)
text1.bind('<Return>', trans)

text2=Text(frame_tab_page2, width=47)
text2.grid(column=1,row=1)
text2.insert(1.0, "예시) 왼쪽 입력 란 양식 \n1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n")

trans_button = Button(frame_tab_page2, text="조회" ,command=lambda: process (target = trans).start (), bg='white')
trans_button.grid(column=0, row=2, columnspan=2, sticky="news", pady=20)

#세번째 탭 내용 작성은 여기로

frame_tab_page3=Frame(win)
notebook.add(frame_tab_page3, text="도메인 조회기")

label3=Label(frame_tab_page3, text="도메인 입력").grid(column=0, row=0, sticky="n")
label3_1=Label(frame_tab_page3, text="IP 결과").grid(column=1, row=0, sticky="n")

text3_1=Text(frame_tab_page3, width=47)
text3_1.grid(column=0,row=1)
text3_1.bind('<Return>', rawdomains)


text3_2=Text(frame_tab_page3, width=47)
text3_2.grid(column=1,row=1)
text3_2.insert(1.0, "아래의 예시와 같이 통째로 긁어와서 조회하시면 됩니다. \n\n유의사항 : \nIP형태의 도메인은 인식이 되지 않습니다. \n\nex)\n109119	2019-11-01	악성코드 유포준비단계 (추정)	hxxps://lymingyang.cn/a/xingyexinwen/2015/0930/1.html\n109118	2019-10-31	모바일 악성앱	hxxp://xiazai1.05sun.com/crack/LoveMsg.apk\n109117	2019-10-31	모바일 악성앱	hxxp://ftp-new-apk.pconline.com.cn:8080/1eb3f56c64ffef87d87553ee3c949822/pub/download/201807/pconline1531205464878.apk\n109116	2019-10-31	모바일 악성앱	hxxp://app2.paopaoche.net/app4/shoujidianboquwen.apk\n109113	2019-10-31	모바일 악성앱	hxxp://down.sj.2144.cn/sj/20130822/game/201308221248027370.apk\n109111	2019-10-31	기타 악성코드	hxxp://23.95.200.195/app/app.exe\n")

text3_csv=Text(frame_tab_page3, width=0)
text3_csv_to=Text(frame_tab_page3, width=0)

trans_doma = Button(frame_tab_page3,text="조회" ,command=lambda: process (target = rawdomains).start (), bg='white')
trans_doma.grid(column=0, row=2, columnspan = 2, sticky="news")
trans_csv_export = Button(frame_tab_page3, text="csv저장", command=export_csv, bg='white').grid(column=0, row=3, columnspan=1, sticky="news")
trans_csv_to = Button(frame_tab_page3, text="csv저장(전달)", command=export_csv_to, bg='white').grid(column=1, row=3, columnspan=1, sticky="news")

#네번째 탭 내용 작성은 여기로

frame_tab_page4=Frame(win)
notebook.add(frame_tab_page4, text="IP 이력 및 평판 조회")

label4=Label(frame_tab_page4, text="검색어 : ")
label4_1=Label(frame_tab_page4, text="결과값 : ")
label4.grid(column=0, row=0, sticky="ew")
label4_1.grid(column=0, row=3, sticky=E+W)

frame_search_repute = Frame(frame_tab_page4, borderwidth=0, relief='ridge', width=100, bd=1)
frame_search_repute.grid(column=2, row=0,  sticky="we")
entry_search_repute = Entry(frame_search_repute)
entry_search_repute.pack(fill='x', side="bottom")#, pady=10)

result_test = StringVar()
entry_result_repute = Text(frame_tab_page4)
entry_result_repute.grid(column=1, row=3, columnspan=2)
entry_result_repute.insert(1.1,"검색란에 IP를 입력해주세요\n\nMalware API = IP와 관련된 도메인, 파일 다운로드 이력 조회\nIBM API = IP 평판 조회")

str = StringVar()
platform_combo_repute = ttk.Combobox(frame_tab_page4, width=10, textvariable=str, takefocus=NO)
platform_combo_repute['values'] = ("Malware API", "IBM API")
platform_combo_repute.grid(column=1, row=0, sticky=W+E, pady=10)
platform_combo_repute.current(0)
platform_combo_repute.bind('<Return>', reputation)

search_action = Button(frame_tab_page4, text='검색', bg='white', command=reputation)
search_action.grid(column=3, row=0, columnspan=1,sticky="news")
entry_search_repute.bind('<Return>', reputation)

#다섯번째 탬 내용 작성은 여기로
frame_tab_page5=Frame(win)
notebook.add(frame_tab_page5, text="개인정보 크롤링")

label5=Label(frame_tab_page5, text="검색어 : ")
label5_1=Label(frame_tab_page5, text="결과값 : ")
label5.grid(column=0, row=0, sticky="ew")
label5_1.grid(column=0, row=3, sticky=E+W)

str = StringVar()
pages_combo_sensitive = ttk.Combobox(frame_tab_page5, width=10, textvariable=str, takefocus=NO)
pages_combo_sensitive['values'] = ("검색할 페이지 수 입력", "10")
pages_combo_sensitive.grid(column=1, row=0, sticky=W+E, pady=10)
pages_combo_sensitive.current(0)
pages_combo_sensitive.bind('<Return>', pages)

frame_sensitive_email_format = Frame(frame_tab_page5, borderwidth=0, relief='ridge', width=100, bd=1)
frame_sensitive_email_format.grid(column=2, row=0,  sticky="we")
entry_sensitive_email_format = Entry(frame_sensitive_email_format)
entry_sensitive_email_format.pack(fill='x', side="bottom")#, pady=10)

frame_sensitive_search = Frame(frame_tab_page5, borderwidth=0, relief='ridge', width=100, bd=1)
frame_sensitive_search.grid(column=3, row=0,  sticky="we")
entry_sensitive_search = Entry(frame_sensitive_search)
entry_sensitive_search.pack(fill='x', side="bottom")#, pady=10)

result_test = StringVar()
entry_result_sensitive = Text(frame_tab_page5)
entry_result_sensitive.grid(column=1, row=3, columnspan=3)
entry_result_sensitive.insert(1.1,"개선 작업 중\n 첫번째 항목 : 검색할 페이지 수, \n 두번째 항목 : 이메일 형식 ex)naver.com\n 세번째 항목 : 검색어")





search_action = Button(frame_tab_page5, text='검색', bg='white', command=lambda: process (target = pages).start ())
search_action.grid(column=4, row=0, columnspan=1,sticky="news")
entry_search_repute.bind('<Return>', pages)


#여섯번째 탬 내용 작성은 여기로
frame_tab_page6=Frame(win)
notebook.add(frame_tab_page6, text="기타")

label5=Label(frame_tab_page6, text="추가기능 및 오류 : soocheol.chung@ahnlab.com\n csc04160@naver.com")
label5.pack()
rnote_subject = Label(frame_tab_page6, text = "#업데이트 내역").pack()

rnote = Text(frame_tab_page6, bg='grey95')
rnote.pack()
rnote.insert(1.0, '-20191130 v5.0 : 구글 크롤링 개인정보 검색기 구현, GUI 개선 작업 중\n-191128 v4.9.1 : IBM API 403 Error 리턴 되는 현상 해결\n-191127 v4.9 : nslookup timed out 발생시 자동 재조회 기능 추가\n\t 용량 90%감소, 현재 IBM API 403 응답문제로 해결 중\n-191109 v4.8 : IP로 된 도메인도 엑셀 출력 파싱 (오류발생가능있음)\n-191104_v4.7 : 쓰레드 문제 해결로 실시간 재조회 가능\n-191102_v4.6 : 도메인 조회 탭 DNS Query 속도 대폭 향상 및 서버오류로 멈춤 현상 제거\n-191031_v4.5 : 새로운 악성코드 양식에 따라 csv조회(전달용) 추가\n-191028_v4.4 : 정규식으로 IP형태 도메인 표기, csv 출력 결과 변경\n-191024_v4.3 : 악성코드 유포지 메일 발송에 따라 출력 형태 변경\n-191011_v4.2 : Enter 키 누를 시 조회가 되는 기능 추가\n-191008_v4.1 : 악성코드 도메인 csv Export와 재조회 가능한 버튼 구현')

win.mainloop()