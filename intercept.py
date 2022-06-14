#MITM proxy imports to use their Python API.
from stat import S_ENFMT
from mitmproxy import http 
from mitmproxy import ctx
from mitmproxy.net.http.http1.assemble import assemble_request
from mitmproxy.net.http import status_codes
#Import to implement a case insensitive dictionary
from requests.structures import CaseInsensitiveDict
#json import to write json objects to the requests.json file
import json
import re

#First function is called, taking the flow object of the proxy as an argument
def request(flow: http.HTTPFlow):
    full_request = ""
    #This try and except statement attempts to assemble the request currently being looked at, into a readable format. UTF-8 format to be exact
    try:
        full_request = assemble_request(flow.request).decode('utf-8')
    except:
        print("error while trying to assemble request")

    #This is the shutdown check. When the user stops the interception (in the main GUI, located in the IDOR_detection file)
    #it will use curl to send a HTTP request through the proxy to this fabricated address. The only scenario the flow would 
    #encounter this address is if the user presses the stop button for the interception. If this happens, the flow is shutdown with
    #ctx.master.shutdown()
    if(flow.request.url == "http://www.madeupsite45945.com/"):
        ctx.master.shutdown()

    #Next function is called to check if the request contains cookies, passing with it the flow object and the full current request.
    retrieve_cookies(flow, full_request)
    
def retrieve_cookies(flow: http.HTTPFlow, full_request):
    request_cookies = CaseInsensitiveDict()
    concat_cookies = ""

    #Loop through request to create list of all cookies (this is if the cookies are formatted as different cookies rather than a list
    #under one cookie)
    for line in full_request.splitlines():
        if line.startswith('Cookie'):
            line = line[8:]
            concat_cookies = concat_cookies + line

        if line.startswith('cookie'):
            line = line[8:]   
            if concat_cookies == "":    
                concat_cookies = concat_cookies + line  
            else:
                concat_cookies = concat_cookies + ";" + line
    
    request_cookies["Cookie"] = concat_cookies

    #If the cookie field in the dictionary exists, then the last function to store the request is called.
    if request_cookies["Cookie"]: 
        store_requests(flow)

#This function is where to storage of the requests is done.
def store_requests(flow):
    #creates a dictionary of all the headers in the request
    d = dict(flow.request.headers.items())
    
    #open the requests.json file and opens the list object so the new request can be added to it
    with open('requests.json') as fp:
        listObj = json.load(fp)

    #Here all the necessary information a request needs it assigned their respective value from the request.
    method = str(flow.request.method)
    url = str(flow.request.url)
    #This decoding is needed because the content is initially in an unreadable byte format
    content_old = (flow.request.content).decode("utf-8")
    content = str(content_old)
    headers = d

    #This is the filter list, any request URL containing any of these file extensions or phrases will be discarded 
    #and not appeneded to the requests file
    filter = re.compile('\.js|css|png|jpeg|gif|socket|woff|map|bmp|ico$|jpg')

    #If the url contains any filtered material it will be discarded and not added
    if filter.search(url):
        print("request filtered, most likely not an endpoint")
    #if passes the filter, then the list object of all the existing json objects is appended to with the variables declared above
    else:
        listObj.append({
            "http_method":method,
            "url":url,
            "headers":headers,
            "content":content
        })  

    #Now that the list object contains the new request, it is written to the requests file to save it. 
    #an indent of 4 and separators are used for readability if the user wants to examine the requests in more detail
    with open('requests.json', 'w') as json_file:
        json.dump(listObj, json_file,
        indent=4,
        separators=(',',': '))
    pass   


#initialising the script to begin the request capture/interception
if __name__ == '__main__':
    request()