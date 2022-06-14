#Tkinter imports as this is the basis of the GUI 
import tkinter as tk
from tkinter import ttk
from select import select
from tkinter import *
from tkinter import ttk  
from tkinter import messagebox
from random import randint
#Threading needed to run the interception and request forwarding
#without the tool hanging or crashing/freezing
import threading
#OS import needed to run system commands from this python script
import os
#Subprocess needed for the same reason threading is needed
import subprocess
#JSON import for the requests.json file to be read/dumped
import json
from markupsafe import re
#requests needed as it is the library of choice to make the original and modified HTTP requests
import requests

#App class, the whole tool
class App:
    #This serves as the constructor for the application and its GUI components
    #Within this every TKinter component attribute is initialised and the main loop for the Tkinter window is started
    def __init__(self):
        #Instantiate the TKinter window and add relevant titles, dimensions, and colours.
        self.root = tk.Tk()
        self.root.title("IDOR Hunter")
        self.root['bg'] = '#45b3e0'
        width, height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry('%dx%d+0+0' % (width, height))
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview", background="#45b3e0", 
        fieldbackground="#45b3e0", foreground="#45b3e0")

        #Add scrollbars to each axis (if there are a lot of requests) and pack them to an axis
        scroll = Scrollbar(self.root)
        scrollH = Scrollbar(self.root)
        scroll.pack(side = RIGHT, fill = Y)
        scrollH.pack(side = BOTTOM, fill = X)

        #Create our table to contain the intercepted requests, including its columns.
        #Also add the scrollbars already defined.
        self.requestTable = ttk.Treeview(self.root, yscrollcommand=scroll.set, xscrollcommand=scrollH, selectmode="extended")
        self.requestTable['columns'] = ('Request ID', 'Transfer Method', 'URL', 'Headers', 'Bypassed?')

        #Format the columns that were just created. Anchoring them all to the WEST
        self.requestTable.column("#0", width=0, stretch=NO)
        self.requestTable.column("Request ID",anchor=W, width=70)
        self.requestTable.column("Transfer Method",anchor=W,width=100)
        self.requestTable.column("URL",anchor=W,width=430)
        self.requestTable.column("Headers",anchor=W,width=430)
        self.requestTable.column("Bypassed?",anchor=W,width=70)

        #Create Headings for the columns, also anchoring to the WEST
        self.requestTable.heading("#0",text="",anchor=W)
        self.requestTable.heading("Request ID",text="Request ID",anchor=W)
        self.requestTable.heading("Transfer Method",text="Transfer Method",anchor=W)
        self.requestTable.heading("URL",text="URL",anchor=W)
        self.requestTable.heading("Headers",text="Headers",anchor=W)
        self.requestTable.heading("Bypassed?",text="Bypassed?",anchor=W)

        #Define the tables onClick event handler. This is for when a user doubleclicks a
        #request record to examine it further. When doubleclicked, it will run the OnDoubleClick method.
        self.requestTable.bind("<Double-1>", self.OnDoubleClick)
        
        #Pack table
        self.requestTable.pack(side = RIGHT, fill = BOTH)

        #Create main labels and buttons. All dimensions and colours of all labels and buttons
        #Is done here.
        self.welcomeLabel = Label(bg="white", width=17, text = "IDOR Hunter")
        self.welcomeLabel.pack(pady=5)
        #Help button when pressed will run the instructionManual method
        self.helpButton = Button(bg="white", width=6, text = "Help", command = self.instructionManual)
        self.helpButton.pack(pady=10)
        #Start interception button will run the clearJson method when pressed, this time 
        #it will also start a thread because it may run for some time. And allows this to happen
        #without the tool crashing
        self.interceptButton = Button(bg="white", width=17, justify = LEFT, text = "Start request\ninterception", command = threading.Thread(target=self.clearJson).start)
        self.interceptButton.pack(pady=5)
        #Similarly to the start button, the stop button also starts a thread and points to 
        #the stop_intercept method. This is because the stop button also instatiates the request forwading 
        #methods (which also may take some time, so benefit from a thread).
        self.stopButton = Button(bg="white",text = "Stop interception", width=17, command = threading.Thread(target=self.stop_intercept).start)
        self.stopButton.pack(pady=5)
        self.randomLabel = Label(bg="white", width=17, text="Enter low priv\n cookies below")
        self.randomLabel.pack(pady=5)
        #Cookie/Header entry field attribute created.
        self.cookies = Text(width = 15, height=30)
        self.cookies.pack(pady=10)

        #Begin the main window loop now that all attributes of the class have been initialised.
        self.root.mainloop()

    #Instruction manual method to create a pop-up of how to use the tool when the user presses the help button.
    def instructionManual(self):
        messagebox.showinfo("Instruction manual - IDOR detection", 
        "Enter the Cookies or Authorisation headers to be replaced in the text box provided on the left.\n\nPlease provide the headers in the following format:\n{'Cookie':'value','Authorisation':'value'} and so on.\n\nIf using the headers of a low privileged user, start the interception and navigate the API as a high privileged user.\n\nThis tool can also be used to test for authentication vulnerabilities by leaving the text entry blank. This will test each endpoint with empty 'Cookie' and 'Authorisation' values, if present.\n\nWhen you wish to end the interception and display the results, simply press the stop button and wait a few seconds for the requests to populate the central table.\n\nTo look at a request in detail, simply double click the record where you can view the original response and request compared to its modified counterpart.\n\nYES means both responses were equal, NO means they were different, and ??? means it was unclear due to the headers entered not being present in the original request.")
        
    #First method called once the user presses start. Deals with clearing the existing requests file. 
    #So that the new request interception session can take place. Populates the file with one empty entry
    #So the format is clear to the tool.
    def clearJson(self):
        data = [
            {
                "http_method":"",
                "url":"",
                "headers":{},
                "content":""
            }
        ]
        with open('requests.json', 'w') as f:
            json.dump(data, f)
        
        #Pulls user-entered cookies/headers
        cookies = str(self.cookies.get("1.0", END)).strip()

        #Set the flag depending on if cookie entry field is empty or not
        if cookies == '':
            flag = False
        else:
            flag = True
        #if it's not empty, then warn the user the tool will now be testing for authentication vulnerabilities instead
        #of replacing the cookies/authorisation content and testing for authorisation vulnerabilities.
        if not flag:
            messagebox.showinfo("Empty headers", "Warning, you have not entered any Cookies/Headers for this interception so the forwarded requests will be made with empty 'Cookie' and 'Authorisation' headers (if present).")
        else:
            pass

        #Calls the intercept method.
        self.intercept()

    #This begins the request by creating a subprocess and running an OS.system command
    #this command is running the intercept python script but telling the terminal that it is 
    #a mitm proxy command and should listen on localhost. The -q is quiet, so there is no terminal 
    #output, and the -s means it is transparent. This will run until the user decides to stop the interception
    def intercept(self):
        global x
        x = subprocess.check_output('mitmdump -s intercept.py --listen-host 127.0.0.1 -q')

    #This method is called when the user presses the stop interception button. 
    #It throws a terminal curl HTTP request to a fabricated URL. In the proxy flow in intercept.py, this URL
    #is checked for in each request, if it is found the proxy shutsdown since this curl request puts the URL
    #in the proxy flow. This is a very hacky workaround, I just had a lot of trouble trying to get the mitm
    #command to stop on command, this was the only working solution I came up with. But it works! 
    #Once the proxy is stopped, the displayRequests method is called.
    def stop_intercept(self):
        os.system('curl --proxy localhost:8080 www.madeupsite45945.com')
        self.displayRequests()

    #This is the most important method, where all the modified requests are created. 
    def displayRequests(self):
        #Opens the requests.json file, now containing all the requests  of interest.
        #loads them into the list object.
        with open('requests.json') as fp:
            listObj = json.load(fp)

        #This is so each request can have a unique and referrable ID to display with it in the table view.
        id_counter = 0

        #Get input headers entered by user, if there. If not, set to empty.
        try:
            input_headers = json.loads(self.cookies.get("1.0", END))
        except:
            input_headers = {}

        #instantiate a global array to hold a dictionary. Dictionary will contain the original and modified requests
        #and responses.
        global ogArr
        ogArr = []

        #Main FOR loop to loop through each request found in the requests.json file. This is repeated for each type of HTTP request
        #(GET, POST, DELTE, and PATCH). So only the first is commented. The rest are relatively identical. 
        for object in listObj:
            #enumerate counter ID
            id_counter += 1

            #Pulls the relevant details needed to make a request from the request object in question
            method = object['http_method']
            url = object['url']
            if object['headers'] != "":
                headers_dict = object['headers']
            else:
                headers_dict = {} 
            content = object['content']

            original_response = ""
            replaced_response = ""

            newDict = headers_dict.copy()
            
            #If the request method is GET
            if method == "GET":
                try:
                    #x is the original request, it is using the original request parameters/details just pulled from the file itself.
                    x = requests.get(url, headers=headers_dict, timeout=1)
                    original_request = (method, url, headers_dict, content)
                    #the content of the response is assigned here, for later comparison
                    original_response = x.content

                    #This is a check that will be used to see if the cookies the user has entered are actually present in the
                    #request currently in the loop.
                    presentCheck = False

                    #if the user entered headers are present in the dictionary of the actual request headers,
                    #then replace the value of the OG header with the user entered one. If it isn't present
                    #then an accurate test can not be made, so the present flag is changed which will be reflected
                    #in the bypassed section.
                    if input_headers:
                        for x in input_headers.keys():
                            if x in headers_dict.keys():
                                newDict[x] = input_headers[x]
                            else:
                                presentCheck = True
                                print("one of the entered headers was not present")
                    #If the user has not entered any headers, then it will test for authentication vulnerabilities by 
                    #removing the values of any authorisation or cookie headers.
                    else:
                        newDict['Authorization'] = ""
                        newDict['authorization'] = ""
                        newDict['Cookie'] = ""
                        newDict['cookie'] = ""
                        
                    # y is the modified request. Since newDict will now either contain the user entered headers, or the 
                    #same original headers but with empty cookie/authorisation values, it can be sent off. URL obviously stays the same
                    y = requests.get(url, headers=newDict, timeout=1)
                    replaced_request = (method, url, newDict, content)
                    #Content of the response is assigned to a variable for future comparison
                    replaced_response = y.content

                    #This appends the request ID, it's original request and response, and it's modified request and response as a dictionary to the list ogArr.
                    #This is so the user can double-click a record and view the content in more detail, not just whether it has bypassed the authorisation or not.
                    ogArr.append({'id':id_counter, 'original_response':original_response, 'replaced_response':replaced_response, 'original_request':original_request, 'replaced_request':replaced_request})

                    #This IF and ELSE is assigning a value to the 'bypassed' column of the table view. There are three scenarios. 
                    #The stringified responses from both requests were perfectly equal - YES, bypassed. the responses were not perfectly
                    #equal - NO, not bypassed. Or unclear because the user-entered headers were not present in the request.
                    if presentCheck == False:
                        if original_response == replaced_response:
                            bypassed = "YES"
                        else:
                            bypassed = "NO"
                    else: 
                        bypassed = "???"

                    #Inserts the requests' separate parameters into their relevant table values.
                    self.requestTable.insert(parent='', index='end', iid=id_counter, text='',
                    values=(id_counter, method, url, headers_dict, bypassed))
                except:
                    print("Timed out")
            #If HTTP method is POST
            if method == "POST":
                try:
                    x = requests.post(url, headers=headers_dict, data=content, timeout=1)
                    original_request = (method, url, headers_dict, content)
                    original_response = x.content

                    presentCheck = False

                    if input_headers:
                        for x in input_headers.keys():
                            if x in headers_dict.keys():
                                newDict[x] = input_headers[x]
                            else:
                                presentCheck = True
                                print("this headers was not present")
                    else:
                        newDict['Authorization'] = ""
                        newDict['authorization'] = ""
                        newDict['Cookie'] = ""
                        newDict['cookie'] = ""

                    y = requests.post(url, headers=newDict, data=content, timeout=1)
                    replaced_request = (method, url, newDict, content)
                    replaced_response = y.content

                    ogArr.append({'id':id_counter, 'original_response':original_response, 'replaced_response':replaced_response, 'original_request':original_request, 'replaced_request':replaced_request})

                    if presentCheck == False:
                        if original_response == replaced_response:
                            bypassed = "YES"
                        else:
                            bypassed = "NO"
                    else: 
                        bypassed = "???"

                    self.requestTable.insert(parent='', index='end', iid=id_counter, text='',
                    values=(id_counter, method, url, headers_dict, bypassed))
                except:
                    print("Timed out")
            #If HTTP method is PATCH
            if method == "PATCH":
                try:
                    x = requests.patch(url, headers=headers_dict, data=content, timeout=1)
                    original_request = (method, url, headers_dict, content)
                    original_response = x.content
                                        
                    presentCheck = False

                    if input_headers:
                        for x in input_headers.keys():
                            if x in headers_dict.keys():
                                newDict[x] = input_headers[x]
                            else:
                                presentCheck = True
                                print("this headers was not present")
                    else:
                        newDict['Authorization'] = ""
                        newDict['authorization'] = ""
                        newDict['Cookie'] = ""
                        newDict['cookie'] = ""                

                    y = requests.patch(url, headers=newDict, data=content, timeout=1)
                    replaced_request = (method, url, newDict, content)
                    replaced_response = y.content

                    ogArr.append({'id':id_counter, 'original_response':original_response, 'replaced_response':replaced_response, 'original_request':original_request, 'replaced_request':replaced_request})

                    if presentCheck == False:
                        if original_response == replaced_response:
                            bypassed = "YES"
                        else:
                            bypassed = "NO"
                    else: 
                        bypassed = "???"

                    print(original_response)
                    print(replaced_response)

                    self.requestTable.insert(parent='', index='end', iid=id_counter, text='',
                    values=(id_counter, method, url, headers_dict, bypassed))
                except:
                    print("Timed out")
            #If HTTP method is DELETE
            if method == "DELETE":
                try:
                    x = requests.delete(url, headers=headers_dict, data=content, timeout=1)
                    original_request = (method, url, headers_dict, content)
                    original_response = x.content

                    presentCheck = False

                    if input_headers:
                        for x in input_headers.keys():
                            if x in headers_dict.keys():
                                newDict[x] = input_headers[x]
                            else:
                                presentCheck = True
                                print("this headers was not present")
                    else:
                        newDict['Authorization'] = ""
                        newDict['authorization'] = ""
                        newDict['Cookie'] = ""
                        newDict['cookie'] = ""

                    y = requests.delete(url, headers=newDict, data=content, timeout=1)
                    replaced_request = (method, url, newDict, content)
                    replaced_response = y.content

                    ogArr.append({'id':id_counter, 'original_response':original_response, 'replaced_response':replaced_response, 'original_request':original_request, 'replaced_request':replaced_request})
                    
                    if presentCheck == False:
                        if original_response == replaced_response:
                            bypassed = "YES"
                        else:
                            bypassed = "NO"
                    else: 
                        bypassed = "???"

                    print(original_response)
                    print(replaced_response)

                    self.requestTable.insert(parent='', index='end', iid=id_counter, text='',
                    values=(id_counter, method, url, headers_dict, bypassed))
                except:
                    print("Timed out")
        #Final pop-up to tell the user all of the requests that were captured by the proxy during there session have now been checked.
        messagebox.showinfo("Finished", "All results complete.\n\nIf there are requests missing that you may have expected, they may have been discarded by our filtering system. To alter the filtering system please refer to the interception config file.")


    #Method called when the user double-clicks a request from the table view results.
    def OnDoubleClick(self, event):
        #Gets the ID of the request clicked, so the relevant information can be pulled from the global list of dictionaries containing all request results.
        item_id = self.requestTable.selection()[0]
        item_id = int(item_id)
        print('item clicked ', item_id)

        #For each item in the array, if the item matched the ID clicked then assign the item to new variable my_item
        for item in ogArr:
            if item['id'] == item_id:
                my_item = item
                break
        else:
            my_item = None
        
        #Assigns the responses to new string variables to display
        og_response = str((my_item['original_response']))
        mod_response = str((my_item['replaced_response']))

        #Assign the original request
        og_request = (my_item['original_request'])
        #Pulls each separate value out of the full request dictionary
        #So method, URL, headers, and content. So they can be displayed in a text field line by line for better readability.
        total_request = (str(og_request[0])+"\n"+str(og_request[1])+"\n"+str(og_request[2])+"\n"+str(og_request[3]))

        #Assign the modified request
        mod_request = (my_item['replaced_request'])
        #Again, pulls each separate value out of the full request dictionary
        #So method, URL, headers, and content. So they can be displayed in a text field line by line for better readability.
        total_request_mod = (str(mod_request[0])+"\n"+str(mod_request[1])+"\n"+str(mod_request[2])+"\n"+str(og_request[3]))

        #Created the formatting and geometry for the pop-up window of the request/response details
        win = tk.Toplevel()
        win.geometry('1250x800')
        win.wm_title("Window")

        # configure the grid
        win.columnconfigure(0, weight=1)
        win.columnconfigure(1, weight=3)

        #Below four blocks each insert the original request, original response, modified request, modified response, respectively.
        original_request = Text(win)
        original_request.grid(column=0, row=0, sticky=tk.W, padx=5, pady=1)
        original_request.insert(INSERT, total_request)                

        modified_request = Text(win)
        modified_request.grid(column=1, row=0, sticky=tk.E, padx=5, pady=1)
        modified_request.insert(INSERT, total_request_mod)

        original_response = Text(win)
        original_response.grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        original_response.insert(INSERT, og_response)

        modified_response = Text(win)
        modified_response.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)       
        modified_response.insert(INSERT, mod_response)

#Initialising the app.
if __name__ == "__main__":
    app = App()