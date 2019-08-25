from burp import IBurpExtender, IBurpExtenderCallbacks, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.io import PrintWriter
from java.lang import String

import threading
import json
import collections
import random
import string

class BurpExtender(IBurpExtender, IBurpExtenderCallbacks, IContextMenuFactory):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        self.context = None

        # set our extension name
        callbacks.setExtensionName("Superbus - OpenAPI Site Map Creator")
        global stdout
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        # set context for the menu item creation
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):

        self.context = invocation
        menulist = ArrayList()

        # set a menu item with double click
        menulist.add(JMenuItem("Create a site map - OpenApi", actionPerformed=self.swaggermenu))

        return menulist

    def swaggermenu(self, event):

        # grab the details of what the user clicked
        self.http_traffic = self.context.getSelectedMessages()
        for item in self.http_traffic:
            obj = item.getHttpService()
            self.host = obj.getHost()
            self.port = obj.getPort()
            self.protocol = obj.getProtocol()

        # review this item here
        self.swaggerQuery()


        return

    def threadQuery(self, fullReq, host, protocol, port):
        thread = threading.Thread(target=self.connection, args=(fullReq, host, protocol, port,))
        thread.start()

    def swaggerQuery(self):
        for item in self.http_traffic:
            parsedObj = Parser(String(item.getResponse()))
            respBody  = parsedObj.normalizeResp()
            stdout.println(respBody.keys())
            d = Swagger(respBody, self._callbacks)
            objHttpService = item.getHttpService()

            url = d.returnURL()
            host = d.returnHost()
            protocol = d.returnScheme()
            port = d.returnPort()

            if not host:
                host = objHttpService.getHost()

            if not protocol:
                protocol = objHttpService.getProtocol()

            if not port:
                if host == objHttpService.getHost():
                    port = objHttpService.getPort()
                elif isinstance(protocol, list):
                    if 'https' in protocol:
                            port = 443
                    else:
                            port = 80
                else:
                    if 'https' == protocol:
                        port = 443
                    else:
                        port = 80
            for item in url:
                fullreq = self.initateReq(item)
                # stdout.println(fullreq)
                self.threadQuery(fullreq, host, protocol, port)

    def initateReq(self, component):
        isBody = False
        addHeaders = []
        params = []
        for item in component['params']:
            if item.location == 'header':
                addHeaders.append((item.param, item.type))
            elif item.location == 'query':
                if isinstance(item.param, list):
                    for var in item.param:
                        component['url'] += '?'
                        component['url'] += var + '=' + self.randomValue(item.type) + '&'
                else:
                    component['url'] += '?'
                    component['url'] += item.param + '=' + self.randomValue(item.type) + '&'
            elif item.location == 'path':
                if isinstance(item.param, list):
                    for var in item.param:
                        component['url'] = component['url'].replace('{'+var+'}', self.randomValue(item.type))
                        component['url'].strip(' ')
                else:
                    component['url'] = component['url'].replace('{' + item.param + '}', self.randomValue(item.type))
                    component['url'].strip(' ')
            elif item.location == 'body' or item.location == 'form':
                isBody = True
                params.append((item.param, item.type))
        if isinstance(component['content-type'], list):
            cntType = component['content-type'][0]
        else:
            cntType = component['content-type']

        if not addHeaders:
            headers = self.craftHeader(component['method'], component['url'], isBody, cnt=cntType)
        else:
            headers = self.craftHeader(component['method'], component['url'], isBody, additionalheaders=addHeaders, cnt=cntType)

        body =  self.craftBody(component['content-type'], params)

        if not body:
            return headers
        else:
            return headers+body

    def connection(self, fullReq, host, protocol, port=None):
        """Establish the connection with target host, port issuing the request and adding the IRequest obj into the site map"""
        try:
            if isinstance(protocol, list):
                for prot in protocol:
                    if prot == 'https':
                        httpService = self._helpers.buildHttpService(host, 443, prot)
                    elif protocol == 'http':
                        httpService = self._helpers.buildHttpService(host, 80, prot)
                    else:
                        httpService = self._helpers.buildHttpService(host, port, prot)
                    obj = self._callbacks.makeHttpRequest(httpService, fullReq)
                    self._callbacks.addToSiteMap(obj)
            else:
                if protocol == 'https':
                    httpService = self._helpers.buildHttpService(host, 443, protocol)
                elif protocol == 'http':
                    httpService = self._helpers.buildHttpService(host, 80, protocol)
                else:
                    httpService = self._helpers.buildHttpService(host, port, protocol)
                obj = self._callbacks.makeHttpRequest(httpService, fullReq)
                self._callbacks.addToSiteMap(obj)

        except Exception as e:
                print(host, port, protocol)
                stdout.println(e)

    def craftBody(self, cnt, values=None):
        """Craft the body content for the http request"""
        body = {}
        if values:
            for item in values:
                body[item[0]] = self.randomValue(item[1])
        else:
            return None
        if cnt == 'application/json':
            return json.dumps(body)
        else:
            return ", ".join(["=".join([key, str(val)]) for key, val in body.items()])


    def randomValue(self, element):
        """Generate random values """
        if element == "string":
            numbers = '0123456789'
            letters = string.ascii_letters
            letters += numbers
            return ''.join(random.choice(letters) for i in range(random.randint(0,10)))
        elif element == "number":
            return str(random.random())
        elif element == "integer":
            return str(random.randint(0,100000))
        elif element == "boolean":
            return 'true'
        elif element == "array":
            return "['item1', 'item2', 'item3']"
        elif element == "file":
            return 'This is a file data type'
        else:
            stdout.println("This data type {} is presenting error.".format(element))
            return 'Fuck it'

    def craftHeader(self, method, url,  isBody, additionalheaders=None, cnt=None):

        for item in self.http_traffic:
            requestInfo = self._helpers.analyzeRequest(item)
            hedStr = requestInfo.getHeaders()
        hedLis = [item for item in str(hedStr).strip('[').strip(']').split(', ')]
        firstLine = hedLis[0].split()
        firstLine[0] = method.upper()
        firstLine[1] = url
        firstLine[2] += '\r\n'
        headers = {item.split(': ')[0]:item.split(': ')[1] for item in hedLis[1:]}

        if 'Content-Length' in headers.keys():
            headers.pop('Content-Length' )

        fullHeader = ' '.join(firstLine)

        for key, value in headers.items():
            fullHeader += key+': '+value+'\r\n'

        if additionalheaders:
            for item in additionalheaders:
                key = item[0]
                if item[1] == 'integer':
                    value = 12345
                else:
                    value = 'Test'
                fullHeader += key+': '+value+'\r\n'
        if isBody:
            try:
                fullHeader += 'Content-Type: '+cnt+'\r\n'
            except TypeError:
                stdout.println('Error here')
                stdout.println(str(cnt))
                stdout.println(str(type(cnt)))

        fullHeader += '\r\n'

        return fullHeader

class Swagger(IBurpExtenderCallbacks):
    """Class to parse json object containing OpenAPI specification"""
    def __init__(self, respBody, callbacks):
        self.resp = respBody
        self.version = self.checkVersion()
        self._callbacks = callbacks
        global stdout
        stdout = PrintWriter(self._callbacks.getStdout(), True)

    def checkVersion(self):
        """Returns the version of the OpenAPI specification being used"""
        if 'swagger' in self.resp.keys():
            return self.resp['swagger'].strip('"')
        elif 'swaggerVersion' in self.resp.keys():
            return self.resp['swaggerVersion'].strip('"')
        elif 'openapi' in self.resp.keys():
            return self.resp['openapi'].strip('"')
        else:
            stdout.println('Please check the OpenAPI specification. The version was not identified for this API')
            return None
    def returnHost(self):
        """Returns host to be used in the connection if there's any defined"""
        host = None
        if self.checkVersion()[0] == '1':
            if 'basePath' in self.resp.keys():
                host = self.resp['basePath'].split('/')[2]
            else:
                host = None
        elif self.checkVersion()[0] == '2':
            if 'host' in self.resp.keys():
                host = self.resp['host']
            else:
                host = None
        elif self.checkVersion()[0] == '3':
            if 'servers' in self.resp.keys():
                if isinstance(self.resp['servers'], list):
                    host = [item['url'].split("://")[1] for item in self.resp['servers']]
                else:
                    host = self.resp['servers']['url'].split('://')[1]
        return host

    def returnPort(self):
        port = None
        if self.checkVersion()[0] == '2':
            if 'host' in self.resp.keys():
                host = self.resp['host']
                if ':' in host:
                    port = host.split(':')[1]
        return port

    def returnScheme(self):
        """Return the scheme to be used if there's any defined"""
        scheme = None
        if self.checkVersion()[0] == '1':
            if 'basePath' in self.resp.keys():
                scheme = self.resp['basePath'].split('://')[0]
            else:
                scheme = None
        elif self.checkVersion()[0] == '2':
            if 'schemes' in self.resp.keys():
                scheme = self.resp['schemes']
            else:
                scheme = None
        elif self.checkVersion()[0] == '3':
            if 'servers' in self.resp.keys():
                if isinstance(self.resp['servers'], list):
                    scheme = [item['url'].split("://")[0] for item in self.resp['servers']]
                else:
                    scheme = self.resp['servers']['url'].split('://')[0]
        else:
            stdout.println('Please check the OpenAPI specification. The scheme was not identified for this API')
        return scheme

    def returnURL(self):
        """Returns the url to be used to access the API replacing or not an URL parameter"""
        url = None
        basePath = None
        if self.checkVersion()[0] == '1':
            if 'apis' in self.resp.keys():
                if isinstance(self.resp['apis'], list):
                    url = []
                    for item in self.resp['apis']:
                        if 'path' in item.keys():
                            url.append(item['path'])
                        else:
                            stdout.println(
                                'Please check the OpenAPI specification. The paths were not identified for this API')
                else:
                    url = self.resp['apis']['path']
            else:
                stdout.println('Please check the OpenAPI specification. The APIs was not identified for this API')
        elif self.checkVersion()[0] == '2':
            if 'basePath' in self.resp.keys():
                basePath = self.resp['basePath']
            else:
                basePath = ''
            if 'paths' in self.resp.keys():
                url = []
                for item in self.resp['paths'].keys():
                    url.append(item)
            else:
                stdout.println(self.resp.keys())
                stdout.println('Please check the OpenAPI specification. The scheme was not identified for this API')
        elif self.checkVersion()[0] == '3':
            if 'servers' in self.resp.keys():
                if isinstance(self.resp['servers'], list):
                    for item in self.resp['servers']:
                        if "{basePath}" in item['url']:
                            if 'variables' in item.keys():
                                basePath = item['variables']['basePath']
                        else:
                            basePath = item['url'].split("/",3)[-1]
                else:
                    basePath = self.resp['servers']['url'].split("/",3)[-1]

            if 'paths' in self.resp.keys():
                url = []
                for item in self.resp['paths'].keys():
                    url.append(item)
            else:
                stdout.println('Please check the OpenAPI specification. The scheme was not identified for this API')
        else:
            stdout.println('Please check the OpenAPI specification. The scheme was not identified for this API')
        if url:
            final = self.returnBparams(basePath, list(set(url)))
        else:
            stdout.println('Please check the OpenAPI specification. It was not possible to parse the url')
            final = None
        return final

    def returnContentType(self, method, api=None):
        """Returns the content-type to be used if there is any"""
        cntType = None
        if self.checkVersion()[0] == '1':
            if not api:
                if 'consumes' in self.resp.keys():
                    cntType = self.resp['consumes']
                else:
                    cntType = 'application/json'
            else:
                for item in self.resp['apis']:
                    if api == item['path'] and 'operations' in item.keys():
                        for ops in item['operations']:
                            if ops['method'] == method and 'consumes' in ops.keys():
                                cntType = ops['consumes']
                            elif 'consumes' in self.resp.keys():
                                cntType = self.resp['consumes']
                            else:
                                cntType = 'application/json'
                    elif 'consumes' in self.resp.keys():
                        cntType = self.resp['consumes']
                    else:
                        cntType = 'application/json'
        elif self.checkVersion()[0] == '2':
            if not api:
                if 'consumes' in self.resp.keys():
                    cntType = self.resp['consumes']
                else:
                    cntType = 'application/json'
            else:
                if 'paths' in self.resp.keys():
                    if api in self.resp['paths'].keys():
                        if method in self.resp['paths'][api].keys():
                            if 'consumes' in self.resp['paths'][api][method].keys():
                                cntType = self.resp['paths'][api][method]['consumes']
                            elif 'consumes' in self.resp.keys():
                                cntType = self.resp['consumes']
                            else:
                                cntType = 'application/json'
                        elif 'consumes' in self.resp.keys():
                            cntType = self.resp['consumes']
                        else:
                            cntType = 'application/json'
                    else:
                        stdout.println("Please check the OpenAPI specification. It was not possible to identify the"
                                       "'api' {} in the specification".format(api))
                else:
                    stdout.println("Please check the OpenAPI specification. It was not possible to identify 'paths' "
                                   "in the specification")
        elif self.checkVersion()[0] == '3':
            if 'paths' in self.resp.keys():
                if api in self.resp['paths'].keys():
                    if method in self.resp['paths'][api].keys():
                        if 'requestBody' in self.resp['paths'][api][method].keys():
                            cntType = self.resp['paths'][api][method]['requestBody']
                        else:
                            cntType = 'application/json'

                else:
                    stdout.println("Please check the OpenAPI specification. It was not possible to identify the"
                                   "'api' {} in the specification".format(api))
            else:
                stdout.println("Please check the OpenAPI specification. It was not possible to identify 'paths' "
                               "in the specification")

        else:
            stdout.println("Please check the OpenAPI specification. It was not possible to identify the correct version "
                                   "in the specification")

        if not cntType:
            cntType = 'application/json'

        return cntType


    def returnBparams(self, basepath=None, url=None):
        """Returns the body params and content type base on url and method"""
        final = []
        if self.checkVersion()[0] == '1':
            Param = collections.namedtuple('Param', 'param location type')
            for item in url:
                for path in self.resp['apis']:
                    if item == path['path'] and 'operations' in path.keys():
                        for ops in self.resp['apis'][path]['operations']:
                            meth = ops['method']
                            params = []
                            if 'parameters' in ops.keys():
                                for param in self.resp['paths'][item][ops]['parameters']:
                                    try:
                                        params.append(Param(param['name'], param['paramType'], param['type']))
                                    except KeyError:
                                        stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify the parameter {} within the parameters for path {}".format(param, item))
                            else:
                                stdout.println(
                                    "Please check the OpenAPI specification. It was not possible to "
                                    "identify parameters key within the parameters for path {} in version 1.2".format(item))
                            final.append({'url':item,
                                              'method':meth,
                                              'params':params,
                                              'content-type': self.returnContentType(meth, item)})

        elif self.checkVersion()[0] == '2':
            Param = collections.namedtuple('Param', 'param location type')
            for item in url:
                for meth in self.resp['paths'][item]:
                    params = []
                    if 'parameters' in self.resp['paths'][item][meth].keys():
                        for param in self.resp['paths'][item][meth]['parameters']:
                            if isinstance(param, list):
                                for mini in param:
                                    if mini['in'].lower() != 'body':
                                        try:
                                            params.append(Param(mini['name'], mini['in'], mini['type']))
                                        except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify the parameter {} within the parameters for path {}".format(
                                                    mini, item))
                                    else:
                                        try:
                                            for prop in mini['schema']['properties']:
                                                params.append(Param(prop, mini['in'],
                                                                    mini['schema']['properties'][prop]['type']))
                                        except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify schema within the parameters for path {}".format(item))

                            else:
                                if param['in'].lower() != 'body':
                                    try:
                                        params.append(Param(param['name'], param['in'], param['type']))
                                    except KeyError:
                                        stdout.println(
                                            "Please check the OpenAPI specification. It was not possible to "
                                            "identify the parameter {} within the parameters for path {}".format(param, item))
                                else:
                                    try:
                                        for prop in param['schema']['properties']:
                                            params.append(Param(prop, param['in'], param['schema']['properties'][prop]['type']))
                                    except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify schema within the parameters for path {}".format(item))
                            if {'url': item,
                                          'method': meth,
                                          'params': params,
                                          'content-type': self.returnContentType(meth, item)} not in final:
                                final.append({'url': item,
                                          'method': meth,
                                          'params': params,
                                          'content-type': self.returnContentType(meth, item)})
                    elif 'parameters' in self.resp['paths'][item].keys():
                        for param in self.resp['paths']['item']['parameters']:
                            if isinstance(param, list):
                                for mini in param:
                                    if mini['in'].lower() != 'body':
                                        try:
                                            params.append(Param(mini['name'], mini['in'], mini['type']))
                                        except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify the parameter {} within the parameters for path {}".format(
                                                    mini, item))
                                    else:
                                        try:
                                            for prop in mini['schema']['properties']:
                                                params.append(Param(prop, mini['in'],
                                                                    mini['schema']['properties'][prop]['type']))
                                        except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify schema within the parameters for path {}".format(item))
                            else:
                                if param['in'].lower() != 'body':
                                    try:
                                        params.append(Param(param['name'], param['in'], param['type']))
                                    except KeyError:
                                        stdout.println(
                                            "Please check the OpenAPI specification. It was not possible to "
                                            "identify the parameter {} within the parameters for path {}".format(param, item))
                                else:
                                    try:
                                        for prop in param['schema']['properties']:
                                            params.append(Param(prop, param['in'], param['schema']['properties'][prop]['type']))
                                    except KeyError:
                                            stdout.println(
                                                "Please check the OpenAPI specification. It was not possible to "
                                                "identify schema within the parameters for path {}".format(item))

                            if {'url': item,
                                          'method': meth,
                                          'params': params,
                                          'content-type': self.returnContentType(meth, item)} not in final:
                                final.append({'url': item,
                                          'method': meth,
                                          'params': params,
                                          'content-type': self.returnContentType(meth, item)})
        elif self.checkVersion()[0] == '3':
            """"""

        return final


class Parser:
    """Class object to parse the OpenAPI specification"""
    def __init__(self, respObj):
        self.resp = respObj
        self.body = self.normalizeResp()

    def normalizeResp(self):
        """Normalization of object response to json format"""
        headers = self.normalizeHeader(str(self.resp).split('\r\n\r\n',1)[0])
        if self.checkFormat(headers) == 'json':
            resp = json.loads(str(self.resp).split('\r\n\r\n',1)[1])
        else:
            resp = self.yaml(str(self.resp).split('\r\n\r\n',1)[1])
        return resp

    def normalizeHeader(self, obj):
        """ Normalization of header as a dict type"""
        headerList = obj.split('\n')
        headerList.pop(0)
        headerDict = {}
        for header in headerList:
            headerDict[header.split(':',1)[0]] = header.split(':',1)[1]
        return headerDict

    def checkFormat(self, headers):
        """Format checking for the OpenAPI specification"""
        self.format = None

        def inferBody(obj):
            """Check based on body content to infer the format of the openapi specification"""
            try:
                json.loads(str(obj).split('\r\n\r\n', 1)[1])
                return 'json'
            except:
                return 'yaml'

        if 'Content-Type'  in headers.keys():
            if 'json' in headers['Content-Type']:
                self.format = 'json'
            elif 'yaml' in headers['Content-Type']:
                self.format = 'yaml'
            else:
                self.format = inferBody(self.resp)
        else:
            self.format = inferBody(self.resp)

        return self.format

    def yaml(self, obj):
        yaml = YAML(obj)
        return yaml.load()

class YAML():
    """Custom parser for OpenAPI specification"""
    def __init__(self, resp):
        import re
        self.root = 0
        self.content = resp.split('\n')
        # fix this item below
        if not re.search('[a-zA-Z]', self.content[0]):
            self.content.pop(0)
        if not re.search('[a-zA-Z]', self.content[-1]):
            self.content.pop(-1)
        self.returnjson = {}
        for item in self.content:
            found = re.match(r'^([^#]*)#(.*)$', item)
            if found:  # The line contains a hash / comment
                self.content[self.content.index(item)] = found.group(1)
    def yamlNormalize(self):
        """Normalization of yaml data to json"""
        dtstruct = []
        for item in self.content:
            if item.strip() is not '':
                if item[-1] == ':':
                    if item.lstrip(' ')[0] == '-':
                        dtstruct.append({'name': item.lstrip(' ').strip(':').strip('- '), 'value': "",
                                         'level': (len(item) - len(item.lstrip(' '))), 'isList': self.isList(item)})
                    else:
                        dtstruct.append({'name': item.lstrip(' ').strip(':'), 'value': "",
                                     'level': (len(item) - len(item.lstrip(' '))), 'isList': self.isList(item)})
                elif ':' in item:
                    if item.lstrip(' ')[0] == '-':
                        dtstruct.append(
                            {'name': item.split(':')[0].lstrip(' ').strip('- '), 'value': item.split(':')[1].lstrip(' '),
                             'level': (len(item) - len(item.lstrip(' '))), 'isList': self.isList(item)})
                    else:
                        dtstruct.append({'name': item.split(':')[0].lstrip(' '), 'value': item.split(':')[1].lstrip(' '),
                                     'level': (len(item) - len(item.lstrip(' '))), 'isList': self.isList(item)})
                else:
                    dtstruct.append({'name': item.lstrip('- '), 'value': '',
                                     'level': (len(item) - len(item.lstrip(' '))), 'isList': self.isList(item)})
        flag = True
        for item in dtstruct:
            if item['level'] == 0:
                flag = False
        if flag:
            for item in dtstruct:
                item['level'] -= 2
        self.normlized = dtstruct
        data = self.objToJson(dtstruct)
        return data
    def objToJson(self, ttree, level=0):
        # Based on this stackoverflow implementation https://stackoverflow.com/questions/17858404/creating-a-tree-deeply-nested-dict-from-an-indented-text-file-in-python
        result = {}
        for i in range(0, len(ttree)):
            cn = ttree[i]
            try:
                nn = ttree[i + 1]
            except:
                nn = {'level': -1}
            # Edge cases
            if cn['level'] > level:
                continue
            if cn['level'] < level:
                return result
            # Recursion
            if nn['level'] == level:
                self.insertAndAppend(result, cn['name'], cn['value'])
            elif nn['level'] > level:
                # nested dictionary addition process occur here where rr will return the nested values
                # to be added on the current level
                rr = self.objToJson(ttree[i + 1:], level=nn['level'])
                if cn['isList'] and cn['value']:
                    for item in self.normlized[:self.normlized.index(cn)][::-1]:
                        if cn['level'] > item['level']:
                            r = [{cn['name']:cn['value']}]
                            r[0].update(rr)
                            name = item['name']
                            #the problem is here because you are addin
                            self.insertAndAppend(result, name, r)
                            break
                else:
                    if nn['level'] > cn['level'] and nn['isList'] and isinstance(rr, dict):
                        if cn['name'] in rr.keys():
                            self.insertAndAppend(result, cn['name'], rr[cn['name']])
                    else:
                        self.insertAndAppend(result, cn['name'], rr)
            else:
                self.insertAndAppend(result, cn['name'], cn['value'])
                if cn['isList']:
                    if not cn['value']:
                        result = [cn['name']]
                    else:
                        result = [{cn['name']:cn['value']}]
                return result
        return result
    def insertAndAppend(self, adict, key, val):
        """Insert a value in dict at key if one does not exist
        Otherwise, convert value to list and append
        """
        try:
            if key in adict:
                if type(adict[key]) != list:
                    adict[key] = [adict[key]]
                adict[key].append(val)
            else:
                adict[key] = val
        except TypeError:
            print('result\n',adict)
            print('key\n', key)
            print('value\n', val)
    def isList(self, obj):
        return True if obj.lstrip(' ')[0] == '-' else False
    def load(self):
        """Load function to return a dictionary"""
        self.returnjson = self.yamlNormalize()
        return self.returnjson