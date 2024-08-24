import PySimpleGUI as sg
import scapy.all as scp
import scapy.arch.windows as scpwinarch
import threading
import socket
import codecs
import os
import sys
import pyshark
import json
import logging
import re
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

sg.theme("BluePurple")

def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols = []
alertdestips = []
alertscrips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertscrips
    global alertsrcports
    global alertdestports
    global alertmsgs

    alertprotocols = []
    alertdestips = []
    alertscrips = []
    alertsrcports = []
    alertdestports = []
    alertmsgs = []

    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        
        if rulewords[2] != "any":
            scrip = rulewords[2]
            alertscrips.append(scrip.lower())
        else:
            alertscrips.append("any")
        
        if rulewords[3] != "any":
            srcport = rulewords[3]
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")

        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")

        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")

        try:
            alertmsgs.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            alertmsgs.append("")
            pass
    
    print(alertprotocols)
    print(alertdestips)
    print(alertscrips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsgs)


process_rules(readrules())

suspiciouspackets = []
sus_packetactual = []
sus_readablepayloads = []

lastpacket = ""
all_readablepayloads = []
tcpstreams = []
http2streams = []
logdecodedtls = True

httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []

SSLLOGFILEPATH = "C:\\Users\\visha\\OneDrive\\Desktop\\My_Project\\ssl1.log"

pktsummarylist = []
updatepktlist = False

layout = [
    [
        sg.Button("START", key="-start-"),
        sg.Button("STOP", key="-stop-"),
        sg.Button("SAVE", key="-save-"),
        sg.Button("REFRESH RULES", key="-refreshrules-"),
        sg.Button("Load TCP/HTTP2 Streams", key='-showtcpstreamsbtn-'),
        sg.Button("Load HTTP Streams", key='-showhttpstreamsbtn-')
    ],
    [
        sg.Text("ALERT PACKETS", font=('Arial Bold', 20), size=(60, None), justification="left"),
        sg.Text("ALL PACKETS", font=('Arial Bold', 20), size=(60, None), justification="left")
    ],
    [
        sg.Listbox(key="-pkts-", size=(100,20), enable_events=True, values=suspiciouspackets),
        sg.Listbox(key="-pktsall-", size=(100,20), enable_events=True, values=pktsummarylist)
    ],
    [
        sg.Text("ALERT DECODED", font=('Arial Bold', 14), size=(35, None), justification="left"),
        sg.Text("HTTP2 STREAMS", font=('Arial Bold', 14), justification="left"),
        sg.Text("TCP STREAMS", font=('Arial Bold', 14), justification="left"),
        sg.Text("HTTP OBJECTS", font=('Arial Bold', 14), justification="left")
    ],
    [
        sg.Multiline(size=(60,20), key='-payloaddecoded-'),
        sg.Listbox(key='-http2streams-', size=(20, 20), values=http2streams, enable_events=True),
        sg.Listbox(key='-tcpstreams-', size=(20,20), values=tcpstreams, enable_events=True),
        sg.Listbox(key='-httpobjects-', size=(20, 20), values=httpobjectindexes, enable_events=True)
    ],
    [sg.Button('EXIT')]
]

def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))
    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None
    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None
    return headers


def extract_object(headers, http_payload):
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():
            object_extracted = http_payload[http_payload.index(b"\r\n\r\n") +4:]
            object_type = object_extracted[:2]
            logging.info("Object Type: %s" % object_type)
        else:
            logging.info("No Content Type in Package")
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info("%s: %s" % (b'Content-Length', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type

def read_http():
    objectlist = []
    objectsactual = []
    objectsactualtypes = []
    objectcount = 0
    global pkt_list
    try:
        os.remove(f".\\temp\\httpstreamread.pcap")
    except:
        pass
    httppcapfile = f".\\temp\\httpstreamread.pcap"
    scp.wrpcap(httppcapfile, pkt_list)
    pcap_flow = scp.rdpcap(httppcapfile)
    sessions_all = pcap_flow.sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if pkt.haslayer("TCP"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80 or pkt["TCP"].dport == 8080 or pkt["TCP"].sport == 8080:
                    if pkt["TCP"].payload:
                        payload = pkt["TCP"].payload
                        http_payload += scp.raw(payload)
        if len(http_payload):
            http_headers = get_http_headers(http_payload)

            if http_headers is None:
                continue

            object_found, object_type = extract_object(http_headers, http_payload)

            if object_found is not None and object_type is not None:
                objectcount += 1
                objectlist.append(objectcount-1)
                objectsactual.append(object_found)
                objectsactualtypes.append(object_type)
    
    return objectlist, objectsactual, objectsactualtypes


def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol Not Found"

def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertscrips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport
            for i in range(len(alertprotocols)):
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest

                if alertscrips[i] != "any":
                    chkscrip = alertscrips[i]
                else:
                    chkscrip = src

                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport

                if (str(src).strip() == str(chkscrip).strip() and 
                    str(dest).strip() == str(chkdestip).strip() and
                    str(proto).strip() == str(chkproto).strip() and
                    str(dport).strip() == str(chkdestport).strip() and
                    str(sport).strip() == str(chksrcport).strip()):

                    print("Flagged Packet")

                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode("UTF-8", "replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting TCP payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode("UTF-8", "replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting UDP payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("Not TCP or UDP packet")
                    
                    return True, str(alertmsgs[i])
            
        except:
            pkt.show()

    return False, ""

window = sg.Window("Network Traffic Analysis with Intrusion Detection System", layout, size=(1600,800), resizable=True)

pkt_list = []

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
capiface = ifaces[0]

def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary = pkt.summary()
    pktsummarylist.append(pkt_summary)
    pkt_list.append(pkt)
    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1} {pkt_summary} MSG: {sus_msg}")
        sus_packetactual.append(pkt)
    return

sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn":pkt_process,"filter":""}, daemon=True)

sniffthread.start()

def show_tcp_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("TCPSTREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def show_http2_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def load_tcp_streams(window):
    global http2streams
    global logdecodedtls
    try:
        os.remove(f".\\temp\\tcpstreamread.pcap")
    except:
        pass
    scp.wrpcap(f".\\temp\\tcpstreamread.pcap", pkt_list)
    global tcpstreams
    tcpstreams = []
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap1 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
        keep_packets=True)
    number_of_streams = 0
    for pkt in cap1:
        if pkt.highest_layer.lower() == "tcp" or pkt.highest_layer.lower() == "tls":
            print(pkt.tcp.stream)
            if int(pkt.tcp.stream) > number_of_streams:
                number_of_streams = int(pkt.tcp.stream) + 1
    for i in range(0, number_of_streams):
        tcpstreams.append(i)
    window["-tcpstreams-"].update(values=[])
    window["-tcpstreams-"].update(values=tcpstreams)

    if logdecodedtls == True:
        http2streams = []
        cap2 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="http2.streamid",
        keep_packets=True)
        #numberofhttp2streams = 0
        for pkt in cap2:
            field_names = pkt.http2._all_fields
            for field_name in field_names:
                http2_stream_id = {val for key, val in field_names.items() if key == 'http2.streamid'}
                http2_stream_id = "".join(http2_stream_id)
            #x1 = str(pkt.http2.stream).split(", ")
            #print(x1)
            #streamid = int(x1[1].strip().split(":")[1].strip())
            #print(streamid)
            if http2_stream_id not in http2streams:
                http2streams.append(http2_stream_id)
        window['-http2streams-'].update(values=http2streams)
        pass

def show_http2_stream(window, streamno):
    
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(
            tcpstreamfilename,
            display_filter = f'http2.streamid eq {str(http2streamindex)}',
            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
        )
    #print(cap3[0].http2.stream)
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        #try:
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
            #does literally nothing because we do not know the encoding format of the payload so scp.raw returns type error
        except:
            pass

        print(pkt.http2.stream)
        if ("DATA" not in pkt.http2.stream):
            http2headerdat = ''
            rawvallengthpassed = False
            print(pkt.http2._all_fields.items())
            for field, val in pkt.http2._all_fields.items():
                if rawvallengthpassed == False:
                    if field == 'http2.header.name.length':
                        rawvallengthpassed = True
                else:
                    #if field.split(".")[-1] != "headers":
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat
            # httpdat = "".join("".join({val for key,val in pkt.http2._all_fields.items() if key == 'http2.data.data'}).split(":"))
            # httpdatdecoded = decode_hex(httpdat)[0]
            # dat += httpdatdecoded
            # dat = pkt.pretty_print
            # payload = pkt.http2.payload
            # if hasattr(pkt,'http2'):
            #     if hasattr(pkt.http2,'json_object'):
            #         if hasattr(pkt.http2,'body_reassembled_data'):
            #             avp=json.loads(codecs.decode(pkt.http2.body_reassembled_data.raw_value,'hex'))
            # # encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            # # encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            # # dat += encryptedapplicationdata_hex_decoded
            #             dat += avp
            #print(encryptedapplicationdata_hex_decoded)
        # except Exception as ex:
        #     print(ex)
    
    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"


    print(dat)
    formatteddat = dat
    # formatteddat = str(dat, "ascii", "replace")
    #show_tcp_stream_openwin(formatteddat)
    print(formatteddat)

    show_http2_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)
    pass

def show_tcpstream(window, streamno):
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"    
    streamnumber = streamno
    cap = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter = 'tcp.stream eq %d' % streamnumber,
        override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
    )
    dat = b""
    decode_hex = codecs.getdecoder("hex_codec")
    for pkt in cap:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        try:
            payload = pkt.tcp.payload
            encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            dat += encryptedapplicationdata_hex_decoded
            #print(encryptedapplicationdata_hex_decoded)
        except Exception as ex:
            print(ex)

    formatteddat = str(dat, "ascii", "replace")

    # dat1 = ""
    # try:
    #     if pkt.http > 0:
    #         dat1 += "Stream Index :" , str(pkt.tcp.stream) # to print stream index at the start

    #         dat1 += "\nHTTP LAYER :", str(pkt.http).replace('\\n', '').replace('\\r', '')

    # except:
    #     pass
    #show_tcp_stream_openwin(formatteddat)
    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        sg.PopupAutoClose("No data")
    else:
        show_tcp_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)




def save_packets():
    global pkt_list
    if pkt_list:
        filename = sg.popup_get_text("Enter file name to save packets", default_text="saved")
        if filename:
            if not filename.endswith(".pcap"):
                filename += ".pcap"
            scp.wrpcap(filename, pkt_list)

while True:

    print(suspiciouspackets)

    event, values = window.read() 

    if event == "-refreshrules-":
        process_rules(readrules)

    if event == "-start-":
        updatepktlist = True
        incomingpacketlist = []
        inc_pkt_list = []
        suspiciouspackets = []
        suspacketactual = []
        pktsummarylist = []
        sus_readablepayloads = []
        pkt_list = []

        while True:

            event, values = window.read(timeout=10)
            if event == "-stop-":
                updatepktlist = False
                break
            if event == "-refreshrules-":
                process_rules(readrules)

            
            if event == sg.TIMEOUT_EVENT:
                window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))
                window["-pkts-"].update(values=suspiciouspackets, scroll_to_index=len(suspiciouspackets))
            
            if event in (None, 'Exit'):
                sys.exit()
                break
            if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
                sus_selected = values['-pkts-']
                #sus_selected_index = int(sus_selected.split()[0][0:2])
                sus_selected_index = values[event][0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
                except:
                    pass
                window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index ])
            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                #pktselected = values['-pktsall-']
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass
            if event == "-showtcpstreamsbtn-":
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()
                show_tcpstream(window, streamindex)
            if event == "-http2streams-":
                http2streamindex = values[event][0]
                show_http2_stream(window, int(http2streamindex))
            if event == "-showhttpstreamsbtn-":
                httpobjectindexes = []
                httpobjectactuals = []
                httpobjecttypes = []
                httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
                window["-httpobjects-"].update(values=httpobjectindexes)
            if event == "-httpobjects-":
                httpobjectindex = values[event][0]
                show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])
    
    if event == "-showhttpstreamsbtn-":
        httpobjectindexes = []
        httpobjectactuals = []
        httpobjecttypes = []
        httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
        window["-httpobjects-"].update(values=httpobjectindexes)
    
    if event == "-httpobjects-":
        httpobjectindex = values[event][0]
        show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
        #pktselected = values['-pktsall-']
        pkt_selected_index = window["-pktsall-"].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
        except:
            pass
    if event == '-savepcap-':
        pcapname = "nettrafic"
        scp.wrpcap(f'.\\savedpcap\\{pcapname}.pcap', inc_pkt_list)
    if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
        sus_selected = values['-pkts-']
        #sus_selected_index = int(sus_selected.split()[0][0:2])
        sus_selected_index = window['-pkts-'].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
        except:
            pass
        window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])
    if event == "-showtcpstreamsbtn-":
        load_tcp_streams(window)    
    if event == "-tcpstreams-":
        streamindex = window["-tcpstreams-"].get_indexes()
        show_tcpstream(window, streamindex)            
    # if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
    #             pktselected = values['-pktsall-']
    #             #sus_selected_index = int(sus_selected.split()[0][0:2])
    #             pktselectedindex = window['-pktsall-'].get_indexes()[0]
    #             window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
    if event in (None, 'Exit'):
        break


    elif event == "-save-":
        save_packets()
    elif event == sg.WINDOW_CLOSED:
        break

window.close()
