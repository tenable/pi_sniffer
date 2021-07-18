import socket
import time
import board
import busio
import re
import subprocess
import adafruit_ssd1306
from digitalio import DigitalInOut, Direction, Pull
from PIL import Image, ImageDraw, ImageFont

from pkgs.mac import mac_vendor_lookup

mac_tool = mac_vendor_lookup.MacLookup()

###
# This monolithic madness is the entire UI of pi sniffer. It communicates with
# the pi_sniffer engine over UDP and with Kismet over TCP. It issues various
# shell commands in order to interact with the system. It checks to see if the
# UI needs repainting every 0.1ish seconds. An enterprising individual might
# break this thing up.
###

###
# Hooray for globals!
###

# Create the I2C interface.
i2c = busio.I2C(board.SCL, board.SDA)

# Create a "display" that represents the OLED screen
disp = adafruit_ssd1306.SSD1306_I2C(128, 64, i2c)

# Input pins
button_A = DigitalInOut(board.D5)
button_A.direction = Direction.INPUT
button_A.pull = Pull.UP

button_B = DigitalInOut(board.D6)
button_B.direction = Direction.INPUT
button_B.pull = Pull.UP

button_L = DigitalInOut(board.D27)
button_L.direction = Direction.INPUT
button_L.pull = Pull.UP

button_R = DigitalInOut(board.D23)
button_R.direction = Direction.INPUT
button_R.pull = Pull.UP

button_U = DigitalInOut(board.D17)
button_U.direction = Direction.INPUT
button_U.pull = Pull.UP

button_D = DigitalInOut(board.D22)
button_D.direction = Direction.INPUT
button_D.pull = Pull.UP

button_C = DigitalInOut(board.D4)
button_C.direction = Direction.INPUT
button_C.pull = Pull.UP

# views
status_view = 0
overview = 1
ap_view = 2
client_view = 3
antenna = 4
system_view = 5
gps_view = 6
lock_screen = 7
rotate = 8  # place holder

# ap view
selected_ap = 0
selected_ant = 0
selected_client = 0

# current view
current_view = status_view

# lock controls
locked = False

# do we need to update the view?
redraw = True

# last ap list
ap_list = []
clients_list = []

# last update time
last_update = 0
last_stats = None

# observed some curious behavior from kismet. After many hours it sometimes
# just stops sending data in the kismet packets. I'm 90% certain it isn't me.
# who knows. Poor man's solution: watchdog that restarts kismet
watch_dog = time.time()

# flush output every five minutes just in case of catastrophic error
flush_time = time.time()

# the font all text writing will use
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 9)

# create a UDP socket to talk to pi_sniffer engine
backend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


###
# Globals over. I am appropriately embarrassed.
### 

##
# Issue a command to the pi sniffer UDP interface. Not all commands require
# responses (e.g. 'S\n' for shutdown does not require a response)
##
def pi_sniff_command(command, get_response):
    data = None

    pi_sniffer = subprocess.run(["ps", "-C", "pi_sniffer"], capture_output=True)
    if pi_sniffer.stdout.find(b"pi_sniffer") != -1:
        backend_sock.sendto(command + b"\n", ("127.0.0.1", 1270))
        if get_response is True:
            data = backend_sock.recvfrom(65535)[0]

    return data


##
# Issue a generic kismet command (e.g. shutdown) and return
##
def do_kismet_command(command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 2501))
    s.sendall(b"!0 " + command + b"\n")
    s.close()


##
# Grab the current channel list, hop status, and current channel for the
# provided antenna (uuid defined in kismet.conf. wlan0 == 01 and wlan1 == 02)
##
def kismet_ant_info(uuid):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 2501))
    s.sendall(b"!0 ENABLE SOURCE uuid,channellist,hop,channel\n")
    data = b""

    try:
        data = s.recv(1024)
        s.close()
    except:
        pass

    channel_info = re.search(b"SOURCE: " + uuid + b" ([0-9,]+) ([0-9]+) ([0-9]+)", data)
    if channel_info is None:
        return b'', b'', b''
    else:
        # channel list, hop status, current channel
        return channel_info.group(1), channel_info.group(2), channel_info.group(3)

    ##


# Set the channel of the provided antenna (uuid defined in kismet.conf). If
# the provided channel == "0" than switch to channel hopping.
##
def kismet_set_channel(uuid, channel):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 2501))
    if channel == b"0":
        s.sendall(b"!0 HOPSOURCE " + uuid + b" HOP 3\n")
    else:
        s.sendall(b"!0 HOPSOURCE " + uuid + b" LOCK " + channel + b"\n")
    s.close()


##
# Every 60 seconds check if kismet is still sending us data. I've observed it
# sending us empty packets for some reason... If we observe that behavior just
# restart it.
#
# Every 300 seconds tell pi_sniffer to flush output to disk.
##
def do_watchdog():
    global watch_dog
    global last_stats
    global flush_time

    if (current_time - 60) > watch_dog:
        watch_dog = current_time
        overview_stats = pi_sniff_command(b"o", True)
        if overview_stats is not None:
            stats = overview_stats.split(b",")
            if last_stats is None:
                last_stats = stats[5]
            elif last_stats == stats[5]:
                # we are either getting no data or kismet is behaving odd.
                # knock it over and set it back up
                last_stats = None
                kismet = subprocess.run(["ps", "-C", "kismet_server"], capture_output=True)
                if kismet.stdout.find(b"kismet_server") != -1:
                    do_kismet_command(b"SHUTDOWN")
                    subprocess.run(["airmon-ng", "stop", "wlan0mon"])
                    subprocess.run(["airmon-ng", "stop", "wlan1mon"])
                    time.sleep(3)
                    subprocess.Popen(["kismet_server", "-f", "/home/pi/kismet.conf", "-n", "--daemonize"])
            else:
                last_stats = stats[5]

    # let's check if we should flush output too
    if (current_time - 300) > flush_time:
        flush_time = current_time
        # only send the command if it's running
        pi_sniffer = subprocess.run(["ps", "-C", "pi_sniffer"], capture_output=True)
        if pi_sniffer.stdout.find(b"pi_sniffer") != -1:
            pi_sniff_command(b"f", False)


###
# Have the client attempt to rotate to the next screen
###
def check_view():
    global redraw
    global current_view
    global selected_ap
    global selected_ant
    global selected_client

    # Right joystick controls screen movement
    if not button_R.value:
        redraw = True

        # reset screen specific items
        # todo move this until ap_view
        selected_ap = 0
        selected_ant = 0
        selected_client = 0

        # move to the next screen
        current_view = current_view + 1
        current_view = current_view % rotate
    # Left joystick controls screen movement too
    elif not button_L.value:
        redraw = True

        # reset screen specific items
        # todo move this until ap_view
        selected_ap = 0
        selected_ant = 0
        selected_client = 0

        if current_view == 0:
            current_view = lock_screen
        else:
            current_view = current_view - 1


##
# Populate the start/status view
##
def do_status_view():
    global redraw

    if not button_A.value and not button_B.value:
        # attempt a clean shutdown
        pi_sniff_command(b"s", False)
        time.sleep(5)
        subprocess.run(["shutdown", "-h", "now"])
        return False

    elif not button_B.value:
        # start kismet and pi sniffer
        kismet = subprocess.run(["ps", "-C", "kismet_server"], capture_output=True)
        if kismet.stdout.find(b"kismet_server") == -1:
            redraw = True
            subprocess.Popen(["kismet_server", "-f", "/home/pi/kismet.conf", "-n", "--daemonize"])
            time.sleep(3)  # give it a second to get established

        pi_sniffer = subprocess.run(["ps", "-C", "pi_sniffer"], capture_output=True)
        if pi_sniffer.stdout.find(b"pi_sniffer") == -1:
            redraw = True
            subprocess.Popen(
                ["/home/pi/pi_sniffer/build/pi_sniffer", "-c", "/home/pi/pi_sniffer/pi_sniffer.conf", "-k", "127.0.0.1",
                 "-p", "3501"])
    elif not button_A.value:
        # shutdown kismet and pi sniffer
        redraw = True
        pi_sniff_command(b"s", False)
        kismet = subprocess.run(["ps", "-C", "kismet_server"], capture_output=True)
        if kismet.stdout.find(b"kismet_server") != -1:
            do_kismet_command(b"SHUTDOWN")
            subprocess.run(["airmon-ng", "stop", "wlan0mon"])
            subprocess.run(["airmon-ng", "stop", "wlan1mon"])

    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 12, 0), "Status", fill=0)

        kismet = subprocess.run(["ps", "-C", "kismet_server"], capture_output=True)
        if kismet.stdout.find(b"kismet_server") != -1:
            draw.text((0, 10), "Kismet: Running", font=font, fill=1)
        else:
            draw.text((0, 10), "Kismet: Stopped", font=font, fill=1)

        pi_sniffer = subprocess.run(["ps", "-C", "pi_sniffer"], capture_output=True)
        if pi_sniffer.stdout.find(b"pi_sniffer") != -1:
            draw.text((0, 20), "PiSniff: Running", font=font, fill=1)
        else:
            draw.text((0, 20), "PiSniff: Stopped", font=font, fill=1)

        wlan0mon = subprocess.run(["ifconfig", "wlan0mon"], capture_output=True)
        if wlan0mon.stdout.find(b"RUNNING,PROMISC") != -1:
            draw.text((0, 30), "wlan0mon: Up", font=font, fill=1)
        else:
            draw.text((0, 30), "wlan0mon: Down", font=font, fill=1)

        wlan1mon = subprocess.run(["ifconfig", "wlan1mon"], capture_output=True)
        if wlan1mon.stdout.find(b"RUNNING,PROMISC") != -1:
            draw.text((0, 40), "wlan1mon: Up", font=font, fill=1)
        else:
            draw.text((0, 40), "wlan1mon: Down", font=font, fill=1)

        gps_found = subprocess.run(["ls", "/dev/ttyACM0"], capture_output=True)
        if len(gps_found.stdout) > 0:
            draw.text((0, 50), "GPS: Available", font=font, fill=1)
        else:
            draw.text((0, 50), "GPS: Not Found", font=font, fill=1)

    return True


##
# Populate the overview screen
##
def do_overview():
    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 16, 0), "Overview", fill=0)
        draw.line((width / 2, 10, width / 2, height), fill=1)
        overview_stats = pi_sniff_command(b"o", True)
        if overview_stats is not None:
            stats = overview_stats.split(b",")
            draw.text((0, 10), "Time: " + stats[0].decode("utf-8"), font=font, fill=1)
            draw.text((0, 20), "APs: " + stats[1].decode("utf-8"), font=font, fill=1)
            draw.text((0, 30), "Open: " + stats[2].decode("utf-8"), font=font, fill=1)
            draw.text((0, 40), "WEP: " + stats[3].decode("utf-8"), font=font, fill=1)
            draw.text((0, 50), "WPA: " + stats[4].decode("utf-8"), font=font, fill=1)
            draw.text((width / 2 + 2, 10), "Pkts: " + stats[5].decode("utf-8"), font=font, fill=1)
            draw.text((width / 2 + 2, 20), "Bcns: " + stats[6].decode("utf-8"), font=font, fill=1)
            draw.text((width / 2 + 2, 30), "Data: " + stats[7].decode("utf-8"), font=font, fill=1)
            draw.text((width / 2 + 2, 40), "Enc: " + stats[8].decode("utf-8"), font=font, fill=1)
            draw.text((width / 2 + 2, 50), "EAPOL: " + stats[9].decode("utf-8"), font=font, fill=1)


##
# Handle antenna view and input
##
def do_ant_view():
    global redraw
    global selected_ant

    if not button_D.value:  # down arrow
        if selected_ant < 2:
            redraw = True
            selected_ant = selected_ant + 1
    elif not button_U.value:  # up arrow
        if selected_ant > 0:
            selected_ant = selected_ant - 1
            redraw = True
    elif not button_B.value and selected_ant != 0:
        if selected_ant == 1:
            wlan0mon = subprocess.run(["ifconfig", "wlan0mon"], capture_output=True)
            if wlan0mon.stdout.find(b"RUNNING,PROMISC") == -1:
                # if the antenna doesn't exist do nothing
                return
            uid = b"00000000-0000-0000-0000-000000000001"
        elif selected_ant == 2:
            wlan1mon = subprocess.run(["ifconfig", "wlan1mon"], capture_output=True)
            if wlan1mon.stdout.find(b"RUNNING,PROMISC") == -1:
                # if the antenna doesn't exist do nothing
                return
            uid = b"00000000-0000-0000-0000-000000000002"
        else:
            # ignore
            return

        (channellist, hopping, channel) = kismet_ant_info(uid)
        channels = channellist.split(b",")
        if len(channels) > 0:
            if hopping != b"0":
                kismet_set_channel(uid, channels[0])
            else:
                current = channels.index(channel)
                current = current + 1
                if current >= len(channels):
                    kismet_set_channel(uid, b"0")
                else:
                    kismet_set_channel(uid, channels[current])

            # kismet needs a little before we slam it with more requests
            time.sleep(0.3)
            redraw = True

    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 8, 0), "Antenna", fill=0)
        draw.line((width / 2, 10, width / 2, height), fill=1)

        if selected_ant == 1:
            draw.rectangle((0, 10, width / 2, 20), outline=1, fill=1)
            draw.text((0, 10), "wlan0mon", font=font, fill=0)

            wlan0mon = subprocess.run(["ifconfig", "wlan0mon"], capture_output=True)
            if wlan0mon.stdout.find(b"RUNNING,PROMISC") == -1:
                draw.text((width / 2 + 2, 10), "Disabled", font=font, fill=1)
            else:
                (channellist, hopping, channel) = kismet_ant_info(b"00000000-0000-0000-0000-000000000001")
                if hopping == b'':
                    draw.text((width / 2 + 2, 10), "Channel:\nTransitioning", font=font, fill=1)
                elif hopping != b"0":
                    draw.text((width / 2 + 2, 10), "Channel:\nHopping", font=font, fill=1)
                else:
                    draw.text((width / 2 + 2, 10), "Channel:\n" + channel.decode("utf-8"), font=font, fill=1)
        else:
            draw.text((0, 10), "wlan0mon", font=font, fill=1)

        if selected_ant == 2:
            draw.rectangle((0, 20, width / 2, 30), outline=1, fill=1)
            draw.text((0, 20), "wlan1mon", font=font, fill=0)

            wlan1mon = subprocess.run(["ifconfig", "wlan1mon"], capture_output=True)
            if wlan1mon.stdout.find(b"RUNNING,PROMISC") == -1:
                draw.text((width / 2 + 2, 10), "Disabled", font=font, fill=1)
            else:
                (channellist, hopping, channel) = kismet_ant_info(b"00000000-0000-0000-0000-000000000002")
                if hopping == b'':
                    draw.text((width / 2 + 2, 10), "Channel:\nTransitioning", font=font, fill=1)
                elif hopping != b"0":
                    draw.text((width / 2 + 2, 10), "Channel:\nHopping", font=font, fill=1)
                else:
                    draw.text((width / 2 + 2, 10), "Channel:\n" + channel.decode("utf-8"), font=font, fill=1)
        else:
            draw.text((0, 20), "wlan1mon", font=font, fill=1)


##
# Draw the system view
##
def do_system_view():
    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 36, 0), "System Status", fill=0)

        cpu = subprocess.run(["top", "-b", "-n", "1"], capture_output=True)
        result = re.search(b"%Cpu\(s\):[ ]+[0-9\.]+[ ]+us,[ ]+[0-9\.]+[ ]+sy,[ ]+[0-9\.]+[ ]+ni,[ ]+([0-9\.]+)[ ]+id",
                           cpu.stdout)
        if result is None:
            draw.text((0, 10), "CPU: Unknown%", font=font, fill=1)
        else:
            value = 100 - int(float(result.group(1)))
            draw.text((0, 10), "CPU: " + str(value) + "%", font=font, fill=1)

        mem = subprocess.run(["vmstat", "-s"], capture_output=True)
        total_mem = re.search(b"([0-9]+) K total memory\n", mem.stdout)
        total_free = re.search(b"([0-9]+) K free memory\n", mem.stdout)
        if total_mem is None or total_free is None:
            draw.text((0, 20), "Memory: Unknown%", font=font, fill=1)
        else:
            value = 100 - ((float(total_free.group(1)) / float(total_mem.group(1))) * 100)
            draw.text((0, 20), "Memory: " + str(int(value)) + "%", font=font, fill=1)

        disk = subprocess.run(["df"], capture_output=True)
        disk_usage = re.search(b"/dev/root[ ]+[A-Z0-9\.]+[ ]+[A-Z0-9\.]+[ ]+[A-Z0-9\.]+[ ]+([0-9]+)% /", disk.stdout)
        if disk_usage is None:
            draw.text((0, 30), "Disk: Unknown%", font=font, fill=1)
        else:
            draw.text((0, 30), "Disk: " + disk_usage.group(1).decode("utf-8") + "%", font=font, fill=1)

        temp = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True)
        temp_C = re.search(b"temp=(.*)", temp.stdout)
        if temp_C is None:
            draw.text((0, 40), "Temp: Unknown", font=font, fill=1)
        else:
            draw.text((0, 40), "Temp: " + temp_C.group(1).decode("utf-8"), font=font, fill=1)


##
# Populate the GPS view
##
def do_gps_view():
    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 28, 0), "GPS Status", fill=0)

        gps_found = subprocess.run(["ls", "/dev/ttyACM0"], capture_output=True)
        if len(gps_found.stdout) == 0:
            draw.text((0, 10), "Hardware: Not Found", font=font, fill=1)
        else:
            draw.text((0, 10), "Hardware: Available", font=font, fill=1)

            # does gpsd see the device?
            gps_found = subprocess.run(["gpspipe", "-w", "-n", "2"], capture_output=True)
            if gps_found.stdout.find(b'"devices":[]') != -1:
                draw.text((0, 20), "Hardware: Not Recognized", font=font, fill=1)
            else:
                draw.text((0, 20), "Hardware: Recognized", font=font, fill=1)

                # grab lat long
                gps_found = subprocess.run(["gpspipe", "-w", "-n", "4"], capture_output=True)
                result = re.search(b'"lat":([0-9\.-]+),"lon":([0-9\.-]+),', gps_found.stdout)
                if result is None:
                    draw.text((0, 30), "No sync", font=font, fill=1)
                else:
                    draw.text((0, 30), "Lat: " + result.group(1).decode("utf-8"), font=font, fill=1)
                    draw.text((0, 40), "Lon: " + result.group(2).decode("utf-8"), font=font, fill=1)


##
# Populate the client view and handle user input
##
def do_client_view():
    global redraw
    global selected_client
    global clients_list

    if not button_D.value:  # down arrow
        if selected_client < len(clients_list):
            redraw = True
            selected_client = selected_client + 1
    elif not button_U.value:  # up arrow
        if selected_client > 0:
            selected_client = selected_client - 1
            redraw = True
    elif not button_B.value:
        if selected_client > 0:
            # grab the client's bssid
            data = pi_sniff_command(b"c" + clients_list[selected_client - 1], True)
            if data is not None:
                split_info = data.split(b",")
                subprocess.run(["aireplay-ng", "-0", "1", "-a", split_info[1].decode("utf-8"), "-c",
                                clients_list[selected_client - 1].decode("utf-8"), "wlan0mon"])

    if redraw is True and selected_client == 0:
        # get the list from the back end
        clients = pi_sniff_command(b"c", True)
        if clients is not None:
            clients_list = clients.splitlines()
            # trim the \n\n
            clients_list = clients_list[:len(clients_list) - 1]

    if redraw is True:
        # divide screen
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 30, 0), "Client View", fill=0)
        draw.line((width / 2 + 22, 10, width / 2 + 22, height), fill=1)

        if selected_client > 3:
            i = selected_client - 4
        else:
            i = 0

        location = 0
        while location < 5 and i < len(clients_list):
            if selected_client == (i + 1):
                draw.rectangle((0, (location * 10) + 10, width / 2 + 22, (location * 10) + 20), outline=1, fill=1)
                draw.text((0, (location * 10) + 10), clients_list[i].decode("utf-8"), font=font, fill=0)
                data = pi_sniff_command(b"c" + clients_list[i], True)
                if data is not None:
                    split_info = data.split(b",")
                    vendor = mac_tool.lookup(clients_list[i].decode("utf-8"))
                    draw.text((width / 2 + 22, 10), split_info[1].decode("utf-8")[:9], font=font, fill=1)
                    draw.text((width / 2 + 22, 20), split_info[1].decode("utf-8")[9:], font=font, fill=1)
                    draw.text((width / 2 + 22, 30), "Sig: " + split_info[0].decode("utf-8"), font=font, fill=1)
                    draw.text((width / 2 + 22, 40), vendor[:9], font=font, fill=1)
                    draw.text((width / 2 + 22, 50), vendor[8:17], font=font, fill=1)

            else:
                draw.text((0, (location * 10) + 10), clients_list[i].decode("utf-8"), font=font, fill=255)

            i = i + 1
            location = location + 1


def do_ap_view():
    global redraw
    global selected_ap
    global ap_list

    if not button_D.value:  # down arrow
        if selected_ap < len(ap_list):
            redraw = True
            selected_ap = selected_ap + 1
    elif not button_U.value:  # up arrow
        if selected_ap > 0:
            selected_ap = selected_ap - 1
            redraw = True
    elif redraw == True and selected_ap == 0:
        # get the list from the back end
        access_points = pi_sniff_command(b"l", True)
        if access_points is not None:
            ap_list = access_points.splitlines()
            ap_list = ap_list[:len(ap_list) - 1]

    if redraw:
        # divide screen
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 18, 0), "Live View", fill=0)
        draw.line((width / 2, 10, width / 2, height), fill=1)

        # this supports forever scrolling... I hope
        if selected_ap > 3:
            i = selected_ap - 4
        else:
            i = 0

        location = 0
        while location < 5 and i < len(ap_list):
            ap = ap_list[i].split(b",")
            if len(ap[0]) > 11:
                shorten = ap[0][:8]
                shorten = shorten + b"..."
                ap[0] = shorten

            if selected_ap == (i + 1):
                draw.rectangle((0, (location * 10) + 10, width / 2, (location * 10) + 20), outline=1, fill=1)
                draw.text((0, (location * 10) + 10), ap[0].decode("utf-8"), font=font, fill=0)

                data = pi_sniff_command(b"r" + ap[1], True)
                if data is not None:
                    split_info = data.split(b",")
                    draw.text((width / 2 + 2, 10), ap[1].decode("utf-8")[:9], font=font, fill=1)
                    draw.text((width / 2 + 2, 20), ap[1].decode("utf-8")[9:], font=font, fill=1)
                    draw.text((width / 2 + 2, 30), "Ch: " + split_info[0].decode("utf-8"), font=font, fill=1)
                    draw.text((width / 2 + 2, 40), split_info[1].decode("utf-8"), font=font, fill=1)
                    draw.text((width / 2 + 2, 50), "Sig: " + split_info[2].decode("utf-8"), font=font, fill=1)
                    draw.text((width / 2 + 2, 60), "Clnts: " + split_info[3].decode("utf-8"), font=font, fill=1)
            else:
                draw.text((0, (location * 10) + 10), ap[0].decode("utf-8"), font=font, fill=255)

            i = i + 1
            location = location + 1


##
# Handle the lock screen drawing and locking input (unlocked handled elsewhere)
##
def do_lock_screen():
    global redraw
    global locked

    if not button_B.value:  # button 6
        locked = True
        redraw = True

    if redraw:
        draw.rectangle((0, 0, width, 10), outline=1, fill=1)
        draw.text(((width / 2) - 26, 0), "Lock Status", fill=0)

        if locked:
            draw.text((0, 10), "Locked", font=font, fill=1)
        else:
            draw.text((0, 10), "Unlocked", font=font, fill=1)


# ensure the echo is disabled on the gps tty. Really annoying this needs to be done.
subprocess.run(["stty", "-F", "/dev/ttyACM0", "-echo"])

# kill hdmi. power saving.
subprocess.run(["/usr/bin/tvservice", "-o"])

# loop until the user hits the break
# Clear display.
disp.fill(0)
disp.show()

while True:

    if locked:
        # the user can lock the display in the lock screen. If they have, don't
        # do any other UI processing. We will have to still do the watch dog
        # logic though
        if not button_A.value and not button_U.value:
            locked = False
            redraw = True
        else:
            current_time = time.time()
            if (current_time - 6) > last_update:
                redraw = True
            do_watchdog()
            time.sleep(0.1)
            continue

    # check if the user is changing the view
    check_view()

    # see if we should be refreshing
    if not redraw:
        current_time = time.time()
        if (current_time - 6) > last_update:
            redraw = True

        # while we have current time let's kick the dog
        do_watchdog()

    # we might draw! Create a blank canvas
    width = disp.width
    height = disp.height
    image = Image.new('1', (width, height))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, height), outline=0, fill=0)

    # which view to draw to the screen
    if current_view == status_view:
        if not do_status_view():
            # user has requested shutdown
            break
    elif current_view == overview:
        do_overview()
    elif current_view == antenna:
        do_ant_view()
    elif current_view == system_view:
        do_system_view()
    elif current_view == gps_view:
        do_gps_view()
    elif current_view == client_view:
        do_client_view()
    elif current_view == ap_view:
        do_ap_view()
    elif current_view == lock_screen:
        do_lock_screen()
    else:
        print("oh no! Why are we here?")

    if redraw:
        last_update = time.time()
        disp.image(image)
        disp.show()
        redraw = False

    time.sleep(0.1)

disp.fill(0)
disp.show()
