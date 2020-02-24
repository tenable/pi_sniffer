# Pi Sniffer

Pi Sniffer is a Wi-Fi sniffer built on the Raspberry Pi Zero W. While there are many excellent sniffing platforms out there, Pi Sniffer is unique for it's small size, real time display of captured data, and handling of user input.

<image src="https://user-images.githubusercontent.com/787916/75169212-291e0c00-56f6-11ea-8ae9-13e4a2762276.jpg" height="66%" width="66%">

## Current Release Image
You can download an an RPI image of this project from the "Releases" page. If you don't trust that, you can generate your own release by using the image_gen/create_image.sh script.

## Project Goals
The goal of this project was to create a Wi-Fi sniffer that I could carry around in my pocket, easily view real time status, decrypt packets on the fly, and change antenna channels as needed. Also, I wanted this project to be cheap (less than $100) and require no soldering.
  
## Hardware

The project was conceived with the goal to avoid any type of soldering. While Pi Sniffer does require the GPIO header on the Raspberry Pi Zero W, you can buy that pre-soldered. So I'm gonna claim no soldering required.

The base install requires:

* [Raspberry Pi Zero WH](https://www.adafruit.com/product/3708)
* [Adafruit 128x64 OLED Bonnet](https://www.adafruit.com/product/3531)
* A power source. I suggest one of the following:
    * [Anker PowerCore 5000](https://www.amazon.com/dp/B01CU1EC6Y)
    * [Anker E1 Astro](https://www.amazon.com/Anker-bar-Sized-Portable-High-Speed-Technology/dp/B00P7N0320)
    * [UPS-Lite](https://www.tindie.com/products/rachel/ups-lite-for-raspberry-pi-zero/)
* Any SD card 8GB or larger

Additionally, you can configure the device with any of the following add-ons (and still reasonably be called pocket sized):
* [Secondary antenna by CanKit](https://www.amazon.com/CanaKit-Raspberry-Wireless-Adapter-Dongle/dp/B00GFAN498)
* [Ublox-7 GPS](https://www.amazon.com/WINGONEER%C2%AE%C2%AE-Antenna-VK-172-Receiver-Windows/dp/B07F6TJG9L)
* [MicroUSB to USB adapters](https://www.amazon.com/Ksmile%C2%AE-Female-Adapter-SamSung-tablets/dp/B01C6032G0)
* [USB MiniHub](https://www.adafruit.com/product/2991)


## Software
Download the release image and flash it to an SD card. Stick the SD card into your RPI Zero WH and you should be good to go!

## Issues and Pull Requests
Issues and pull requests are welcome. I only ask that you provide enough information to recreate the issue or information about why the pull request should be accepted.
