import asyncio
import os
import logging
import sys
from datetime import datetime

import aiofiles
import aiohttp

OUI_URL = "http://standards-oui.ieee.org/oui.txt"


class InvalidMacError(Exception):
    pass


class BaseMacLookup(object):
    dirname = os.path.dirname(__file__)
    cache_path = os.path.expanduser(os.path.join(dirname, 'mac-vendors.txt'))

    @staticmethod
    def sanitise(_mac):
        mac = _mac.replace(":", "").replace("-", "").replace(".","").upper()
        try:
            int(mac, 16)
        except ValueError:
            raise InvalidMacError("{} contains unexpected character".format(_mac))
        if len(mac) > 12:
            raise InvalidMacError("{} is not a valid MAC address (too long)".format(_mac))
        return mac

    def get_last_updated(self):
        vendors_location = self.find_vendors_list()
        if vendors_location:
            return datetime.fromtimestamp(os.path.getmtime(vendors_location))

    def find_vendors_list(self):
        possible_locations = [
            BaseMacLookup.cache_path,
            sys.prefix + "/mac-vendors.txt",
            os.path.dirname(__file__) + "/../../mac-vendors.txt",
            os.path.dirname(__file__) + "/../../../mac-vendors.txt",
            ]

        for location in possible_locations:
            if os.path.exists(location):
                return location


class AsyncMacLookup(BaseMacLookup):
    def __init__(self):
        self.prefixes = None

    async def update_vendors(self, url=OUI_URL):
        logging.log(logging.DEBUG, "Downloading MAC vendor list")
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                async with aiofiles.open(AsyncMacLookup.cache_path, mode='wb') as f:
                    self.prefixes = {}
                    while True:
                        line = await response.content.readline()
                        if not line:
                            break
                        if b"(base 16)" in line:
                            prefix, vendor = (i.strip() for i in line.split(b"(base 16)", 1))
                            self.prefixes[prefix] = vendor
                            await f.write(prefix + b":" + vendor + b"\n")

    async def load_vendors(self):
        self.prefixes = {}

        vendors_location = self.find_vendors_list()
        if vendors_location:
            logging.log(logging.DEBUG, "Loading vendor list from {}".format(vendors_location))
            async with aiofiles.open(vendors_location, mode='rb') as f:
                # Loading the entire file into memory, then splitting is
                # actually faster than streaming each line. (> 1000x)
                for l in (await f.read()).splitlines():
                    prefix, vendor = l.split(b":", 1)
                    self.prefixes[prefix] = vendor
        else:
            try:
                os.makedirs("/".join(AsyncMacLookup.cache_path.split("/")[:-1]))
            except OSError:
                pass
            await self.update_vendors()
        logging.log(logging.DEBUG, "Vendor list successfully loaded: {} entries".format(len(self.prefixes)))

    async def lookup(self, mac):
        mac = self.sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        if type(mac) == str:
            mac = mac.encode("utf8")
        return self.prefixes[mac[:6]].decode("utf8")


class MacLookup(BaseMacLookup):
    def __init__(self):
        self.async_lookup = AsyncMacLookup()
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    def update_vendors(self, url=OUI_URL):
        return self.loop.run_until_complete(self.async_lookup.update_vendors(url))

    def lookup(self, mac):
        return self.loop.run_until_complete(self.async_lookup.lookup(mac))

    def load_vendors(self):
        return self.loop.run_until_complete(self.async_lookup.load_vendors())


def main():
    import sys

    loop = asyncio.get_event_loop()
    if len(sys.argv) < 2:
        print("Usage: {} [MAC-Address]".format(sys.argv[0]))
        sys.exit()
    try:
        print(loop.run_until_complete(AsyncMacLookup().lookup(sys.argv[1])))
    except KeyError:
        print("Prefix is not registered")
    except InvalidMacError as e:
        print("Invalid MAC address:", e)


if __name__ == "__main__":
    main()