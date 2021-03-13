# Script adjusted for run as HomeAssisant pyscript script.
import os
import sys
import json
import requests
import smtplib
import random
import time
import datetime
import telegram
import base64
#from config import config

class TooGoodToGo:
    def __init__(self):
        self.home = os.path.expanduser("~")
        #self.cfgfile = "%s/.config/tgtgw/config.json" % self.home

        # default values
        self.config = {
            'email': pyscript.app_config['email'],
            'password': pyscript.app_config['password'],
            'accesstoken': None,
            'refreshtoken': None,
            'userid': "",
        }

        self.availables = {}
        self.baseurl = 'https://apptoogoodtogo.com'
        self.session = requests.session()

        self.colors = {
            'red': "\033[31;1m",
            'green': "\033[32;1m",
            'nc': "\033[0m",
        }

        #self.bot = telegram.Bot(token=config['telegram-token'])

        # load configuration if exists
        self.load()

    # load configuration
    def load(self):
        if not 'sensor.tgtg_watcher_config' in state.names(domain=None):
            return False
		
        if state.get('sensor.tgtg_watcher_config.accesstoken') == '' or  state.get('sensor.tgtg_watcher_config.refreshtoken') == '' or state.get('sensor.tgtg_watcher_config.userid') == '':
            return False		
	
        #if not os.path.exists(self.cfgfile):
        #    return False

        #log.info("[+] loading configuration: %s" % self.cfgfile)

        #with open(self.cfgfile, "r") as f:
        #with task.executor(open, self.cfgfile, "r") as f:
        #    data = task.executor(f.read())

        #self.config = json.loads(data)
        self.config['accesstoken'] = state.get('sensor.tgtg_watcher_config.accesstoken')
        self.config['refreshtoken'] = state.get('sensor.tgtg_watcher_config.refreshtoken')
        self.config['userid'] = state.get('sensor.tgtg_watcher_config.userid')

        log.info("[+] access token: %s" % self.config['accesstoken'])
        log.info("[+] refresh token: %s" % self.config['refreshtoken'])
        log.info("[+] user id: %s" % self.config['userid'])
			
    # save configuration
    def save(self):
        #basepath = os.path.dirname(self.cfgfile)
        #log.info("[+] configuration directory: %s" % basepath)

        #if not os.path.exists(basepath):
        #    os.makedirs(basepath)

        #with task.executor(open, self.cfgfile, "w") as f:
        #    log.info("[+] writing configuration: %s" % self.cfgfile)
        #    task.executor(f.write, json.dumps(self.config))

        state.set('sensor.tgtg_watcher_config', value=datetime.datetime.now(), new_attributes={'accesstoken': self.config['accesstoken'], 'refreshtoken': self.config['refreshtoken'], 'userid': self.config['userid'], 'task_id': task.current_task().get_name()})
		
    def isauthorized(self, payload):
        if not payload.get("error"):
            return True

        if payload['error'] == 'Unauthorized':
            log.info("[-] request: unauthorized request")
            return False

        return None

    def url(self, endpoint):
        return "%s%s" % (self.baseurl, endpoint)

    def post(self, endpoint, json):
        headers = {
            'User-Agent': 'TooGoodToGo/20.1.1 (732) (iPhone/iPhone SE (GSM); iOS 13.3.1; Scale/2.00)',
            'Accept': "application/json",
            'Accept-Language': "en-US"
        }

        if self.config['accesstoken']:
            headers['Authorization'] = "Bearer %s" % self.config['accesstoken']

        return task.executor(self.session.post, self.url(endpoint), headers=headers, json=json)

    def login(self):
        login = {
            'device_type': "UNKNOWN",
            'email': self.config['email'],
            'password': self.config['password']
        }

        # disable access token to request a new one
        self.config['accesstoken'] = None

        log.info("[+] authentication: login using <%s> email" % login['email'])

        r = self.post("/api/auth/v1/loginByEmail", login)
        data = r.json()

        if self.isauthorized(data) == False:
            log.info("[-] authentication: login failed, unauthorized")
            self.rawnotifier("Could not authenticate watcher, stopping.")
            sys.exit(1)

        self.config['accesstoken'] = data['access_token']
        self.config['refreshtoken'] = data['refresh_token']
        self.config['userid'] = data['startup_data']['user']['user_id']

        return True

    def refresh(self):
        data = {'refresh_token': self.config['refreshtoken']}
        ref = self.post('/api/auth/v1/token/refresh', data)

        payload = ref.json()
        if self.isauthorized(payload) == False:
            log.info("[-] authentication: refresh failed, re-loggin")
            return self.login()

        self.config['accesstoken'] = payload['access_token']

        log.info("[+] new token: %s" % self.config['accesstoken'])

        return True

    def favorite(self):
        data = {
            'favorites_only': True,
            'origin': {
                'latitude': pyscript.app_config['latitude'],
                'longitude': pyscript.app_config['longitude']
            },
            'radius': 200,
            'user_id': self.config['userid'],
            'page': 1,
            'page_size': 20
        }

        while True:
            try:
                r = self.post("/api/item/v7/", data)
                if r.status_code >= 500:
                    continue

                if r.status_code == 200:
                    return r.json()

            except Exception as e:
                log.info(e)

            task.sleep(1)


    def datetimeparse(self, datestr):
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        value = datetime.datetime.strptime(datestr, fmt)
        return value.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)

    def issameday(self, d1, d2):
        return (d1.day == d2.day and d1.month == d2.month and d1.year == d2.year)

    def pickupdate(self, item):
        now = datetime.datetime.now()
        pfrom = self.datetimeparse(item['pickup_interval']['start'])
        pto = self.datetimeparse(item['pickup_interval']['end'])

        prange = "%02d:%02d - %02d:%02d" % (pfrom.hour, pfrom.minute, pto.hour, pto.minute)

        if self.issameday(pfrom, now):
            return "Today, %s" % prange

        return "%d/%d, %s" % (pfrom.day, pfrom.month, prange)


    def available(self, items):
        favourites = []
        for item in items['items']:
            name = item['display_name']
            price = item['item']['price']['minor_units'] / 100
            value = item['item']['value_including_taxes']['minor_units'] / 100
            color = "green" if item['items_available'] > 0 else "red"
            kname = "%s-%.2d" % (name, price)

            ## log.info("[+] merchant: %s%s%s" % (self.colors[color], name, self.colors['nc']))

            if item['items_available'] > 0:
                favourites.append({'name': name, 'price': price, 'value': value, 'color': self.colors[color], 'kname': name, 'items_available': item['items_available'], 'pickup_date': self.pickupdate(item), 'link': 'https://share.toogoodtogo.com/item/'+str(item['item']['item_id'])})
            else:
                favourites.append({'name': name, 'price': price, 'value': value, 'color': self.colors[color], 'kname': name, 'items_available': item['items_available'], 'pickup_date': 'N/A', 'link': 'https://share.toogoodtogo.com/item/'+str(item['item']['item_id'])})

            if item['items_available'] == 0:
                if self.availables.get(kname):
                    del self.availables[kname]

                continue

            log.info("[+]   distance: %.2f km" % item['distance'])
            log.info("[+]   available: %d" % item['items_available'])
            log.info("[+]   price: %.2f PLN [%.2f PLN]" % (price, value))
            log.info("[+]   address: %s" % item['pickup_location']['address']['address_line'])
            log.info("[+]   pickup: %s" % self.pickupdate(item))

            if not self.availables.get(kname):
                log.info("[+]")
                log.info("[+]   == NEW ITEMS AVAILABLE ==")
                self.notifier(item)
                self.availables[kname] = True
                #state.set('sensor.tgtg_watcher_data', value="*%s*\n*Available*: %d\n*Price*: %.2f PLN\n*Pickup*: %s" % (item['display_name'], item['items_available'], item['item']['price']['minor_units'] / 100, self.pickupdate(item)))
                state.set('sensor.tgtg_watcher_data', value=datetime.datetime.now(), new_attributes={'newest_display_name': item['display_name'], 'newest_items_available': item['items_available'], 'newest_price': item['item']['price']['minor_units'] / 100, 'newest_pickup': self.pickupdate(item), 'newest_link': 'https://share.toogoodtogo.com/item/'+item['item']['item_id'], 'newest_ts': datetime.datetime.now()})

            log.info("[+]")

        state.setattr('sensor.tgtg_watcher_data.items', value=favourites)
        
    #
    # STAGING BASKET / CHECKOUT
    #
    def basket(self, itemid):
        payload = {
            "supported_payment_providers": [
                {
                    "payment_provider": {
                        "provider_id": "VOUCHER",
                        "provider_version": 1
                    },
                    "payment_types": [
                        "VOUCHER"
                    ]
                },
                {
                    "payment_provider": {
                        "provider_id": "ADYEN",
                        "provider_version": 1
                    },
                    "payment_types": [
                        "CREDITCARD",
                        "PAYPAL",
                        "IDEAL",
                        "SOFORT",
                        "VIPPS",
                        "BCMCMOBILE",
                        "DOTPAY",
                        "APPLEPAY"
                    ]
                },
                {
                    "payment_provider": {
                        "provider_id": "PAYPAL",
                        "provider_version": 1
                    },
                    "payment_types": [
                        "PAYPAL"
                    ]
                }
            ],
            "user_id": self.config['userid']
        }

        r = self.post("/api/item/v4/%s/basket" % itemid, payload)
        data = r.json()

        if data['create_basket_state'] == 'SUCCESS':
            basketid = data['basket_id']
            log.info("[+] basket created: %s" % basketid)

            self.checkout(basketid)

        pass

    def checkout(self, basketid):
        now = datetime.datetime.now().replace(microsecond=0).isoformat() + "Z"

        paymentsdk = {
            "locale": "en_BE",
            "deviceIdentifier": "",
            "platform": "ios",
            "osVersion": "13.3.1",
            "integration": "quick",
            "sdkVersion": "2.8.5",
            "deviceFingerprintVersion": "1.0",
            "generationTime": now,
            "deviceModel": "iPhone8,4"
        }

        sdkkey = json.dumps(paymentsdk)

        payload = {
            "items_count": 1,
            "payment_provider": {
                "provider_id": "ADYEN",
                "provider_version": 1
            },
            "payment_sdk_key": base64.b64encode(sdkkey.encode('utf-8')),
            "payment_types": [
                "CREDITCARD",
                "APPLEPAY",
                "BCMCMOBILE",
                "PAYPAL"
            ],
            "return_url": "toogoodtogoapp://"
        }

        log.info(payload)

        r = self.post("/api/basket/v2/%s/checkout" % basketid, payload)
        data = r.json()

        log.info(data)

        if data['result'] == 'CONTINUE_PAYMENT':
            log.info("OK OK")

        pass

    def debug(self):
        self.basket("43351i2634099")
        log.info("debug")

    #
    #
    #

    def rawnotifier(self, message):
        fmt = telegram.ParseMode.MARKDOWN
        #self.bot.send_message(chat_id=config['telegram-chat-id'], text=message, parse_mode=fmt)

    def notifier(self, item):
        name = item['display_name']
        items = item['items_available']
        price = item['item']['price']['minor_units'] / 100
        pickup = self.pickupdate(item)

        fmt = telegram.ParseMode.MARKDOWN
        message = "*%s*\n*Available*: %d\n*Price*: %.2f PLN\n*Pickup*: %s" % (name, items, price, pickup)

        #self.bot.send_message(chat_id=config['telegram-chat-id'], text=message, parse_mode=fmt)

    def daytime(self):
        now = datetime.datetime.now()
        nowint = (now.hour * 100) + now.minute
        return nowint

    def watch(self):
        if self.config['accesstoken'] is None:
            self.login()
            self.save()

        while True:
            fav = self.favorite()
            if self.isauthorized(fav) == False:
                log.info("[-] favorites: unauthorized request, refreshing token")
                self.refresh()
                continue

            self.available(fav)

            #
            # night pause
            #
            now = self.daytime()

            if now >= pyscript.app_config['night-pause-from'] or now <= pyscript.app_config['night-pause-to']:
                log.info("[+] night mode enabled, fetching disabled")

                while now >= pyscript.app_config['night-pause-from'] or now <= pyscript.app_config['night-pause-to']:
                    now = self.daytime()
                    task.sleep(60)

                log.info("[+] starting new day")

            #
            # speedup or normal waiting time
            #
            waitfrom = pyscript.app_config['normal-wait-from']
            waitto = pyscript.app_config['normal-wait-to']

            if now >= pyscript.app_config['speedup-time-from'] and now <= pyscript.app_config['speedup-time-to']:
                log.info("[+] speedup time range enabled")
                waitfrom = pyscript.app_config['speedup-wait-from']
                waitto = pyscript.app_config['speedup-wait-to']

            #
            # next iteration
            #
            wait = random.randrange(waitfrom, waitto)
            log.info("[+] waiting %d seconds" % wait)
            #time.sleep(wait)
            task.sleep(wait)

        self.save()

@state_trigger("input_boolean.tgtg_script_active == 'on' or input_boolean.tgtg_script_active == 'off'")
def tgtg_watcher():
    #if __name__ == '__main__':
      tgtg = TooGoodToGo()
      # tgtg.debug()

      task.unique('TASK_NAME', kill_me=False)
      if (state.get('input_boolean.tgtg_script_active') == 'on'):
          #if ('sensor.tgtg_watcher_data' in state.names(domain=None)):
              #state.delete('sensor.tgtg_watcher_data')
          log.info("tgtg Watch")
          if (not 'sensor.tgtg_watcher_data' in state.names(domain=None)):
              state.set('sensor.tgtg_watcher_data', value="")
          tgtg.watch()
      else:
          log.info("tgtg Destroy")