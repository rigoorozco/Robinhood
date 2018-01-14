# Robinhood.py: a collection of utilities for working with Robinhood's
# Private API

from enum import Enum

from six.moves.urllib.parse import unquote
from six.moves.urllib.request import getproxies
from six.moves import input

import getpass
import requests

from dateutil.parser import parse

from collections import namedtuple, defaultdict, OrderedDict

from logbook import Logger
log = Logger('Robinhood API')


class RobinhoodException(Exception):
    # Wrapper for custom Robinhood library exceptions
    pass


class LoginFailed(RobinhoodException):
    # Unable to login to Robinhood
    pass


class TwoFactorRequired(LoginFailed):
    # Unable to login because of 2FA failure
    pass


class Bounds(Enum):
    # Enum for bounds in `historicals` endpoint

    REGULAR = 'regular'
    EXTENDED = 'extended'


class Robinhood:
    # Wrapper class for fetching/parsing Robinhood endpoints

    endpoints = {
        "login": "https://api.robinhood.com/api-token-auth/",
        "logout": "https://api.robinhood.com/api-token-logout/",
        "investment_profile":
        "https://api.robinhood.com/user/investment_profile/",
        "accounts": "https://api.robinhood.com/accounts/",
        "ach_iav_auth": "https://api.robinhood.com/ach/iav/auth/",
        "ach_relationships": "https://api.robinhood.com/ach/relationships/",
        "ach_transfers": "https://api.robinhood.com/ach/transfers/",
        "applications": "https://api.robinhood.com/applications/",
        "dividends": "https://api.robinhood.com/dividends/",
        "edocuments": "https://api.robinhood.com/documents/",
        "instruments": "https://api.robinhood.com/instruments/",
        "margin_upgrades": "https://api.robinhood.com/margin/upgrades/",
        "markets": "https://api.robinhood.com/markets/",
        "notifications": "https://api.robinhood.com/notifications/",
        "orders": "https://api.robinhood.com/orders/",
        "password_reset": "https://api.robinhood.com/password_reset/request/",
        "portfolios": "https://api.robinhood.com/portfolios/",
        "positions": "https://api.robinhood.com/positions/",
        "quotes": "https://api.robinhood.com/quotes/",
        "historicals": "https://api.robinhood.com/quotes/historicals/",
        "document_requests":
        "https://api.robinhood.com/upload/document_requests/",
        "user": "https://api.robinhood.com/user/",
        "watchlists": "https://api.robinhood.com/watchlists/",
        "news": "https://api.robinhood.com/midlands/news/",
        "fundamentals": "https://api.robinhood.com/fundamentals/",
    }

    session = None
    username = None
    password = None
    headers = None
    auth_token = None

    def __init__(self):
        self.session = requests.session()
        self.session.proxies = getproxies()
        self.headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language":
            "en;q=1, fr;q=0.9, de;q=0.8, ja;q=0.7, nl;q=0.6, it;q=0.5",
            "Content-Type":
            "application/x-www-form-urlencoded; charset=utf-8",
            "X-Robinhood-API-Version": "1.0.0",
            "Connection": "keep-alive",
            "User-Agent": "Robinhood/823 (iPhone; iOS 7.1.2; Scale/2.00)"
        }

        self.session.headers = self.headers

    def login_prompt(self):  # pragma: no cover
        # Prompts user for username and password and calls login()

        username = input("Username: ")
        password = getpass.getpass()

        return self.login(username=username, password=password)

    def login(self,
              username,
              password,
              mfa_code=None):
        # Save and test login info for Robinhood accounts

        # Args:
        #     username (str): username
        #     password (str): password

        # Returns:
        #     (bool): received valid auth token

        self.username = username
        self.password = password
        payload = {
            'password': self.password,
            'username': self.username
        }

        if mfa_code:
            payload['mfa_code'] = mfa_code

        try:
            res = self.session.post(self.endpoints['login'], data=payload)
            res.raise_for_status()
            data = res.json()
        except requests.exceptions.HTTPError:
            raise LoginFailed()

        if 'mfa_required' in data.keys():           # pragma: no cover
            raise TwoFactorRequired()
            # requires a second call to enable 2FA

        if 'token' in data.keys():
            self.auth_token = data['token']
            self.headers['Authorization'] = 'Token ' + self.auth_token
            return True

        return False

    def logout(self):
        # Logout from Robinhood

        # Returns:
        #     (:obj:`requests.request`) result from logout endpoint

        try:
            req = self.session.post(self.endpoints['logout'])
            req.raise_for_status()
        except requests.exceptions.HTTPError as err_msg:
            log.warn('Failed to log out ' + repr(err_msg))

        self.headers['Authorization'] = None
        self.auth_token = None

        return req

    def get_url_content_json(self, url):
        res = self.session.get(url)
        res.raise_for_status()  # will throw without auth
        data = res.json()
        return data

    def investment_profile(self):
        # Fetch investment_profile

        # Returns:
        #     dictionary with investment profile information

        res = self.session.get(self.endpoints['investment_profile'])
        res.raise_for_status()  # will throw without auth
        data = res.json()
        return data

    def instruments(self, symbol):
        # Generates an instrument object. Currently this is only used for
        # placing orders
        res = self.session.get(self.endpoints['instruments'],
                               params={'query': symbol.upper()})
        if res.status_code == 200:
            result = res.json()['results']
            if len(result) > 0 and result[0]['symbol'] == symbol.upper():
                return result[0]
            else:
                raise Exception("Symbol queried was not found.")
        else:
            raise Exception("Could not generate instrument object")

    def quote_data(self, stock):
        # Fetch stock quote

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (:obj:`dict`): JSON contents from `quotes` endpoint

        url = str(self.endpoints['quotes']) + str(stock) + "/"
        req = requests.get(url)

        # Check for validity of symbol
        if req.status_code == 200:
            req.raise_for_status()
            data = req.json()
        else:
            raise Exception("Invalid ticker: " + req.text)

        return data

    def get_historical_quotes(self, stock, interval, span,
                              bounds=Bounds.REGULAR):
        # Fetch historical data for stock

        #     Note: valid interval/span configs
        #         interval = 5minute | 10minute + span = day, week
        #         interval = day + span = year
        #         interval = week
        #         TODO: NEEDS TESTS

        #     Args:
        #         stock (str): stock ticker
        #         interval (str): resolution of data
        #         span (str): length of data
        #         bounds (:enum:`Bounds`, optional): 'extended' or 'regular'
                #         trading hours

        #     Returns:
        #         (:obj:`dict`) values returned from `historicals` endpoint

        if isinstance(bounds, str):  # recast to Enum
            bounds = Bounds(bounds)

        params = {
            'symbols': ','.join(stock).upper,
            'interval': interval,
            'span': span,
            'bounds': bounds.name.lower()
        }

        res = self.session.get(self.endpoints['historicals'], params=params)
        return res.json()

    def get_news(self, stock):
        # Fetch news endpoint
        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (:obj:`dict`) values returned from `news` endpoint

        url = self.endpoints['news'] + stock.upper() + "/"
        return self.session.get(url).json()

    def ask_price(self, stock):
        # Get asking price for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (float): ask price

        return float(self.quote_data(stock)['ask_price'])

    def ask_size(self, stock):
        # Get ask size for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (int): ask size

        return int(self.quote_data(stock)['ask_size'])

    def bid_price(self, stock):
        # Get bid price for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (float): bid price

        return float(self.quote_data(stock)['bid_price'])

    def bid_size(self, stock):
        # Get bid size for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (int): bid size

        return int(self.quote_data(stock)['bid_size'])

    def last_trade_price(self, stock):
        # Get last trade price for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (float): last trade price

        return float(self.quote_data(stock)['last_trade_price'])

    def previous_close(self, stock):
        # Get previous closing price for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (float): previous closing price

        return float(self.quote_data(stock)['previous_close'])

    def previous_close_date(self, stock):
        # Get previous closing date for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (str): previous close date

        return self.quote_data(stock)['previous_close_date']

    def adjusted_previous_close(self, stock):
        # Get adjusted previous closing price for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (float): adjusted previous closing price

        return float(self.quote_data(stock)['adjusted_previous_close'])

    def symbol(self, stock):
        # Get symbol for a stock

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (str): stock symbol

        return self.quote_data(stock)['symbol']

    def last_updated_at(self, stock):
        # Get last update datetime

        #     Note:
        #         queries `quote` endpoint, dict wrapper

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (str): last update datetime

        return self.quote_data(stock)['updated_at']

    def last_updated_at_datetime(self, stock):
        # Get last updated datetime

        #     Note:
        #         queries `quote` endpoint, dict wrapper
        #         `self.last_updated_at` returns time as `str` in format:
        #         'YYYY-MM-ddTHH:mm:ss:000Z'

        #     Args:
        #         stock (str): stock ticker

        #     Returns:
        #         (datetime): last update datetime

        datetime_string = self.last_updated_at(stock)
        result = parse(datetime_string)

        return result

    @property
    def account(self):
        # Fetch account information

        #     Returns:
        #         (:obj:`dict`): `accounts` endpoint payload

        res = self.session.get(self.endpoints['accounts'])
        res.raise_for_status()  # auth required
        res = res.json()

        return res['results'][0]

    def fundamentals(self, stock):
        # Find stock fundamentals data

        #     Args:
        #         (str): stock ticker

        #     Returns:
        #         (:obj:`dict`): contents of `fundamentals` endpoint

        url = str(self.endpoints['fundamentals']) + str(stock.upper()) + "/"

        # Check for validity of symbol
        req = requests.get(url)

        if req.status_code == 200:
            req.raise_for_status()
            data = req.json()
        else:
            raise Exception("Ticker %s not found!" % stock)

        return data

    @property
    def portfolios(self):
        req = self.session.get(self.endpoints['portfolios'])
        req.raise_for_status()

        return req.json()['results'][0]

    @property
    def adjusted_equity_previous_close(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `adjusted_equity_previous_close` value

        return float(self.portfolios['adjusted_equity_previous_close'])

    @property
    def equity(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `equity` value

        return float(self.portfolios['equity'])

    @property
    def equity_previous_close(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `equity_previous_close` value

        return float(self.portfolios['equity_previous_close'])

    @property
    def excess_margin(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `excess_margin` value

        return float(self.portfolios['excess_margin'])

    @property
    def extended_hours_equity(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `extended_hours_equity` value

        try:
            return float(self.portfolios['extended_hours_equity'])
        except TypeError:
            log.warn('Failed to get extended hours equity')
            return None

    @property
    def extended_hours_market_value(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `extended_hours_market_value` value or None

        try:
            return float(self.portfolios['extended_hours_market_value'])
        except TypeError:
            log.warn('Failed to get extended hours market value')
            return None

    @property
    def last_core_equity(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `last_core_equity` value

        return float(self.portfolios['last_core_equity'])

    @property
    def last_core_market_value(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `last_core_market_value` value

        return float(self.portfolios['last_core_market_value'])

    @property
    def market_value(self):
        # Wrapper for portfolios

        #     Returns:
        #         (float): `market_value` value

        return float(self.portfolios['market_value'])

    @property
    def order_history(self):
        # Wrapper for portfolios

        #     Returns:
        #         (:obj:`dict`): JSON dict from getting orders

        return self.session.get(self.endpoints['orders']).json()

    @property
    def dividends(self):
        # Wrapper for portfolios

        #     Returns:
        #         (:obj: `dict`): JSON dict from getting dividends

        return self.session.get(self.endpoints['dividends']).json()

    @property
    def positions(self):
        # Returns the user's positions data

        #     Returns:
        #         (:object: `dict`): JSON dict from getting positions

        return self.session.get(self.endpoints['positions']).json()

    @property
    def securities_owned(self):
        # Returns list of securities' symbols that the user has shares in

        #     Returns:
        #         (:object: `dict`): Non-zero positions

        url = self.endpoints['positions'] + '?nonzero=true'
        return self.session.get(url).json()

    def place_market_order(
            self,
            instrument,
            quantity,
            transaction,
            time_in_force='gfd'):

        payload = {
            'account': self.account['url'],
            'instrument': unquote(instrument['url']),
            'quantity': quantity,
            'side': transaction,
            'symbol': instrument['symbol'],
            'time_in_force': time_in_force.lower(),
            'trigger': 'immediate',
            'type': 'market'
        }

        if transaction.lower() == "buy":
            price = self.quote_data(instrument['symbol'])['bid_price']
            payload['price'] = float(price)

        res = self.session.post(
            self.endpoints['orders'],
            data=payload
        )

        if res.status_code == 201:
            res = res.json()
            order_ID = res['url'][res['url'].index("orders")+7:-1]
            return order_ID
        else:
            raise Exception("Could not place order: " + res.text)

    def place_limit_order(
            self,
            instrument,
            quantity,
            limit_price,
            transaction,
            time_in_force='gfd'):

        payload = {
            'account': self.account['url'],
            'instrument': unquote(instrument['url']),
            'price': float(limit_price),
            'quantity': quantity,
            'side': transaction,
            'symbol': instrument['symbol'],
            'time_in_force': time_in_force.lower(),
            'trigger': 'immediate',
            'type': 'limit'
        }

        res = self.session.post(
            self.endpoints['orders'],
            data=payload
        )

        if res.status_code == 201:
            res = res.json()
            order_ID = res['url'][res['url'].index("orders")+7:-1]
            return order_ID
        else:
            raise Exception("Could not place order: " + res.text)

    def place_stop_limit_order(
            self,
            instrument,
            quantity,
            limit_price,
            stop_price,
            transaction,
            time_in_force='gfd'):

        payload = {
            'account': self.account['url'],
            'instrument': unquote(instrument['url']),
            'price': float(limit_price),
            'stop_price': float(stop_price),
            'quantity': quantity,
            'side': transaction,
            'symbol': instrument['symbol'],
            'time_in_force': time_in_force.lower(),
            'trigger': 'stop',
            'type': 'limit',
        }

        res = self.session.post(
            self.endpoints['orders'],
            data=payload
        )

        if res.status_code == 201:
            res = res.json()
            order_ID = res['url'][res['url'].index("orders")+7:-1]
            return order_ID
        else:
            raise Exception("Could not place order: " + res.text)

    def place_stop_loss_order(
            self,
            instrument,
            quantity,
            stop_price,
            transaction,
            time_in_force='gfd'):

        payload = {
            'account': self.account['url'],
            'instrument': unquote(instrument['url']),
            'stop_price': float(stop_price),
            'quantity': quantity,
            'side': transaction,
            'symbol': instrument['symbol'],
            'time_in_force': time_in_force.lower(),
            'trigger': 'stop',
            'type': 'market'
        }

        if transaction.lower() == "buy":
            price = self.quote_data(instrument['symbol'])['bid_price']
            payload['price'] = float(price)

        res = self.session.post(
            self.endpoints['orders'],
            data=payload
        )

        if res.status_code == 201:
            res = res.json()
            order_ID = res['url'][res['url'].index("orders")+7:-1]
            return order_ID
        else:
            raise Exception("Could not place order: " + res.text)

    def cancel_order(self, order_id):
        payload = {}

        res = self.session.post(
            self.endpoints['orders'] + order_id + "/cancel/",
            data=payload
        )

        if res.status_code == 200:
            return res
        else:
            raise Exception("Could not cancel order: " + res.text)

    def get_user_info(self):
        # Pulls user info from API and stores it in Robinhood object
        res = self.session.get(self.endpoints['user'])
        if res.status_code == 200:
            self.first_name = res.json()['first_name']
            self.last_name = res.json()['last_name']
        else:
            raise Exception("Could not get user info: " + res.text)
        res = self.session.get(self.endpoints['user'] + 'basic_info/')
        if res.status_code == 200:
            res = res.json()
            self.phone_number = res['phone_number']
            self.city = res['city']
            self.number_dependents = res['number_dependents']
            self.citizenship = res['citizenship']
            self.marital_status = res['marital_status']
            self.zipcode = res['zipcode']
            self.state_residence = res['state']
            self.date_of_birth = res['date_of_birth']
            self.address = res['address']
            self.tax_id_ssn = res['tax_id_ssn']
        else:
            raise Exception("Could not get basic user info: " + res.text)

    def order_details(self, order_ID):
        # Returns an order object which contains information about an order
        # and its status
        res = self.session.get(self.endpoints['orders'] + order_ID + "/")
        if res.status_code == 200:
            return res.json()
        else:
            raise Exception("Could not get order status: " + res.text)

    def order_status(self, order_ID):
        # Returns an order status string
        return self.order_details(order_ID)['state']

    @property
    def orders(self):
        # returns a list of all order_IDs, ordered from newest to oldest
        res = self.session.get(self.endpoints['orders'])
        if res.status_code == 200:
            orders = []
            for i in res.json()['results']:
                URL = i['url']
                orders.append(URL[URL.index("orders")+7:-1])
            return orders
        else:
            raise Exception("Could not retrieve orders: " + res.text)

    @property
    def open_orders(self):
        open_orders = {}

        for order in self.order_history["results"]:
            if order['state'] == 'queued' or \
               order['state'] == 'confirmed' or \
               order['state'] == 'partially_filled':
                open_orders[order['id']] = {
                    'dt': order['created_at'],
                    'asset':
                    self.session.get(order['instrument']).json()['symbol'],
                    'amount': float(order['quantity']),
                    'stop_price': float(order['stop_price']) \
                        if order['stop_price'] else None,
                    'limit_price': float(order['price']) \
                        if order['price'] else None,
                    'action': order['side'],
                    'state': order['state']
                }

        return open_orders

    @property
    def order_status(self):
        orders = {}

        for order in self.order_history["results"]:
            orders[order['id']] = {
                'status': order['state'],
                'filled': float(order['cumulative_quantity'])
        }

        return orders

    @property
    def executions(self):
        executions = defaultdict(OrderedDict)
        history = self.order_history["results"]

        for order in history:
            executions[order['id']] = {
                'dt': order['created_at'],
                'asset':
                self.session.get(order['instrument']).json()['symbol'],
                'amount': float(order['quantity']),
                'stop_price': float(order['stop_price']) \
                    if order['stop_price'] else None,
                'limit_price': float(order['price']) \
                    if order['price'] else None,
                'action': order['side'],
                'state': order['state'],
                'filled': float(order['cumulative_quantity'])
            }

        return executions
