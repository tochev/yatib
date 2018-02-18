#!/usr/bin/env python3
"""
YATIB - Yet Another Twitter IRC Bot

Dependencies: requests python-irc python-twitter
    apt-get install python3-requests python3-irc python3-twitter

Usage:
    ./yatib.py twitterbot_conf.ini

Configuration file:

    [general]
    robust=no # whether to not die on unknown error

    [logging]
    loglevel=debug
    #logformat=[%(asctime)s] %(levelname)s %(name)s: %(message)s
    #dateformat=%Y-%m-%dT%H:%M:%S

    [oauth]
    consumer_key=INPUT
    consumer_secret=INPUT
    access_token_key=INPUT
    access_token_secret=INPUT

    [irc]
    server=irc.freenode.net
    #port=6697
    use_ssl=yes
    nick=testbot
    channels=#test,#test1

    [twitter]
    #poll_interval=60.0 ; NOTE: https://developer.twitter.com/en/docs/basics/rate-limiting
    skip_old_tweets_on_start=yes
    #query=#somehashtag

    [urls]
    surround_urls_with_space=yes
    use_expanded_urls=yes
    follow_redirects=yes
    #follow_only_domains=
    detect_urls_by_regex=yes

TODOs:
    - document how to aquire consumer and token oauth settings
    - make it accept commands and display help
    - add admins
    - commands to be accepted:
        - help
        - add to query
        - set query
        - subscribe/unsubscribe
        - tweet

"""
import heapq
import http.client
import logging
import re
import ssl
import sys
import time
import urllib.parse
from configparser import RawConfigParser
from html.parser import HTMLParser

import irc.client
import irc.connection
import requests
import twitter
from functools import reduce


IRC_LINE_LIMIT=510  # IRC sucks, IRC max message length = (512 - 2 for CR/LF)

IRC_BOLD = '\x02'
IRC_ITALIC = '\x16'
IRC_UNDERLINE = '\x1f'
IRC_REGULAR = '\x0f'


def split_utf8_at_space(message, chunk_size):
    """Splits message at chunks not exceeding chunk_size.

    :param message: utf-8 encoded bytes
    :param chunk_size: size of the chunks
    :yields: chunks of the appropriate size
    """
    while message:
        if len(message) <= chunk_size:
            yield message
            break
        else:
            for n in range(chunk_size, 0, -1):

                if message[n] in [' ', '\t'] and \
                   (n-1 < 0 or ord(message[n-1]) < 128):
                    yield message[:n]
                    message = message[n:]
                    break
            else:
                yield message[:chunk_size]
                message = message[chunk_size:]


class ScheduledTask(object):
    def __init__(self, task, delta):
        self.task = task
        self.delta = delta
        self.next = time.time()

    def __repr__(self):
        return "<SchedTask %s next:%i delta:%i>" %(
            self.task.__name__, self.next, self.delta)

    def __lt__(self, other):
        return self.next < other.next

    def __call__(self):
        return self.task()


class Scheduler(object):
    #FIXME: ideally the work should be done async
    # (due to the retrieval of the messages and urls)
    def __init__(self, tasks):
        self.task_heap = []
        for task in tasks:
            heapq.heappush(self.task_heap, task)

    def next_task(self):
        now = time.time()
        task = heapq.heappop(self.task_heap)
        wait = task.next - now
        task.next = now + task.delta
        heapq.heappush(self.task_heap, task)
        if (wait > 0):
            time.sleep(wait)
        task()

    def run_forever(self):
        while True:
            self.next_task()


class TwitterBot(object):

    def __init__(self, config_filename=None):
        self.config_filename = config_filename
        self.config = RawConfigParser(defaults={
            # DEFAULTS
            # general
            'robust': 'False',
            # logging
            'loglevel': 'DEBUG',
            'logformat': '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
            'dateformat': '%Y-%m-%dT%H:%M:%S',
            # irc
            'use_ssl': 'False',
            'nick': 'twitterbot',
            'password': '',
            'msg_prefix': '',
            'notification_command': 'NOTICE',
            # twitter
            'poll_interval': '60.0',
            'skip_old_tweets_on_start': 'True',
            'query': '',
            # urls
            'surround_urls_with_space': 'True',
            'use_expanded_urls': 'False',
            'follow_redirects': 'False',
            'follow_only_domains': '',
            'detect_urls_by_regex': 'False',
        })
        self.config.read(self.config_filename)

        # setup general
        self.be_robust = (
            self.config.has_section('general') and
            self.config.getboolean('general', 'robust')
        )

        # setup logging
        self.log = logging.getLogger('twitterbot')
        self.log.setLevel(
            getattr(logging, self.config.get('logging', 'loglevel').upper())
        )
        log_stream = logging.StreamHandler()
        log_stream.setFormatter(
            logging.Formatter(
                self.config.get('logging', 'logformat'),
                self.config.get('logging', 'dateformat')
            )
        )
        self.log.addHandler(log_stream)

        # setup twitter
        self.twitter = twitter.Api(
            consumer_key=self.config.get('oauth', 'consumer_key'),
            consumer_secret=self.config.get('oauth', 'consumer_secret'),
            access_token_key=self.config.get('oauth', 'access_token_key'),
            access_token_secret=self.config.get('oauth', 'access_token_secret')
        )
        self.query = self.config.get('twitter', 'query')
        self.seen_tweets = set() # set of ids

        # get url expansion preferences
        self.surround_urls_with_space = \
                self.config.getboolean('urls', 'surround_urls_with_space')
        self.use_expanded_urls = \
                self.config.getboolean('urls', 'use_expanded_urls')
        self.follow_redirects = \
                self.config.getboolean('urls', 'follow_redirects')
        self.follow_only_domains = [
            domain.strip() for domain in
            self.config.get('urls', 'follow_only_domains').strip().split(',')
            if domain.strip()
        ]
        self.detect_urls_by_regex = \
                self.config.getboolean('urls', 'detect_urls_by_regex')

        # setup irc
        self.irc = irc.client.Reactor() if hasattr(irc.client, 'Reactor') else irc.client.IRC()
        self.irc.add_global_handler('privmsg', self.handle_privmsg)
        self.irc_server = self.irc.server()
        self.irc_server_name = self.config.get('irc', 'server')
        self.irc_use_ssl = self.config.getboolean('irc', 'use_ssl')
        self.irc_server_port = (self.config.getint('irc', 'port')
                                if self.config.has_option('irc', 'port')
                                else None)
        self.nick = self.config.get('irc', 'nick')
        self.irc_password = self.config.get('irc', 'password')
        self.channels = [channel.strip() for channel in
                         self.config.get('irc', 'channels').strip().split(',')
                         if channel.strip()]

        # setup scheduled tasks
        self.scheduler = Scheduler([
            ScheduledTask(self.process_irc_events, delta=0.25),
            ScheduledTask(self.process_twitter,
                          delta=self.config.getfloat('twitter', 'poll_interval'))
        ])


    def handle_privmsg(self, connection, event):
        pass #TODO:
        """
        help
        follow foo
        add-to-query foo
        alter query
        search foo
        # add notification in the channels
        """

    def process_irc_events(self):
        self.irc.process_once()

    def _get_tweets(self):
        """Returns: new twitter status objects."""
        tweets = list(reversed(self.twitter.GetHomeTimeline()))
        if self.query:
            tweets += list(reversed(self.twitter.GetSearch(self.query)))
        seen_tweets = set(tweet.id for tweet in tweets)

        tweets = [tweet for tweet in tweets
                  if tweet.id not in self.seen_tweets]
        if len(self.seen_tweets) < 100000:
            self.seen_tweets.update(seen_tweets)
        else:
            self.seen_tweets = seen_tweets
        return tweets

    def notify_channels(self, message):
        command = '%s %s :' % (self.config.get('irc', 'notification_command'),
                               ','.join(self.channels))

        for chunk in split_utf8_at_space(
                message.encode('utf8'),
                IRC_LINE_LIMIT - len(command)
            ):
            self.irc_server.send_raw(command + chunk.decode('utf8'))

    def _follow_url(self, url):
        """Follows urls and returns the result."""
        self.log.debug('[following] %r', url)
        try:
            if self.follow_only_domains:
                if urllib.parse.urlparse(url).hostname not in \
                        self.follow_only_domains:
                    return url

            r = requests.head(url, allow_redirects=True)
            r.raise_for_status()
            result = r.url
            self.log.debug('[following] %r -> %r', url, result)
            return result

        except requests.ConnectionError as e:
            self.log.debug('[following] %r - connection error: %s', url, e)
        except Exception as e:
            self.log.exception('[following] %r error: %s', url, e, exc_info=e)
        return url

    def _handle_url_expansion(self, message, tweet_urls, max_link_length=None):
        """
        :param message: the tweet as text
        :param tweet_url: {short_url: expanded_url}
        :param max_link_length: if expanded urls shorten if final url is longer
        """
        if not (self.surround_urls_with_space,
                self.use_expanded_urls,
                self.follow_redirects):
            return message

        tweet_urls = (tweet_urls or {}).copy()

        self.log.debug(
            "[expanding urls] (using urls %r) %r",
            tweet_urls,
            message
        )

        if self.detect_urls_by_regex:
            non_urled = reduce(
                lambda s, url: s.replace(url, ' '),
                sorted(tweet_urls, key=len, reverse=True),
                message
            )
            detected_urls = re.findall("(https?://[^ )]+)", non_urled)
            tweet_urls.update((url, url) for url in detected_urls)

        if not self.use_expanded_urls:
            tweet_urls = dict((url, url) for url in tweet_urls)

        if self.follow_redirects:
            tweet_urls = dict((url, self._follow_url(value))
                              for (url, value) in tweet_urls.items())

        if tweet_urls:
            url_replace = lambda url: (
                (" ?%s ?" if self.surround_urls_with_space else "%s") %
                re.escape(url))

            def get_final_url(matched_text):
                res = tweet_urls.get(matched_text.strip(), matched_text)
                if len(res) > max_link_length:
                    return matched_text
                else:
                    return res

            message = re.sub(
                '|'.join(map(url_replace,
                            sorted(tweet_urls, key=len, reverse=True))),
                lambda m: "{sep}{url}{sep}".format(
                    sep=' ' if self.surround_urls_with_space else '',
                    url=tweet_urls.get(m.group(0).strip(), m.group(0))
                ),
                message
            )

        return message.strip()

    def _urls_to_dict(self, url_list):
        """Extracts urls from tweet status url list to {url: expanded}."""
        url_list = url_list or []
        return dict((u.url, u.expanded_url) for u in url_list)

    def _ircfy_tweet(self, tweet):
        """Takes a twitter status and outputs irc message."""
        message = tweet.text
        urls = tweet.urls
        if tweet.retweeted_status:
            #HACK: because iPhone sucks and does not correctly handle RT
            message = "RT @{0}: {1}".format(
                tweet.retweeted_status.user.screen_name,
                tweet.retweeted_status.text
            )
            urls = tweet.urls
        try:
            message = HTMLParser().unescape(message)
        except:
            self.log.exception("Unable to escape message %r", message)

        message = "{surround}{screen_name}{surround}: {message}".format(
            surround=IRC_BOLD,
            screen_name=tweet.user.screen_name,
            message=message
        )
        message = message.replace('\r', '').replace('\n', '  ')
        urls = self._urls_to_dict(urls)
        message = self._handle_url_expansion(message, urls, 440)
        return message

    def process_twitter(self):
        tweets = self._get_tweets()
        self.log.debug("Fetched %d new tweets", len(tweets))

        for tweet in tweets:
            message = self._ircfy_tweet(tweet)
            self.log.debug("[notifying] %r", message)
            self.notify_channels(message)

    def die(self):
        self.log.debug("Quiting...")
        self.irc_server.send_raw('quit')

    def run(self):
        self._connect_irc()

        if self.config.getboolean('twitter', 'skip_old_tweets_on_start'):
            self._get_tweets()

        while True:
            try:
                self.scheduler.run_forever()
            except KeyboardInterrupt:
                self.die()
                break
            except twitter.TwitterError as e:
                # these are mostly harmless - twitter being down or rate
                # limit exceeded
                self.log.info("Twitter error: %s", e)
            except http.client.BadStatusLine as e:
                # for whatever reason twitter sucks
                self.log.info("BadStatusLine (probably twitter error): %s", e)
            except irc.client.ServerNotConnectedError:
                self.log.debug("Not connected to irc server. "
                                "Trying to reconnect...")
                self._connect_irc()
            except UnicodeDecodeError:
                self.log.exception("Unicode exception: %s", e, exc_info=e)
                pass # not good
            except Exception as e:
                self.log.exception("Unhandled exception: %s", e)
                if not self.be_robust:
                    raise

    def _connect_irc(self):
        self.log.debug('Connecting to %s...', self.irc_server_name)
        self.irc_server.connect(
            self.irc_server_name,
            self.irc_server_port or (self.irc_use_ssl and 6697 or 6667),
            self.nick,
            self.irc_password,
            connect_factory=(self.irc_use_ssl
                             and irc.connection.Factory(wrapper=ssl.wrap_socket)
                                # FIXME: there is no ssl verification
                             or irc.connection.Factory()
                             )
        )
        self.log.debug('Connected to %s.', self.irc_server_name)
        for channel in self.channels:
            self.irc_server.join(channel)
        self.log.debug('Joined channels %s .', ','.join(self.channels))


def main(configuration_filename):
    TwitterBot(configuration_filename).run()


if __name__ == '__main__':
    main(sys.argv[1])

