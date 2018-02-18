# YATIB - Yet Another Twitter IRC Bot #

A twitter irc bot that outputs the HomeTimeLine of a twitter account using twitter API.

Also supports listing tweets that match certain query criteria.

# Getting Started #

Requirements;
```bash
pip install -r requirements.txt  # or apt-get install python3-requests python3-irc python3-twitter
```

Usage:
```bash
./yatib.py conf.ini
```

Configuration file:

```ini
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
#poll_interval=60.0 ; NOTE: https://dev.twitter.com/docs/rate-limiting/1.1/limits
skip_old_tweets_on_start=yes
#query=#somehashtag

[urls]
surround_urls_with_space=yes
use_expanded_urls=yes
follow_redirects=yes
#follow_only_domains=
detect_urls_by_regex=yes
```


# TODOs #

* document how to aquire consumer and token oauth settings
* make it accept commands and display help
* add admins
* commands to be accepted:
    * help
    * add to query
    * set query
    * subscribe/unsubscribe
    * tweet

# License #

This software is licensed under MIT License.

Copyright (C) Tocho Tochev <tochoⓐtochev·net>
