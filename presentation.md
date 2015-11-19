# How to tame robots

by

_Alex Malaszkiewicz_

[Fractal Soft](http://fractalsoft.org)

Note: Why this title? Case study



## Agenda

* Definitions (bots, spiders, crawlers)
* Meta tags & Robots Exclusion Protocol
* Poisons & traps
* Tools
* Links

Note:



## Definitions

* Bots
* Spiders
* Crawlers

<blockquote>
A spider is a computer program that follows certain links on the web and gathers information as it goes.
</blockquote>

Note: How to find? In log files (`/var/log/nginx` or `/var/log/apache`)



# Bots

### User Agent examples

```
# Google
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)

# Bing (Microsoft)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)

# Yahoo
Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)

# Baidu (China)
Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)

# Baidu (China) ?
http://www.baidu.com/s?wd=www" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)

# Yandex (China)
Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)

# Ahrefs
Mozilla/5.0 (compatible; AhrefsBot/5.0; +http://ahrefs.com/robot/)

# DotBot
Mozilla/5.0 (compatible; DotBot/1.1; http://www.opensiteexplorer.org/dotbot, help@moz.com)

# Exabot
Mozilla/5.0 (compatible; Exabot/3.0; +http://www.exabot.com/go/robot)

# Scrapy
Scrapy/1.0.3.post6+g2d688cd (+http://scrapy.org)

# Seznam
Mozilla/5.0 (compatible; SeznamBot/3.2; +http://fulltext.sblog.cz/)

# GG
GGBotMaster/2.0
```



# Recomentations

### Meta tags

```
# No index for all
<meta name="robots" content="noindex">

# No follow for Google Bot
<meta name="googlebot" content="nofollow">

# No snippet for Google Bot News
<meta name="googlebot-news" content="nosnippet">

# Google directives:
# all, noindex, nofollow, noarchive,
# nosnippet, noodp, notranslate, noimageindex
# none = noindex, nofollow
```

Note:


### Robots Exclusion Protocol

```
# public/robots.txt

# All robots to stay out of a website
User-agent: *
Disallow: /

# All robots can visit all files
User-agent: *
Allow:

# Exclude assets folder
User-agent: *
Allow: /
Disallow: /assets

# Number of seconds to wait between subsequent visits
User-Agent: Googlebot
Crawl-Delay: 100
```



# Good, bad & ugly

Note: Good bots read robots.txt and observe the recommendations


## Feed the bot

Email crawlers want to eat!

Feed him... [spampoison.com](http://spampoison.com/)


## Trap / Honeypot

```
# public/robots.txt
User-agent: *
Allow: /
Disallow: /any-unused-path

# app/views/layouts/application.html.erb
<a class="hidden" href="/any-unused-path"></a>
```

& block IP!



# Tools


## Nginx

```
# /etc/nginx/blockips.conf
deny 1.2.3.4;

# /etc/nginx/nginx.conf
http {
  ...

  # Blocked IPs
  include blockips.conf;
  ...
}
```


## Rack::Attack!!!

```
# Gemfile
gem 'rack-attack'

# config/application.rb
config.middleware.use Rack::Attack # unless Rails.env.development?

# config/initializers/rack_attack.rb
class Rack::Attack
  # your custom configuration...
end
```


### Whitelist

```
# Always allow requests from localhost
# (blacklist & throttles are skipped)
Rack::Attack.whitelist('Allow from localhost') do |request|
  # Requests are allowed if the return value is truthy
  request.ip == '127.0.0.1'
end
```

or

```
# config/initializers/rack_attack.rb
class Rack::Attack::Request < ::Rack::Request
  def localhost?
    ip == '127.0.0.1'
  end
end

class Rack::Attack
  ...
  whitelist('Allow from localhost') do |req| { req.localhost? }
end
```


### Blacklists

```
# config/initializers/rack_attack.rb
# Block requests from 1.2.3.4
Rack::Attack.blacklist('block 1.2.3.4') do |request|
  # Requests are blocked if the return value is truthy
  request.ip == '1.2.3.4'
end

# Block logins from a bad user agent
Rack::Attack.blacklist('block bad UA logins') do |req|
  req.path == '/login' && req.post? && req.user_agent == 'BadBot'
end
```


### Throttles

```
# Throttle requests to 5 requests per second per ip
Rack::Attack.throttle('req/ip', limit: 5, period: 1.second) do |req|
  # If the return value is truthy, the cache key for the return value
  # is incremented and compared with the limit. In this case:
  #   "rack::attack:#{Time.now.to_i/1.second}:req/ip:#{req.ip}"
  #
  # If falsy, the cache key is neither incremented nor checked.
  req.ip
end

# Throttle login attempts for a given email parameter to 6 reqs/minute
# Return the email as a discriminator on POST /login requests
Rack::Attack.throttle('logins/email', limit: 6, period: 60.seconds) do |req|
  req.params['email'] if req.path == '/login' && req.post?
end

# You can also set a limit and period using a proc. For instance, after
# Rack::Auth::Basic has authenticated the user:
limit_proc = proc {|req| req.env["REMOTE_USER"] == "admin" ? 100 : 1}
period_proc = proc {|req| req.env["REMOTE_USER"] == "admin" ? 1.second : 1.minute}
Rack::Attack.throttle('req/ip', :limit => limit_proc, :period => period_proc) do |req|
  req.ip
end
```


### Tracks

```
# Track requests from a special user agent.
Rack::Attack.track("special_agent") do |req|
  req.user_agent == "SpecialAgent"
end

# Supports optional limit and period,
# triggers the notification only when the limit is reached.
Rack::Attack.track("special_agent", limit: 6, period: 60.seconds) do |req|
  req.user_agent == "SpecialAgent"
end

# Track it using ActiveSupport::Notification
ActiveSupport::Notifications.subscribe("rack.attack") do |name, start, finish, request_id, req|
  if req.env['rack.attack.matched'] == "special_agent" && req.env['rack.attack.match_type'] == :track
    Rails.logger.info "special_agent: #{req.path}"
    STATSD.increment("special_agent")
  end
end
```


### Fail2Ban

```
# Block suspicious requests for '/etc/password' or wordpress specific paths.
# After 3 blocked requests in 10 minutes, block all requests from that IP for 5 minutes.
Rack::Attack.blacklist('fail2ban pentesters') do |req|
  # `filter` returns truthy value if request fails, or if it's from a previously banned IP
  # so the request is blocked
  Rack::Attack::Fail2Ban.filter("pentesters-#{req.ip}", maxretry: 3, findtime: 10.minutes, bantime: 5.minutes) do
    # The count for the IP is incremented if the return value is truthy
    CGI.unescape(req.query_string) =~ %r{/etc/passwd} ||
    req.path.include?('/etc/passwd') ||
    req.path.include?('wp-admin') ||
    req.path.include?('wp-login')
  end
end
```


### My settings

```
# config/blacklist/ip.txt
# config/blacklist/path.txt
# config/blacklist/referer.txt
# config/blacklist/useragent.txt

# config/initializers/rack_attack.rb
# Extend request
class Rack::Attack::Request < ::Rack::Request
  def localhost?
    ip == '127.0.0.1'
  end

  def unknown?
    user_agent == '-'
  end
end

# Set blacklist using IPs, User Agents & url path
class Rack::Attack
  blacklist_folder = Rails.root.join('config', 'blacklist')

  ips = File.read("#{blacklist_folder}/ip.txt").split("\n")
  ips_regexp = Regexp.union(ips)
  blacklist('Block bad IP address') do |request|
    request.ip =~ ips_regexp
  end

  Rack::Attack.blacklist('Block naughty bots <ip>') do |request|
    Rails.cache.fetch("block #{request.ip}").present?
  end

  paths = File.read("#{blacklist_folder}/path.txt").split("\n")
  paths_regexp = Regexp.union(paths)
  blacklist('Block bad paths') do |request|
    request.path =~ paths_regexp
  end

  referers = File.read("#{blacklist_folder}/referer.txt").split("\n")
  referers_regexp = Regexp.union(referers)
  blacklist('Block bad referers') do |request|
    request.referer =~ referers_regexp
  end

  user_agents = File.read("#{blacklist_folder}/useragent.txt").split("\n")
  regexp = Regexp.union(user_agents)
  user_agents_regexp = Regexp.new(regexp.source, Regexp::IGNORECASE)
  blacklist('Block bad User Agents') do |request|
    request.user_agent =~ user_agents_regexp
  end

  throttle('Too many requests', limit: 300, period: 5.minutes) do |request|
    request.ip unless request.path.starts_with?('/assets')
  end

  blacklist('Block unknown User Agents') { |request| request.unknown? }
  whitelist('Accept requests from localhost') { |request| request.localhost? }
end

Rack::Attack.blacklisted_response = lambda do |_env|
  # Using 503 because it may make attacker think that they have successfully
  # DOSed the site. Rack::Attack returns 403 for blacklists by default
  [503, {}, ['Blocked']]
end

Rack::Attack.throttled_response = lambda do |env|
  [503, {}, ['Blocked']]
end
```


## My trap

```
# app/middleware/antibot_middleware.rb
# config/initializers/antibot.rb
# lib/antibot/trap.rb
```

[https://github.com/fractalsoft/fractalsoft.org](https://github.com/fractalsoft/fractalsoft.org)



# Links

* gem [rack-attack](https://github.com/kickstarter/rack-attack)
* [Rack::Attack: protection from abusive clients](https://www.kickstarter.com/backing-and-hacking/rack-attack-protection-from-abusive-clients)
* [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page)
* [Robots meta tag and X-Robots-Tag HTTP header specifications](https://developers.google.com/webmasters/control-crawl-index/docs/robots_meta_tag)
* [Spam Poison](http://spampoison.com/)



# Questions?

Find me [@torrocus](http://fractalsoft.org/en/team/torrocus)
