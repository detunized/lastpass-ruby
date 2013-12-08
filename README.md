LastPass Ruby API
=================

[![Build Status](https://travis-ci.org/detunized/lastpass-ruby.png?branch=master)](https://travis-ci.org/detunized/lastpass-ruby)
[![Coverage Status](https://coveralls.io/repos/detunized/lastpass-ruby/badge.png?branch=master)](https://coveralls.io/r/detunized/lastpass-ruby?branch=master)
[![Code Climate](https://codeclimate.com/github/detunized/lastpass-ruby.png)](https://codeclimate.com/github/detunized/lastpass-ruby)
[![Dependency Status](https://gemnasium.com/detunized/lastpass-ruby.png)](https://gemnasium.com/detunized/lastpass-ruby)

**This is unofficial LastPass API.**

This library implements fetching and parsing of LastPass data.  The library is
still in the proof of concept stage and doesn't support all LastPass features
yet.  Only account information (logins, passwords, urls, etc.) is available so
far.

There is a low level API which is used to fetch the data from the LastPass
server and parse it. Normally this is not the one you would want to use. What
you want is the `Vault` class which hides all the complexity and exposes all
the accounts already parsed, decrypted and ready to use. See the example
program for detail.

A quick example of accessing your account information:

```ruby
require "lastpass.rb"

vault = LastPass::Vault.open_remote "username", "password"
vault.accounts.each do |i|
    puts "#{i.name}: #{i.username}, #{i.password} (#{i.url})"
end
```

The blob received from LastPass could be safely stored locally (it's well
encrypted) and reused later on.


LostPass iOS App
----------------

There's an iOS app called [LostPass](http://detunized.net/lostpass/) that is
based on a totally incomplete C++ port of this library.  If you are a LastPass
user it would have made your life much easier if I didn't have to take it down
from the App Store. Now it's open source and if you have a developer account
or a jailbroken phone you could build it and install it on the phone. The
source code is [here](https://github.com/detunized/LostPass).


Contributing
------------

Contribution in any form and shape is very welcome.  Have comments,
suggestions, patches, pull requests?  All of the above are welcome.


License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).
