LastPass Ruby API
=================

**This is unofficial LastPass API.**

This library implements fetching and parsing of LastPass data.  The library is still at the proof of
concept stage and doesn't support all LastPass features yet.  Only account information (logins,
passwords, urls, etc.) is available so far.

The API currently is very low level.  Hopefully it will evolve into something better and easier to
use.  For examples for now please check with the tests.

A quick example of accessing your account information:

```ruby
require 'lastpass.rb'

fetcher = LastPass::Fetcher.fetch 'username', 'password'
parser = LastPass::Parser.parse fetcher.blob, fetcher.encryption_key
accounts = parser.chunks['ACCT']
```

The blob you receive from LastPass could be stored in a file and reused later on.


LostPass iOS App
----------------

There's an iOS app called [LostPass](http://detunized.net/lostpass/) that is based on a C++ port of
this library.  If you are a LastPass user it will make your life much easier.  Please give it a try.
It's free!


Contributing
------------

Contribution in any form and shape is very welcome.  Have comments, suggestions, patches, pull
requests?  All of the above are welcome.


License
-------

The library is released under [the MIT license](http://www.opensource.org/licenses/mit-license.php).
