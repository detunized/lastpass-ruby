require 'test/unit'
require 'lastpass'
require_relative 'helper'

class FetcherTest < Test::Unit::TestCase
    def setup
    end

    def test_make_key
        keys = {
            1 => 'C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y='.decode64,
            5 => 'pE9goazSCRqnWwcixWM4NHJjWMvB5T15dMhe6ug1pZg='.decode64,
            10 => 'n9S0SyJdrMegeBHtkxUx8Lzc7wI6aGl+y3/udGmVey8='.decode64,
            50 => 'GwI8/kNy1NjIfe3Z0VAZfF78938UVuCi6xAL3MJBux0='.decode64,
            100 => 'piGdSULeHMWiBS3QJNM46M5PIYwQXA6cNS10pLB3Xf8='.decode64,
            500 => 'OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg='.decode64,
            1000 => 'z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg='.decode64
        }

        keys.each do |iterations, key|
            assert_equal key, LastPass::Fetcher.make_key('postlass@gmail.com', 'pl1234567890', iterations)
        end
    end
end
