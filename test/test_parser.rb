require 'test/unit'
require 'lastpass'
require_relative 'helper'

class ParserTest < Test::Unit::TestCase
    @@blob = File.read 'lastpass-blob'
    @@key = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64

    def setup
        @blob = @@blob
        @key = @@key
        @parser = LastPass::Parser.parse @blob, @key
    end

    def test_type_is_correct
        assert_kind_of LastPass::Parser, @parser
    end

    def test_parse_fails_with_nil_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse nil, @key
        end
    end

    def test_parse_fails_with_invalid_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse '', @key
        end

        assert_raise ArgumentError do
            LastPass::Parser.parse 'ABCD', @key
        end
    end

    def test_chunks
        assert_kind_of Hash, @parser.chunks
        @parser.chunks.each do |id, chunks|
            assert_kind_of String, id
            assert_equal 4, id.length
            assert_match /[A-Z]{4}/, id

            assert_kind_of Array, chunks
            assert_operator chunks.length, :>, 0
        end
    end

    def test_chunk_LPAV
        check_only_one_chunk 'LPAV', '9'
    end

    def test_chunk_ENCU
        check_only_one_chunk 'ENCU', 'postlass@gmail.com'
    end

    def test_chunk_NMAC
        check_only_one_chunk 'NMAC', '8'
    end

    def test_chunk_ACCT
        assert @parser.chunks.keys.include? 'ACCT'

        accounts = @parser.chunks['ACCT']
        assert_equal 8, accounts.length

        test_account = {
            :id => '753975336',
            :name => 'twitter.com',
            :group => '',
            :url => 'http://',
            :extra => '',
            :favorite => '0',
            :shared_from_id => '',
            :username => 'lostpass',
            :password => '1234567890',
            :password_protected => '0',
            :generated_password => '0',
            :sn => '0',
            :last_touched => '1339761545',
            :auto_login => '0',
            :never_autofill => '0',
            :realm_data => '',
            :fiid => '753975336',
            :custom_js => '',
            :submit_id => '',
            :captcha_id => '',
            :urid => '0',
            :basic_authorization => '0',
            :method => '',
            :action => '',
            :group_id => '',
            :deleted => '0',
            :attach_key => '',
            :attach_present => '',
            :individual_share => '0',
            :unknown1 => ''
        }

        accounts.each do |account|
            assert_kind_of Hash, account
            assert_equal account.keys.sort, test_account.keys.sort

            test_account.values.each do |item|
                assert_kind_of String, item
            end
        end

        # Check one by one so it's easier spot the problems
        test_account.each do |id, item|
            assert_equal item, accounts[0][id]
        end
    end

    def test_chunk_EQDN
        assert @parser.chunks.keys.include? 'EQDN'

        domains = @parser.chunks['EQDN']
        assert_equal 46, domains.length

        test_domain = {:id => '1', :domain => 'ameritrade.com'}

        domains.each do |domain|
            assert_kind_of Hash, domain
            assert_equal test_domain.keys.sort, domain.keys.sort

            domain.values.each do |item|
                assert_kind_of String, item
            end
        end

        # Check one by one so it's easier spot the problems
        test_domain.each do |id, item|
            assert_equal item, domains[0][id]
        end
    end

    #
    # Helpers
    #

    def check_only_one_chunk id, value
        assert @parser.chunks.keys.include? id
        assert_equal 1, @parser.chunks[id].length
        assert_equal value, @parser.chunks[id][0]
    end
end
