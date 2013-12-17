# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    # Base class for all errors, should not be raised
    class Error < StandardError; end

    #
    # Generic errors
    #

    # Something went wrong with the network
    class NetworkError < Error; end

    # Server responded with something we don't understand
    class InvalidResponseError < Error; end

    # Server responded with XML we don't understand
    class UnknownResponseSchemaError < Error; end

    #
    # LastPass returned errors
    #

    # LastPass error: unknown username
    class LastPassUnknownUsernameError < Error; end

    # LastPass error: invalid password
    class LastPassInvalidPasswordError < Error; end

    # LastPass error: incorrect Google Authenticator code
    class LastPassIncorrectGoogleAuthenticatorCodeError < Error; end

    # LastPass error we don't know about
    class LastPassUnknownError < Error; end
end
