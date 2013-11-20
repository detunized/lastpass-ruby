# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    # Base class for all errors, should not be raised
    class Error < StandardError; end

    # Something went wrong with the network
    class NetworkError < Error; end

    # Server responded with something we don't understand
    class InvalidResponse < Error; end

    # Server responded with XML we don't understand
    class UnknownResponseSchema < Error; end

    # LastPass error we don't know about
    class LastPassUnknownError < Error; end

    # LastPass error: unknown username
    class LastPassUnknownUsername < Error; end

    # LastPass error: invalid password
    class LastPassInvalidPassword < Error; end
end
