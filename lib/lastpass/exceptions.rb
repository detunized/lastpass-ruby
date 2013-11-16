# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    # Base class for all errors, should not be raised
    class Error < StandardError; end

    # Something went wrong with the network
    class NetworkError < Error; end

    # Server responded with something we don't understand
    class InvalidResponse < Error; end
end
