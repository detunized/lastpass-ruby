# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    # Base class for all errors
    class Error < StandardError; end

    # Whenever something goes wrong with the network
    class NetworkError < Error; end
end
