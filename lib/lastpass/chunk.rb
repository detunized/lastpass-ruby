# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Chunk
        attr_reader :id,
                    :payload

        def initialize id, payload
            @id = id
            @payload = payload
        end
    end
end
