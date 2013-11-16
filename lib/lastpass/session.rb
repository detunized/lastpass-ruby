# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Session
        attr_reader :id,
                    :key_iteration_count

        def initialize id, key_iteration_count
            @id = id
            @key_iteration_count = key_iteration_count
        end
    end
end
