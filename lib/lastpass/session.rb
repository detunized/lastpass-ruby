# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Session
        attr_reader :id,
                    :key_iteration_count,
                    :encrypted_private_key

        def initialize id, key_iteration_count, encrypted_private_key
            @id = id
            @key_iteration_count = key_iteration_count
            @encrypted_private_key = encrypted_private_key
        end
    end
end
